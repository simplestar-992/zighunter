//! Scanner Module
//! 
//! High-performance HTTP security scanner with concurrent scanning capabilities.
//! Performs path discovery, parameter discovery, and vulnerability detection.

const std = @import("std");
const http_client = @import("http_client.zig");
const vuln_patterns = @import("vuln_patterns.zig");
const wordlist = @import("wordlist.zig");

pub const ScanDepth = enum {
    quick,
    standard,
    deep,

    pub fn getPathCount(self: ScanDepth) usize {
        return switch (self) {
            .quick => 50,
            .standard => 200,
            .deep => 1000,
        };
    }
};

pub const ScanResult = struct {
    url: []const u8,
    method: http_client.Method,
    status_code: u16,
    content_length: ?usize,
    response_time_us: u64,
    title: ?[]const u8,
    technologies: [][]const u8,
    vulnerabilities: std.ArrayList(vuln_patterns.VulnerabilityInfo),
    redirect_url: ?[]const u8,
    content_type: ?[]const u8,
};

pub const ScanConfig = struct {
    target_url: []const u8,
    threads: usize = 10,
    timeout_ms: u64 = 5000,
    user_agent: []const u8 = "ZigHunter/0.1.0",
    scan_depth: ScanDepth = .standard,
    follow_redirects: bool = true,
    max_redirects: usize = 5,
    rate_limit_ms: u64 = 0,
    custom_headers: ?[]http_client.Header = null,
};

pub const Scanner = struct {
    allocator: std.mem.Allocator,
    config: ScanConfig,
    http_client: http_client.HttpClient,
    wordlist: std.ArrayList([]const u8),
    results: std.ArrayList(ScanResult),
    mutex: std.Thread.Mutex,
    active_threads: std.atomic.Value(usize),
    stop_flag: std.atomic.Value(bool),

    pub fn init(allocator: std.mem.Allocator, config: ScanConfig) !Scanner {
        const client = try http_client.HttpClient.init(allocator, config.target_url);

        return .{
            .allocator = allocator,
            .config = config,
            .http_client = client,
            .wordlist = std.ArrayList([]const u8).init(allocator),
            .results = std.ArrayList(ScanResult).init(allocator),
            .mutex = .{},
            .active_threads = std.atomic.Value(usize).init(0),
            .stop_flag = std.atomic.Value(bool).init(false),
        };
    }

    pub fn deinit(self: *Scanner) void {
        self.http_client.deinit();

        for (self.wordlist.items) |item| {
            self.allocator.free(item);
        }
        self.wordlist.deinit();

        for (self.results.items) |result| {
            self.allocator.free(result.url);
            if (result.title) |t| self.allocator.free(t);
            for (result.technologies) |tech| {
                self.allocator.free(tech);
            }
            self.allocator.free(result.technologies);
            result.vulnerabilities.deinit();
            if (result.redirect_url) |r| self.allocator.free(r);
            if (result.content_type) |c| self.allocator.free(c);
        }
        self.results.deinit();
    }

    pub fn loadWordlist(self: *Scanner, path: []const u8) !void {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, std.math.maxInt(usize));
        defer self.allocator.free(content);

        var lines = std.mem.splitSequence(u8, content, "\n");
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len > 0 and trimmed[0] != '#') {
                try self.wordlist.append(try self.allocator.dupe(u8, trimmed));
            }
        }
    }

    pub fn loadBuiltinWordlist(self: *Scanner) !void {
        const builtin_paths = wordlist.common_paths;
        for (builtin_paths) |path| {
            try self.wordlist.append(try self.allocator.dupe(u8, path));
        }

        const builtin_params = wordlist.common_params;
        for (builtin_params) |param| {
            try self.wordlist.append(try self.allocator.dupe(u8, param));
        }
    }

    pub fn runScan(self: *Scanner) !std.ArrayList(ScanResult) {
        std.log.info("Loaded {} paths/params to test", .{self.wordlist.items.len});

        // Limit to scan depth
        const max_paths = self.config.scan_depth.getPathCount();
        const paths_to_scan = if (self.wordlist.items.len > max_paths)
            self.wordlist.items[0..max_paths]
        else
            self.wordlist.items;

        std.log.info("Scanning {} paths with {} threads", .{ paths_to_scan.len, self.config.threads });

        // Create thread pool
        var threads = std.ArrayList(std.Thread).init(self.allocator);
        defer threads.deinit();

        // Shared state for work distribution
        var current_index = std.atomic.Value(usize).init(0);

        // Start worker threads
        for (0..self.config.threads) |_| {
            const thread = try std.Thread.spawn(.{}, scanWorker, .{
                self,
                paths_to_scan,
                &current_index,
            });
            try threads.append(thread);
        }

        // Wait for all threads to complete
        for (threads.items) |thread| {
            thread.join();
        }

        return self.results;
    }

    fn scanWorker(
        self: *Scanner,
        paths: [][]const u8,
        current_index: *std.atomic.Value(usize),
    ) void {
        _ = self.active_threads.fetchAdd(1, .monotonic);

        while (!self.stop_flag.load(.monotonic)) {
            const idx = current_index.fetchAdd(1, .monotonic);
            if (idx >= paths.len) break;

            const path = paths[idx];

            // Rate limiting
            if (self.config.rate_limit_ms > 0) {
                std.time.sleep(self.config.rate_limit_ms * std.time.ns_per_ms);
            }

            self.scanPath(path) catch |err| {
                std.log.err("Error scanning {s}: {}", .{ path, err });
            };
        }

        _ = self.active_threads.fetchSub(1, .monotonic);
    }

    fn scanPath(self: *Scanner, path: []const u8) !void {
        const req_config = http_client.RequestConfig{
            .method = .GET,
            .path = path,
            .timeout_ms = self.config.timeout_ms,
            .user_agent = self.config.user_agent,
            .follow_redirects = self.config.follow_redirects,
            .max_redirects = self.config.max_redirects,
        };

        var response = self.http_client.request(req_config) catch |err| {
            if (err == error.ConnectionRefused or err == error.ConnectionTimedOut) {
                return;
            }
            return;
        };
        defer response.deinit();

        // Analyze response for vulnerabilities
        const vuln_info = vuln_patterns.analyzeResponse(response, path);

        // Extract title from HTML
        const title = extractTitle(self.allocator, response.body) catch null;

        // Detect technologies - use empty slice on any error
        var techs: [][]const u8 = &.{};
        if (detectTechnologies(self.allocator, response)) |detected| {
            techs = detected;
        } else |_| {}
        const technologies = techs;

        // Create result (must be var for appending)
        var result: ScanResult = .{
            .url = try self.allocator.dupe(u8, path),
            .method = .GET,
            .status_code = response.status_code,
            .content_length = response.content_length,
            .response_time_us = response.response_time_us,
            .title = title,
            .technologies = technologies,
            .vulnerabilities = std.ArrayList(vuln_patterns.VulnerabilityInfo).init(self.allocator),
            .redirect_url = if (response.getHeader("Location")) |loc|
                try self.allocator.dupe(u8, loc)
            else
                null,
            .content_type = if (response.content_type) |ct|
                try self.allocator.dupe(u8, ct)
            else
                null,
        };

        // Add vulnerability if found
        if (vuln_info.vulnerability_type != null and vuln_info.confidence > 0.3) {
            try result.vulnerabilities.append(vuln_info);
        }

        // Thread-safe result storage
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.results.append(result);

        // Log interesting findings
        if (response.status_code >= 400 and response.status_code < 500) {
            // Skip logging 404s for cleaner output
        } else if (response.status_code != 404) {
            std.log.info("[{}] {s} - {} bytes - {} us", .{
                response.status_code,
                path,
                response.content_length orelse 0,
                response.response_time_us,
            });
        }
    }

    fn extractTitle(allocator: std.mem.Allocator, body: []const u8) anyerror!?[]const u8 {
        const title_start = std.mem.indexOf(u8, body, "<title>") orelse return null;
        const after_start = body[title_start + 7..];
        const title_end = std.mem.indexOf(u8, after_start, "</title>") orelse return null;

        const title_content = after_start[0..title_end];
        const trimmed = std.mem.trim(u8, title_content, " \t\n\r");

        if (trimmed.len == 0) return null;
        const result = try allocator.dupe(u8, trimmed);
        return @as([]const u8, result);
    }

    fn detectTechnologies(allocator: std.mem.Allocator, response: http_client.Response) ![][]const u8 {
        var techs = std.ArrayList([]const u8).init(allocator);

        // Check server header
        if (response.getHeader("Server")) |server| {
            if (std.mem.startsWith(u8, server, "nginx")) {
                try techs.append(try allocator.dupe(u8, "nginx"));
            } else if (std.mem.startsWith(u8, server, "Apache")) {
                try techs.append(try allocator.dupe(u8, "Apache"));
            } else if (std.mem.startsWith(u8, server, "Microsoft-IIS")) {
                try techs.append(try allocator.dupe(u8, "IIS"));
            }
        }

        // Check X-Powered-By header
        if (response.getHeader("X-Powered-By")) |powered| {
            if (std.mem.containsAtLeast(u8, powered, 1, "PHP")) {
                try techs.append(try allocator.dupe(u8, "PHP"));
            } else if (std.mem.containsAtLeast(u8, powered, 1, "ASP.NET")) {
                try techs.append(try allocator.dupe(u8, "ASP.NET"));
            } else if (std.mem.containsAtLeast(u8, powered, 1, "Express")) {
                try techs.append(try allocator.dupe(u8, "Express"));
            }
        }

        // Check content-type
        if (response.content_type) |ct| {
            if (std.mem.containsAtLeast(u8, ct, 1, "application/json")) {
                try techs.append(try allocator.dupe(u8, "JSON API"));
            }
        }

        // Check body for framework signatures
        if (std.mem.indexOf(u8, response.body, "wp-content") != null) {
            try techs.append(try allocator.dupe(u8, "WordPress"));
        }
        if (std.mem.indexOf(u8, response.body, "laravel") != null) {
            try techs.append(try allocator.dupe(u8, "Laravel"));
        }
        if (std.mem.indexOf(u8, response.body, "django") != null) {
            try techs.append(try allocator.dupe(u8, "Django"));
        }
        if (std.mem.indexOf(u8, response.body, "react") != null) {
            try techs.append(try allocator.dupe(u8, "React"));
        }
        if (std.mem.indexOf(u8, response.body, "vue") != null) {
            try techs.append(try allocator.dupe(u8, "Vue.js"));
        }

        return techs.toOwnedSlice();
    }

    pub fn stop(self: *Scanner) void {
        self.stop_flag.store(true, .monotonic);
    }
};

test "scanner initialization" {
    const allocator = std.testing.allocator;

    var scanner = try Scanner.init(allocator, .{
        .target_url = "https://example.com",
        .threads = 2,
    });
    defer scanner.deinit();

    try scanner.loadBuiltinWordlist();
    try std.testing.expect(scanner.wordlist.items.len > 0);
}
