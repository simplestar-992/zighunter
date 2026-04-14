//! Fuzzer Module
//! 
//! Compile-time configured fuzzing engine with comptime mutation strategies.
//! Leverages Zig's comptime for highly optimized, configurable fuzzing.

const std = @import("std");
const http_client = @import("http_client.zig");
const vuln_patterns = @import("vuln_patterns.zig");

/// Comptime-defined mutation strategy
pub fn MutationStrategy(comptime T: type) type {
    _ = T; // Type parameter reserved for future extensibility
    return struct {
        name: []const u8,
        mutateFn: fn (allocator: std.mem.Allocator, input: []const u8, seed: u64) []const u8,

        const Self = @This();

        pub fn init(comptime name: []const u8, comptime mutateFn: fn (std.mem.Allocator, []const u8, u64) []const u8) Self {
            return .{
                .name = name,
                .mutateFn = mutateFn,
            };
        }
    };
}

/// Compile-time mutation functions
pub const Mutations = struct {
    /// Bit-flip mutation - flips random bits in the input
    pub fn bitFlip(allocator: std.mem.Allocator, input: []const u8, seed: u64) []const u8 {
        var output = allocator.dupe(u8, input) catch return input;

        var prng = std.Random.DefaultPrng.init(seed);
        const random = prng.random();

        if (output.len > 0) {
            const byte_idx = random.intRangeLessThan(usize, 0, output.len);
            const bit_idx: u3 = @truncate(random.int(u8) % 8); // Fixed: use u3 via truncate
            output[byte_idx] ^= (@as(u8, 1) << bit_idx);
        }

        return output;
    }

    /// Byte insertion - inserts random bytes at random positions
    pub fn byteInsert(allocator: std.mem.Allocator, input: []const u8, seed: u64) []const u8 {
        var prng = std.Random.DefaultPrng.init(seed);
        const random = prng.random();

        var output = std.ArrayList(u8).initCapacity(allocator, input.len + 1) catch return input;
        defer output.deinit();

        const insert_pos = if (input.len > 0) random.intRangeLessThan(usize, 0, input.len + 1) else 0;
        const insert_byte = random.int(u8);

        output.appendSlice(input[0..insert_pos]) catch return input;
        output.append(insert_byte) catch return input;
        output.appendSlice(input[insert_pos..]) catch return input;

        return output.toOwnedSlice() catch return input;
    }

    /// Byte deletion - removes random bytes
    pub fn byteDelete(allocator: std.mem.Allocator, input: []const u8, seed: u64) []const u8 {
        if (input.len <= 1) return input;

        var prng = std.Random.DefaultPrng.init(seed);
        const random = prng.random();

        var output = std.ArrayList(u8).initCapacity(allocator, input.len - 1) catch return input;
        defer output.deinit();

        const delete_pos = random.intRangeLessThan(usize, 0, input.len);

        output.appendSlice(input[0..delete_pos]) catch return input;
        output.appendSlice(input[delete_pos + 1 ..]) catch return input;

        return output.toOwnedSlice() catch return input;
    }

    /// Byte overwrite - overwrites bytes with random values
    pub fn byteOverwrite(allocator: std.mem.Allocator, input: []const u8, seed: u64) []const u8 {
        var output = allocator.dupe(u8, input) catch return input;

        var prng = std.Random.DefaultPrng.init(seed);
        const random = prng.random();

        if (output.len > 0) {
            const overwrite_pos = random.intRangeLessThan(usize, 0, output.len);
            output[overwrite_pos] = random.int(u8);
        }

        return output;
    }

    /// Arithmetic mutation - adds/subtracts random values from bytes
    pub fn arithmetic(allocator: std.mem.Allocator, input: []const u8, seed: u64) []const u8 {
        var output = allocator.dupe(u8, input) catch return input;

        var prng = std.Random.DefaultPrng.init(seed);
        const random = prng.random();

        if (output.len > 0) {
            const mutate_pos = random.intRangeLessThan(usize, 0, output.len);
            const delta = random.intRangeAtMost(i8, -35, 35);
            const current: i16 = @as(i16, output[mutate_pos]);
            const new_val: u8 = @truncate(@as(u16, @intCast(current + delta)));
            output[mutate_pos] = new_val;
        }

        return output;
    }

    /// Injection mutation - injects special characters that often trigger bugs
    pub fn specialChars(allocator: std.mem.Allocator, input: []const u8, seed: u64) []const u8 {
        const special_chars = [_]u8{ 0x00, 0x0a, 0x0d, 0x09, 0x0b, 0x0c, 0x22, 0x27, 0x5c, 0x3c, 0x3e, 0x60, 0x7f };

        var prng = std.Random.DefaultPrng.init(seed);
        const random = prng.random();

        var output = allocator.dupe(u8, input) catch return input;

        if (output.len > 0) {
            const mutate_pos = random.intRangeLessThan(usize, 0, output.len);
            const special_idx = random.intRangeLessThan(usize, 0, special_chars.len);
            output[mutate_pos] = special_chars[special_idx];
        }

        return output;
    }

    /// SQL injection patterns
    pub fn sqlInjection(allocator: std.mem.Allocator, input: []const u8, seed: u64) []const u8 {
        const payloads = [_][]const u8{
            "' OR '1'='1",
            "' OR 1=1--",
            "\" OR \"\"=\"",
            "'; DROP TABLE--",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
            "admin'--",
            "1; SELECT * FROM users",
        };

        var prng = std.Random.DefaultPrng.init(seed);
        const random = prng.random();

        const payload_idx = random.intRangeLessThan(usize, 0, payloads.len);
        const payload = payloads[payload_idx];

        const output = std.fmt.allocPrint(allocator, "{s}{s}", .{ input, payload }) catch return input;
        return output;
    }

    /// XSS patterns
    pub fn xssPayload(allocator: std.mem.Allocator, input: []const u8, seed: u64) []const u8 {
        const payloads = [_][]const u8{
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
            "'-alert(1)-'",
            "\"><script>alert(1)</script>",
            "<iframe src=\"javascript:alert(1)\">",
        };

        var prng = std.Random.DefaultPrng.init(seed);
        const random = prng.random();

        const payload_idx = random.intRangeLessThan(usize, 0, payloads.len);
        const payload = payloads[payload_idx];

        const output = std.fmt.allocPrint(allocator, "{s}{s}", .{ input, payload }) catch return input;
        return output;
    }

    /// Path traversal patterns
    pub fn pathTraversal(allocator: std.mem.Allocator, input: []const u8, seed: u64) []const u8 {
        const payloads = [_][]const u8{
            "../",
            "..\\",
            "....//",
            "....\\\\",
            "%2e%2e%2f",
            "%2e%2e/",
            "..%2f",
            "%2e%2e%5c",
            "..%255c",
            "..%c0%af",
            "/etc/passwd",
            "/windows/system32/config/sam",
        };

        var prng = std.Random.DefaultPrng.init(seed);
        const random = prng.random();

        const payload_idx = random.intRangeLessThan(usize, 0, payloads.len);
        const payload = payloads[payload_idx];

        const output = std.fmt.allocPrint(allocator, "{s}{s}", .{ input, payload }) catch return input;
        return output;
    }

    /// Format string patterns
    pub fn formatString(allocator: std.mem.Allocator, input: []const u8, seed: u64) []const u8 {
        const payloads = [_][]const u8{
            "%s%s%s%s%s",
            "%n%n%n%n%n",
            "%x%x%x%x%x",
            "%.10000d",
            "%08x",
            "%p%p%p%p",
            "${{7*7}}",
            "{{7*7}}",
            "#{7*7}",
        };

        var prng = std.Random.DefaultPrng.init(seed);
        const random = prng.random();

        const payload_idx = random.intRangeLessThan(usize, 0, payloads.len);
        const payload = payloads[payload_idx];

        const output = std.fmt.allocPrint(allocator, "{s}{s}", .{ input, payload }) catch return input;
        return output;
    }
};

/// Fuzzing result
pub const FuzzResult = struct {
    input: []const u8,
    response_code: u16,
    response_body: []const u8,
    response_time_us: u64,
    vulnerability_type: ?vuln_patterns.VulnerabilityType,
    confidence: f32,
    mutation_type: []const u8,
};

/// Fuzzer configuration
pub const FuzzerConfig = struct {
    target_url: []const u8,
    iterations: usize = 1000,
    timeout_ms: u64 = 5000,
    user_agent: []const u8 = "ZigHunter/0.1.0",
    seed: u64 = 0,
    corpus: ?[][]const u8 = null,
};

/// Main fuzzer structure
pub const Fuzzer = struct {
    allocator: std.mem.Allocator,
    config: FuzzerConfig,
    http_client: http_client.HttpClient,
    prng: std.Random.DefaultPrng,

    /// Comptime-defined mutation strategies
    const mutation_strategies = [_]struct { name: []const u8, mutateFn: *const fn (std.mem.Allocator, []const u8, u64) []const u8 }{
        .{ .name = "bit_flip", .mutateFn = Mutations.bitFlip },
        .{ .name = "byte_insert", .mutateFn = Mutations.byteInsert },
        .{ .name = "byte_delete", .mutateFn = Mutations.byteDelete },
        .{ .name = "byte_overwrite", .mutateFn = Mutations.byteOverwrite },
        .{ .name = "arithmetic", .mutateFn = Mutations.arithmetic },
        .{ .name = "special_chars", .mutateFn = Mutations.specialChars },
        .{ .name = "sql_injection", .mutateFn = Mutations.sqlInjection },
        .{ .name = "xss_payload", .mutateFn = Mutations.xssPayload },
        .{ .name = "path_traversal", .mutateFn = Mutations.pathTraversal },
        .{ .name = "format_string", .mutateFn = Mutations.formatString },
    };

    pub fn init(allocator: std.mem.Allocator, config: FuzzerConfig) !Fuzzer {
        const client = try http_client.HttpClient.init(allocator, config.target_url);

        var seed = config.seed;
        if (seed == 0) {
            seed = @as(u64, @intCast(std.time.nanoTimestamp()));
        }

        return .{
            .allocator = allocator,
            .config = config,
            .http_client = client,
            .prng = std.Random.DefaultPrng.init(seed),
        };
    }

    pub fn deinit(self: *Fuzzer) void {
        self.http_client.deinit();
    }

    pub fn run(self: *Fuzzer) !std.ArrayList(FuzzResult) {
        var results = std.ArrayList(FuzzResult).init(self.allocator);

        const random = self.prng.random();

        // Initial corpus - common endpoints and parameters
        const default_corpus = [_][]const u8{
            "id",
            "file",
            "page",
            "search",
            "query",
            "url",
            "redirect",
            "next",
            "callback",
            "path",
            "input",
            "data",
            "name",
            "email",
            "username",
            "password",
        };

        var corpus = std.ArrayList([]const u8).init(self.allocator);
        defer {
            for (corpus.items) |item| {
                self.allocator.free(item);
            }
            corpus.deinit();
        }

        if (self.config.corpus) |custom_corpus| {
            for (custom_corpus) |item| {
                try corpus.append(try self.allocator.dupe(u8, item));
            }
        } else {
            for (default_corpus) |item| {
                try corpus.append(try self.allocator.dupe(u8, item));
            }
        }

        std.log.info("Starting fuzzing with {} initial corpus entries", .{corpus.items.len});

        for (0..self.config.iterations) |i| {
            // Select random corpus entry
            const corpus_idx = random.intRangeLessThan(usize, 0, corpus.items.len);
            const base_input = corpus.items[corpus_idx];

            // Select random mutation strategy
            const strategy_idx = random.intRangeLessThan(usize, 0, mutation_strategies.len);
            const strategy = mutation_strategies[strategy_idx];

            // Generate mutation seed
            const mutation_seed = random.int(u64);

            // Apply mutation
            const mutated_input = strategy.mutateFn(self.allocator, base_input, mutation_seed);
            defer self.allocator.free(mutated_input);

            // Send request
            const req_config = http_client.RequestConfig{
                .method = .GET,
                .path = mutated_input,
                .timeout_ms = self.config.timeout_ms,
                .user_agent = self.config.user_agent,
            };

            var response = self.http_client.request(req_config) catch {
                continue;
            };
            defer response.deinit();

            // Analyze response for vulnerabilities
            const vuln_analysis = vuln_patterns.analyzeResponse(response, mutated_input);

            // If interesting, add to corpus
            if (response.status_code >= 400 and response.status_code < 500) {
                // Client errors might indicate parameter discovery
            } else if (response.status_code >= 500) {
                // Server errors might indicate vulnerability
                try corpus.append(try self.allocator.dupe(u8, mutated_input));

                if (vuln_analysis.vulnerability_type != null) {
                    try results.append(.{
                        .input = try self.allocator.dupe(u8, mutated_input),
                        .response_code = response.status_code,
                        .response_body = try self.allocator.dupe(u8, response.body),
                        .response_time_us = response.response_time_us,
                        .vulnerability_type = vuln_analysis.vulnerability_type,
                        .confidence = vuln_analysis.confidence,
                        .mutation_type = strategy.name,
                    });
                }
            }

            // Check for specific vulnerability patterns
            if (vuln_analysis.confidence > 0.5) {
                try results.append(.{
                    .input = try self.allocator.dupe(u8, mutated_input),
                    .response_code = response.status_code,
                    .response_body = try self.allocator.dupe(u8, response.body),
                    .response_time_us = response.response_time_us,
                    .vulnerability_type = vuln_analysis.vulnerability_type,
                    .confidence = vuln_analysis.confidence,
                    .mutation_type = strategy.name,
                });
            }

            if (i % 100 == 0) {
                std.log.info("Fuzzing progress: {}/{} iterations, {} findings", .{ i, self.config.iterations, results.items.len });
            }
        }

        return results;
    }
};

/// Compile-time fuzzer for specific mutation combinations
pub fn ComptimeFuzzer(comptime strategies: []const []const u8) type {
    return struct {
        pub fn run(allocator: std.mem.Allocator, config: FuzzerConfig) !std.ArrayList(FuzzResult) {
            var fuzzer = try Fuzzer.init(allocator, config);
            defer fuzzer.deinit();
            _ = strategies; // Reserved for future strategy filtering
            return fuzzer.run();
        }
    };
}

test "mutation strategies" {
    const allocator = std.testing.allocator;

    const input = "test input";

    const bit_flipped = Mutations.bitFlip(allocator, input, 12345);
    defer allocator.free(bit_flipped);
    try std.testing.expect(bit_flipped.len == input.len);

    const sql_injected = Mutations.sqlInjection(allocator, input, 12345);
    defer allocator.free(sql_injected);
    try std.testing.expect(sql_injected.len > input.len);
}
