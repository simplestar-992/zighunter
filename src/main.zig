//! ZigHunter - High-Performance HTTP Security Scanner
//! 
//! A fast, memory-safe security scanner designed for bug bounty hunting.
//! Leverages Zig's comptime for compile-time configured fuzzing strategies.
//!
//! Features:
//! - Compile-time mutation strategies
//! - Memory-safe HTTP parsing
//! - Concurrent scanning with configurable workers
//! - Built-in vulnerability pattern detection
//! - Cross-platform single binary

const std = @import("std");
const http_client = @import("http_client.zig");
const fuzzer = @import("fuzzer.zig");
const scanner = @import("scanner.zig");
const report = @import("report.zig");
const wordlist = @import("wordlist.zig");
const vuln_patterns = @import("vuln_patterns.zig");

pub const std_options: std.Options = .{
    .log_level = .info,
};

const CliConfig = struct {
    target_url: []const u8,
    wordlist_path: ?[]const u8 = null,
    threads: usize = 10,
    timeout_ms: u64 = 5000,
    output_format: report.OutputFormat = .json,
    output_path: ?[]const u8 = null,
    rate_limit_ms: u64 = 0,
    follow_redirects: bool = true,
    max_redirects: usize = 5,
    user_agent: []const u8 = "ZigHunter/0.1.0",
    headers: ?[][]const u8 = null,
    scan_depth: scanner.ScanDepth = .standard,
    enable_fuzzing: bool = false,
    fuzz_iterations: usize = 1000,
};

const Banner = 
    \\ 
    \\ ██╗███╗   ██╗████████╗███████╗██████╗ ██╗██╗  ██╗
    \\ ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗██║╚██╗██╔╝
    \\ ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝██║ ╚███╔╝ 
    \\ ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗██║ ██╔██╗ 
    \\ ██║██║ ╚████║   ██║   ███████╗██║  ██║██║██╔╝ ██╗
    \\ ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝ ╚═══╝ 
    \\      HTTP Security Scanner for Bug Bounty Hunters
    \\
    ;

fn printUsage() void {
    const usage = 
        \\Usage: zighunter [OPTIONS] <TARGET_URL>
        \\
        \\Arguments:
        \\  <TARGET_URL>          Target URL to scan (e.g., https://example.com)
        \\
        \\Options:
        \\  -w, --wordlist <PATH>     Custom wordlist for path discovery
        \\  -t, --threads <NUM>       Number of concurrent threads (default: 10)
        \\  --timeout <MS>            Request timeout in milliseconds (default: 5000)
        \\  -o, --output <PATH>       Output file path
        \\  -f, --format <FORMAT>     Output format: json, html, txt (default: json)
        \\  --rate-limit <MS>         Rate limit between requests in milliseconds
        \\  --no-redirects            Don't follow redirects
        \\  --max-redirects <NUM>     Maximum redirects to follow (default: 5)
        \\  -u, --user-agent <UA>     Custom User-Agent string
        \\  -H, --header <HEADER>     Add custom header (can be used multiple times)
        \\  -d, --depth <LEVEL>       Scan depth: quick, standard, deep (default: standard)
        \\  --fuzz                    Enable fuzzing mode
        \\  --fuzz-iterations <NUM>   Number of fuzzing iterations (default: 1000)
        \\  -h, --help                Show this help message
        \\  -v, --version             Show version information
        \\
        \\Examples:
        \\  zighunter https://example.com
        \\  zighunter -w paths.txt -t 20 https://example.com
        \\  zighunter --fuzz --fuzz-iterations 5000 https://api.example.com
        \\  zighunter -H "Authorization: Bearer token123" https://api.example.com
        \\
        ;

    std.debug.print("{s}{s}", .{ Banner, usage });
}

fn parseArgs(allocator: std.mem.Allocator, args: [][]const u8) !CliConfig {
    var config: CliConfig = undefined;
    config.threads = 10;
    config.timeout_ms = 5000;
    config.output_format = .json;
    config.output_path = null;
    config.rate_limit_ms = 0;
    config.follow_redirects = true;
    config.max_redirects = 5;
    config.user_agent = "ZigHunter/0.1.0";
    config.headers = null;
    config.scan_depth = .standard;
    config.enable_fuzzing = false;
    config.fuzz_iterations = 1000;
    config.wordlist_path = null;

    var target_url: ?[]const u8 = null;
    var header_list = std.ArrayList([]const u8).init(allocator);
    defer header_list.deinit();

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsage();
            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--version")) {
            std.debug.print("ZigHunter v0.1.0\n", .{});
            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "-w") or std.mem.eql(u8, arg, "--wordlist")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --wordlist requires a path\n", .{});
                std.process.exit(1);
            }
            config.wordlist_path = args[i];
        } else if (std.mem.eql(u8, arg, "-t") or std.mem.eql(u8, arg, "--threads")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --threads requires a number\n", .{});
                std.process.exit(1);
            }
            config.threads = try std.fmt.parseInt(usize, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--timeout")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --timeout requires a number\n", .{});
                std.process.exit(1);
            }
            config.timeout_ms = try std.fmt.parseInt(u64, args[i], 10);
        } else if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --output requires a path\n", .{});
                std.process.exit(1);
            }
            config.output_path = args[i];
        } else if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--format")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --format requires a format type\n", .{});
                std.process.exit(1);
            }
            const format_str = args[i];
            if (std.mem.eql(u8, format_str, "json")) {
                config.output_format = .json;
            } else if (std.mem.eql(u8, format_str, "html")) {
                config.output_format = .html;
            } else if (std.mem.eql(u8, format_str, "txt")) {
                config.output_format = .txt;
            } else {
                std.debug.print("Error: Unknown format '{s}'\n", .{format_str});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "--rate-limit")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --rate-limit requires a number\n", .{});
                std.process.exit(1);
            }
            config.rate_limit_ms = try std.fmt.parseInt(u64, args[i], 10);
        } else if (std.mem.eql(u8, arg, "--no-redirects")) {
            config.follow_redirects = false;
        } else if (std.mem.eql(u8, arg, "--max-redirects")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --max-redirects requires a number\n", .{});
                std.process.exit(1);
            }
            config.max_redirects = try std.fmt.parseInt(usize, args[i], 10);
        } else if (std.mem.eql(u8, arg, "-u") or std.mem.eql(u8, arg, "--user-agent")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --user-agent requires a string\n", .{});
                std.process.exit(1);
            }
            config.user_agent = args[i];
        } else if (std.mem.eql(u8, arg, "-H") or std.mem.eql(u8, arg, "--header")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --header requires a header string\n", .{});
                std.process.exit(1);
            }
            try header_list.append(args[i]);
        } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--depth")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --depth requires a level\n", .{});
                std.process.exit(1);
            }
            const depth_str = args[i];
            if (std.mem.eql(u8, depth_str, "quick")) {
                config.scan_depth = .quick;
            } else if (std.mem.eql(u8, depth_str, "standard")) {
                config.scan_depth = .standard;
            } else if (std.mem.eql(u8, depth_str, "deep")) {
                config.scan_depth = .deep;
            } else {
                std.debug.print("Error: Unknown depth '{s}'\n", .{depth_str});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "--fuzz")) {
            config.enable_fuzzing = true;
        } else if (std.mem.eql(u8, arg, "--fuzz-iterations")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("Error: --fuzz-iterations requires a number\n", .{});
                std.process.exit(1);
            }
            config.fuzz_iterations = try std.fmt.parseInt(usize, args[i], 10);
        } else if (arg[0] != '-') {
            target_url = arg;
        } else {
            std.debug.print("Error: Unknown option '{s}'\n", .{arg});
            std.process.exit(1);
        }
    }

    if (target_url == null) {
        std.debug.print("Error: Target URL is required\n\n", .{});
        printUsage();
        std.process.exit(1);
    }

    config.target_url = target_url.?;

    if (header_list.items.len > 0) {
        config.headers = try allocator.dupe([]const u8, header_list.items);
    }

    return config;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .safety = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsage();
        std.process.exit(1);
    }

    const config = parseArgs(allocator, args) catch |err| {
        std.debug.print("Error parsing arguments: {}\n", .{err});
        std.process.exit(1);
    };

    std.debug.print("{s}", .{Banner});
    std.log.info("Target: {s}", .{config.target_url});
    std.log.info("Threads: {}", .{config.threads});
    std.log.info("Scan depth: {s}", .{@tagName(config.scan_depth)});

    if (config.enable_fuzzing) {
        std.log.info("Fuzzing mode enabled with {} iterations", .{config.fuzz_iterations});
    }

    var scan_ctx = try scanner.Scanner.init(allocator, .{
        .target_url = config.target_url,
        .threads = config.threads,
        .timeout_ms = config.timeout_ms,
        .user_agent = config.user_agent,
        .scan_depth = config.scan_depth,
        .follow_redirects = config.follow_redirects,
        .max_redirects = config.max_redirects,
        .rate_limit_ms = config.rate_limit_ms,
    });
    defer scan_ctx.deinit();

    if (config.wordlist_path) |path| {
        std.log.info("Loading wordlist from: {s}", .{path});
        try scan_ctx.loadWordlist(path);
    } else {
        std.log.info("Using built-in wordlist", .{});
        try scan_ctx.loadBuiltinWordlist();
    }

    std.log.info("Starting scan...", .{});
    var results = try scan_ctx.runScan();
    defer results.deinit();

    std.log.info("Scan complete. Found {} potential issues", .{results.items.len});

    if (config.enable_fuzzing) {
        std.log.info("Starting fuzzing phase...", .{});
        var fuzz_ctx = try fuzzer.Fuzzer.init(allocator, .{
            .target_url = config.target_url,
            .iterations = config.fuzz_iterations,
            .timeout_ms = config.timeout_ms,
            .user_agent = config.user_agent,
        });
        defer fuzz_ctx.deinit();

        var fuzz_results = try fuzz_ctx.run();
        defer fuzz_results.deinit();

        std.log.info("Fuzzing complete. Found {} potential vulnerabilities", .{fuzz_results.items.len});

        // Convert fuzz results to scan results for reporting
        for (fuzz_results.items) |fuzz_res| {
            const scan_res = scanner.ScanResult{
                .url = fuzz_res.input,
                .method = .GET,
                .status_code = fuzz_res.response_code,
                .content_length = fuzz_res.response_body.len,
                .response_time_us = fuzz_res.response_time_us,
                .title = null,
                .technologies = &.{},
                .vulnerabilities = blk: {
                    var vulns = std.ArrayList(vuln_patterns.VulnerabilityInfo).init(allocator);
                    if (fuzz_res.vulnerability_type) |vt| {
                        try vulns.append(.{
                            .vulnerability_type = vt,
                            .confidence = fuzz_res.confidence,
                            .evidence = null,
                            .severity = switch (vt) {
                                .sql_injection, .command_injection, .path_traversal => .critical,
                                .xss_reflected, .ssrf, .xxsi => .high,
                                else => .medium,
                            },
                        });
                    }
                    break :blk vulns;
                },
                .redirect_url = null,
                .content_type = null,
            };
            try results.append(scan_res);
        }
    }

    const report_content = try report.generate(allocator, results.items, config.output_format);
    defer allocator.free(report_content);

    if (config.output_path) |path| {
        std.log.info("Writing report to: {s}", .{path});
        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();
        try file.writeAll(report_content);
    } else {
        try std.io.getStdOut().writeAll(report_content);
    }

    std.log.info("Done!", .{});
}

test "basic functionality" {
    const testing = std.testing;
    try testing.expect(true);
}
