//! Report Generator Module
//! 
//! Generates security scan reports in multiple formats (JSON, HTML, TXT).
//! Professional-grade output for bug bounty submissions.

const std = @import("std");
const scanner = @import("scanner.zig");
const vuln_patterns = @import("vuln_patterns.zig");
const fuzzer = @import("fuzzer.zig");

pub const OutputFormat = enum {
    json,
    html,
    txt,
};

/// Generate report in specified format
pub fn generate(allocator: std.mem.Allocator, results: []const scanner.ScanResult, format: OutputFormat) ![]const u8 {
    return switch (format) {
        .json => generateJson(allocator, results),
        .html => generateHtml(allocator, results),
        .txt => generateTxt(allocator, results),
    };
}

/// Generate JSON report
fn generateJson(allocator: std.mem.Allocator, results: []const scanner.ScanResult) ![]const u8 {
    var output = std.ArrayList(u8).init(allocator);
    defer output.deinit();

    const writer = output.writer();

    try writer.writeAll("{\n");
    try writer.print("  \"scan_info\": {{\n", .{});
    try writer.print("    \"tool\": \"ZigHunter\",\n", .{});
    try writer.print("    \"version\": \"0.1.0\",\n", .{});
    try writer.print("    \"timestamp\": \"{}\"\n", .{std.time.timestamp()});
    try writer.writeAll("  },\n");
    try writer.writeAll("  \"results\": [\n");

    for (results, 0..) |result, i| {
        if (i > 0) try writer.writeAll(",\n");

        try writer.writeAll("    {\n");
        try writer.print("      \"url\": \"{s}\",\n", .{result.url});
        try writer.print("      \"method\": \"{s}\",\n", .{result.method.toString()});
        try writer.print("      \"status_code\": {},\n", .{result.status_code});
        try writer.print("      \"content_length\": {},\n", .{result.content_length orelse 0});
        try writer.print("      \"response_time_us\": {},\n", .{result.response_time_us});

        if (result.title) |title| {
            try writer.print("      \"title\": \"{s}\",\n", .{escapeJsonString(allocator, title) catch title});
        }

        try writer.writeAll("      \"technologies\": [");
        for (result.technologies, 0..) |tech, j| {
            if (j > 0) try writer.writeAll(", ");
            try writer.print("\"{s}\"", .{tech});
        }
        try writer.writeAll("],\n");

        try writer.writeAll("      \"vulnerabilities\": [\n");
        for (result.vulnerabilities.items, 0..) |vuln, j| {
            if (j > 0) try writer.writeAll(",\n");
            if (vuln.vulnerability_type) |vt| {
                try writer.writeAll("        {\n");
                try writer.print("          \"type\": \"{s}\",\n", .{@tagName(vt)});
                try writer.print("          \"description\": \"{s}\",\n", .{vuln_patterns.getDescription(vt)});
                try writer.print("          \"confidence\": {d:.2},\n", .{vuln.confidence});
                try writer.print("          \"severity\": \"{s}\"\n", .{@tagName(vuln.severity)});
                try writer.writeAll("        }");
            }
        }
        try writer.writeAll("\n      ]\n");
        try writer.writeAll("    }");
    }

    try writer.writeAll("\n  ],\n");
    try writer.writeAll("  \"statistics\": {\n");

    // Calculate statistics
    var total_findings: usize = 0;
    var critical_count: usize = 0;
    var high_count: usize = 0;
    var medium_count: usize = 0;
    var low_count: usize = 0;

    for (results) |result| {
        total_findings += result.vulnerabilities.items.len;
        for (result.vulnerabilities.items) |vuln| {
            switch (vuln.severity) {
                .critical => critical_count += 1,
                .high => high_count += 1,
                .medium => medium_count += 1,
                .low => low_count += 1,
                .informational => {},
            }
        }
    }

    try writer.print("    \"total_requests\": {},\n", .{results.len});
    try writer.print("    \"total_findings\": {},\n", .{total_findings});
    try writer.print("    \"critical\": {},\n", .{critical_count});
    try writer.print("    \"high\": {},\n", .{high_count});
    try writer.print("    \"medium\": {},\n", .{medium_count});
    try writer.print("    \"low\": {}\n", .{low_count});
    try writer.writeAll("  }\n");
    try writer.writeAll("}\n");

    return output.toOwnedSlice();
}

/// Generate HTML report
fn generateHtml(allocator: std.mem.Allocator, results: []const scanner.ScanResult) ![]const u8 {
    var output = std.ArrayList(u8).init(allocator);
    defer output.deinit();

    const writer = output.writer();

    try writer.writeAll(
        \\<!DOCTYPE html>
        \\<html lang="en">
        \\<head>
        \\    <meta charset="UTF-8">
        \\    <meta name="viewport" content="width=device-width, initial-scale=1.0">
        \\    <title>ZigHunter Security Report</title>
        \\    <style>
        \\        * { margin: 0; padding: 0; box-sizing: border-box; }
        \\        body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0a0a0f; color: #e0e0e0; line-height: 1.6; }
        \\        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        \\        header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        \\        h1 { color: #00d4aa; font-size: 2.5em; margin-bottom: 10px; }
        \\        .subtitle { color: #888; font-size: 1.1em; }
        \\        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        \\        .stat-card { background: #1a1a2e; padding: 20px; border-radius: 10px; text-align: center; }
        \\        .stat-number { font-size: 2.5em; font-weight: bold; }
        \\        .stat-label { color: #888; margin-top: 5px; }
        \\        .critical .stat-number { color: #ff4757; }
        \\        .high .stat-number { color: #ff6b35; }
        \\        .medium .stat-number { color: #ffa502; }
        \\        .low .stat-number { color: #2ed573; }
        \\        .results { background: #1a1a2e; border-radius: 10px; overflow: hidden; }
        \\        .result-item { border-bottom: 1px solid #2d2d44; padding: 20px; }
        \\        .result-item:last-child { border-bottom: none; }
        \\        .result-url { color: #00d4aa; font-size: 1.1em; word-break: break-all; }
        \\        .result-meta { display: flex; gap: 20px; margin-top: 10px; color: #888; font-size: 0.9em; }
        \\        .status-badge { display: inline-block; padding: 3px 10px; border-radius: 15px; font-size: 0.85em; font-weight: bold; }
        \\        .status-2xx { background: #2d3436; color: #00b894; }
        \\        .status-3xx { background: #2d3436; color: #0984e3; }
        \\        .status-4xx { background: #2d3436; color: #fdcb6e; }
        \\        .status-5xx { background: #2d3436; color: #e17055; }
        \\        .vuln-badge { display: inline-block; padding: 3px 10px; border-radius: 15px; font-size: 0.8em; margin: 5px 5px 5px 0; }
        \\        .vuln-critical { background: rgba(255, 71, 87, 0.2); color: #ff4757; }
        \\        .vuln-high { background: rgba(255, 107, 53, 0.2); color: #ff6b35; }
        \\        .vuln-medium { background: rgba(255, 165, 2, 0.2); color: #ffa502; }
        \\        .vuln-low { background: rgba(46, 213, 115, 0.2); color: #2ed573; }
        \\        .tech-tag { display: inline-block; background: #2d2d44; padding: 3px 10px; border-radius: 3px; font-size: 0.8em; margin: 5px 5px 5px 0; }
        \\        footer { text-align: center; padding: 30px; color: #666; margin-top: 30px; }
        \\    </style>
        \\</head>
        \\<body>
        \\    <div class="container">
        \\        <header>
        \\            <h1>🛡️ ZigHunter Security Report</h1>
        \\            <p class="subtitle">Generated on {timestamp}</p>
        \\        </header>
        \\
    );

    // Calculate statistics
    var total_findings: usize = 0;
    var critical_count: usize = 0;
    var high_count: usize = 0;
    var medium_count: usize = 0;
    var low_count: usize = 0;

    for (results) |result| {
        total_findings += result.vulnerabilities.items.len;
        for (result.vulnerabilities.items) |vuln| {
            switch (vuln.severity) {
                .critical => critical_count += 1,
                .high => high_count += 1,
                .medium => medium_count += 1,
                .low => low_count += 1,
                .informational => {},
            }
        }
    }

    // Stats section
    try writer.writeAll(
        \\        <div class="stats">
        \\
    );

    try writer.print(
        \\            <div class="stat-card critical">
        \\                <div class="stat-number">{}</div>
        \\                <div class="stat-label">Critical</div>
        \\            </div>
        \\
    , .{critical_count});

    try writer.print(
        \\            <div class="stat-card high">
        \\                <div class="stat-number">{}</div>
        \\                <div class="stat-label">High</div>
        \\            </div>
        \\
    , .{high_count});

    try writer.print(
        \\            <div class="stat-card medium">
        \\                <div class="stat-number">{}</div>
        \\                <div class="stat-label">Medium</div>
        \\            </div>
        \\
    , .{medium_count});

    try writer.print(
        \\            <div class="stat-card low">
        \\                <div class="stat-number">{}</div>
        \\                <div class="stat-label">Low</div>
        \\            </div>
        \\
    , .{low_count});

    try writer.writeAll("        </div>\n");

    // Results section
    try writer.writeAll("        <div class=\"results\">\n");

    for (results) |result| {
        if (result.vulnerabilities.items.len == 0 and result.status_code == 404) continue;

        try writer.writeAll("            <div class=\"result-item\">\n");

        // URL and status
        const status_class = switch (result.status_code / 100) {
            2 => "status-2xx",
            3 => "status-3xx",
            4 => "status-4xx",
            5 => "status-5xx",
            else => "status-4xx",
        };

        try writer.print("                <div class=\"result-url\">{s}</div>\n", .{result.url});
        try writer.print("                <div class=\"result-meta\">\n", .{});
        try writer.print("                    <span class=\"status-badge {s}\">{}</span>\n", .{ status_class, result.status_code });
        try writer.print("                    <span>{} bytes</span>\n", .{result.content_length orelse 0});
        try writer.print("                    <span>{d:.2}ms</span>\n", .{@as(f64, @floatFromInt(result.response_time_us)) / 1000.0});
        try writer.writeAll("                </div>\n");

        // Technologies
        if (result.technologies.len > 0) {
            try writer.writeAll("                <div style=\"margin-top: 10px;\">\n");
            for (result.technologies) |tech| {
                try writer.print("                    <span class=\"tech-tag\">{s}</span>\n", .{tech});
            }
            try writer.writeAll("                </div>\n");
        }

        // Vulnerabilities
        if (result.vulnerabilities.items.len > 0) {
            try writer.writeAll("                <div style=\"margin-top: 10px;\">\n");
            for (result.vulnerabilities.items) |vuln| {
                if (vuln.vulnerability_type) |vt| {
                    const severity_class = @tagName(vuln.severity);
                    try writer.print("                    <span class=\"vuln-badge vuln-{s}\">{s}</span>\n", .{ severity_class, @tagName(vt) });
                }
            }
            try writer.writeAll("                </div>\n");
        }

        try writer.writeAll("            </div>\n");
    }

    try writer.writeAll("        </div>\n");

    // Footer
    try writer.writeAll(
        \\        <footer>
        \\            Generated by ZigHunter v0.1.0 | Memory-Safe Security Scanning
        \\        </footer>
        \\    </div>
        \\</body>
        \\</html>
        \\
    );

    return output.toOwnedSlice();
}

/// Generate plain text report
fn generateTxt(allocator: std.mem.Allocator, results: []const scanner.ScanResult) ![]const u8 {
    var output = std.ArrayList(u8).init(allocator);
    defer output.deinit();

    const writer = output.writer();

    try writer.writeAll(
        \\================================================================================
        \\                         ZIGHUNTER SECURITY REPORT
        \\================================================================================
        \\
    );

    try writer.print("Generated: {}\n\n", .{std.time.timestamp()});

    // Statistics
    var total_findings: usize = 0;
    var critical_count: usize = 0;
    var high_count: usize = 0;
    var medium_count: usize = 0;
    var low_count: usize = 0;

    for (results) |result| {
        total_findings += result.vulnerabilities.items.len;
        for (result.vulnerabilities.items) |vuln| {
            switch (vuln.severity) {
                .critical => critical_count += 1,
                .high => high_count += 1,
                .medium => medium_count += 1,
                .low => low_count += 1,
                .informational => {},
            }
        }
    }

    try writer.writeAll("SUMMARY\n");
    try writer.writeAll("-------\n");
    try writer.print("Total Requests:    {}\n", .{results.len});
    try writer.print("Total Findings:    {}\n", .{total_findings});
    try writer.print("  Critical:        {}\n", .{critical_count});
    try writer.print("  High:            {}\n", .{high_count});
    try writer.print("  Medium:          {}\n", .{medium_count});
    try writer.print("  Low:             {}\n\n", .{low_count});

    try writer.writeAll("FINDINGS\n");
    try writer.writeAll("--------\n\n");

    for (results) |result| {
        if (result.vulnerabilities.items.len == 0) continue;

        try writer.print("[{}] {s}\n", .{ result.status_code, result.url });
        try writer.print("    Size: {} bytes | Time: {d:.2}ms\n", .{ result.content_length orelse 0, @as(f64, @floatFromInt(result.response_time_us)) / 1000.0 });

        for (result.vulnerabilities.items) |vuln| {
            if (vuln.vulnerability_type) |vt| {
                try writer.print("    [{s}] {s} (confidence: {d:.0}%)\n", .{ @tagName(vuln.severity), @tagName(vt), vuln.confidence * 100 });
                try writer.print("    Description: {s}\n", .{vuln_patterns.getDescription(vt)});
            }
        }
        try writer.writeAll("\n");
    }

    try writer.writeAll("================================================================================\n");
    try writer.writeAll("Generated by ZigHunter v0.1.0 - Memory-Safe Security Scanning\n");
    try writer.writeAll("================================================================================\n");

    return output.toOwnedSlice();
}

/// Escape JSON string
fn escapeJsonString(allocator: std.mem.Allocator, s: []const u8) ![]const u8 {
    var output = std.ArrayList(u8).init(allocator);
    defer output.deinit();

    const writer = output.writer();

    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => try writer.writeByte(c),
        }
    }

    return output.toOwnedSlice();
}
