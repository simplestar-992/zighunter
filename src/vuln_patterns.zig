//! Vulnerability Pattern Detection Module
//! 
//! Detects common vulnerability patterns in HTTP responses.
//! Memory-safe pattern matching optimized for security scanning.

const std = @import("std");
const http_client = @import("http_client.zig");

pub const VulnerabilityType = enum {
    sql_injection,
    xss_reflected,
    xss_stored,
    path_traversal,
    open_redirect,
    ssrf,
    information_disclosure,
    authentication_bypass,
    idor,
    csrf,
    command_injection,
    xxsi,
    deserialization,
    crypto_weakness,
    misconfiguration,
    rate_limit_bypass,
    unknown,
};

pub const VulnerabilityInfo = struct {
    vulnerability_type: ?VulnerabilityType,
    confidence: f32,
    evidence: ?[]const u8,
    severity: Severity,

    pub const Severity = enum {
        critical,
        high,
        medium,
        low,
        informational,
    };
};

/// Pattern definition
pub const Pattern = struct {
    name: []const u8,
    patterns: []const []const u8,
    vuln_type: VulnerabilityType,
    severity: VulnerabilityInfo.Severity,
    confidence_boost: f32,
};

/// Compile-time defined vulnerability patterns
pub const vulnerability_patterns = [_]Pattern{
    // SQL Injection patterns
    .{
        .name = "SQL Error Disclosure",
        .patterns = &[_][]const u8{
            "SQL syntax",
            "mysql_fetch",
            "ORA-",
            "PLS-",
            "Unclosed quotation mark",
            "quoted string not properly terminated",
            "sql error",
            "SQLException",
            "MySQLSyntaxErrorException",
            "PostgreSQL",
            "Warning: mysql_",
            "valid MySQL result",
            "MySqlClient",
            "SQLServer",
            "SQLite3::SQLException",
            "SQLSTATE[",
            "DB2 SQL error",
            "ODBC",
        },
        .vuln_type = .sql_injection,
        .severity = .high,
        .confidence_boost = 0.8,
    },
    // XSS patterns
    .{
        .name = "Reflected XSS",
        .patterns = &[_][]const u8{
            "<script>",
            "javascript:",
            "onerror=",
            "onload=",
            "onclick=",
            "onmouseover=",
            "<img src=x",
            "<svg onload",
            "<iframe",
            "<body onload",
            "alert(",
            "prompt(",
            "confirm(",
            "document.cookie",
            "document.location",
            "eval(",
            "expression(",
        },
        .vuln_type = .xss_reflected,
        .severity = .high,
        .confidence_boost = 0.7,
    },
    // Path traversal patterns
    .{
        .name = "Path Traversal",
        .patterns = &[_][]const u8{
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/proc/self",
            "/windows/system32",
            "boot.ini",
            "win.ini",
            "System32\\config\\",
            "\\Windows\\",
            "..%2f",
            "..%5c",
            "..%c0%af",
            "file://",
            "root:",
            "daemon:",
        },
        .vuln_type = .path_traversal,
        .severity = .critical,
        .confidence_boost = 0.9,
    },
    // Open redirect patterns
    .{
        .name = "Open Redirect",
        .patterns = &[_][]const u8{
            "Location: http://",
            "Location: https://",
            "Location: //",
            "window.location",
            "window.location.href",
            "document.location",
            "document.location.href",
            "window.open",
            "header('Location",
            "Response.Redirect",
            "response.sendRedirect",
        },
        .vuln_type = .open_redirect,
        .severity = .medium,
        .confidence_boost = 0.6,
    },
    // Information disclosure patterns
    .{
        .name = "Information Disclosure",
        .patterns = &[_][]const u8{
            "Stack trace",
            "Exception",
            "Error in",
            "at ",
            ".java:",
            ".php on line",
            "Traceback (most recent call last)",
            "File \"/",
            "line ",
            "DEBUG = true",
            "debug = true",
            "phpinfo()",
            "var_dump",
            "print_r",
            "stack_dump",
            "Server: ",
            "X-Powered-By:",
            "X-AspNet-Version",
            "Apache/",
            "nginx/",
            "Microsoft-IIS/",
            "PHP/",
        },
        .vuln_type = .information_disclosure,
        .severity = .low,
        .confidence_boost = 0.5,
    },
    // SSRF patterns
    .{
        .name = "SSRF Indicators",
        .patterns = &[_][]const u8{
            "169.254.",
            "metadata.google",
            "metadata.azure",
            "169.254.169.254",
            "internal.",
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "[::1]",
            "EC2",
            "EC2_METADATA",
        },
        .vuln_type = .ssrf,
        .severity = .high,
        .confidence_boost = 0.7,
    },
    // Command injection patterns
    .{
        .name = "Command Injection",
        .patterns = &[_][]const u8{
            "uid=",
            "gid=",
            "groups=",
            "total ",
            "drwx",
            "-rw-",
            "-rwx",
            "root:",
            "nobody:",
            "bin/bash",
            "/bin/sh",
            "cmd.exe",
            "powershell",
            "whoami",
            "net user",
            "ipconfig",
            "ifconfig",
        },
        .vuln_type = .command_injection,
        .severity = .critical,
        .confidence_boost = 0.9,
    },
    // XXE patterns
    .{
        .name = "XXE Indicators",
        .patterns = &[_][]const u8{
            "<!ENTITY",
            "SYSTEM \"",
            "PUBLIC \"",
            "<!DOCTYPE",
            "ENTITY %",
            "ENTITY x",
            ".dtd",
            "xmlns:",
            "xsi:schemaLocation",
            "xsi:noNamespaceSchemaLocation",
        },
        .vuln_type = .xxsi,
        .severity = .high,
        .confidence_boost = 0.8,
    },
    // Authentication bypass patterns
    .{
        .name = "Auth Bypass",
        .patterns = &[_][]const u8{
            "admin",
            "administrator",
            "root",
            "debug",
            "test",
            "guest",
            "password",
            "passwd",
            "pwd",
            "secret",
            "key",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "bearer",
            "jwt",
            "session",
            "cookie",
        },
        .vuln_type = .authentication_bypass,
        .severity = .high,
        .confidence_boost = 0.6,
    },
    // IDOR patterns
    .{
        .name = "IDOR Indicators",
        .patterns = &[_][]const u8{
            "user_id=",
            "id=",
            "uid=",
            "account=",
            "profile=",
            "document=",
            "file_id=",
            "order_id=",
            "transaction=",
            "record=",
        },
        .vuln_type = .idor,
        .severity = .high,
        .confidence_boost = 0.5,
    },
    // Deserialization patterns
    .{
        .name = "Deserialization Issues",
        .patterns = &[_][]const u8{
            "O:",
            "rO0AB",
            "pickle",
            "marshal",
            "yaml.load",
            "__reduce__",
            "__import__",
            "java.lang.Object",
            "java.io.Serializable",
            "readObject",
            "readUnshared",
            "ObjectInputStream",
            "ObjectOutputStream",
            "MarshalByRefObject",
        },
        .vuln_type = .deserialization,
        .severity = .critical,
        .confidence_boost = 0.8,
    },
    // Security headers missing
    .{
        .name = "Missing Security Headers",
        .patterns = &[_][]const u8{},
        .vuln_type = .misconfiguration,
        .severity = .low,
        .confidence_boost = 0.4,
    },
};

/// Response analyzer - note: requires allocator for case-insensitive search
pub fn analyzeResponse(response: http_client.Response, input: []const u8) VulnerabilityInfo {
    var result: VulnerabilityInfo = .{
        .vulnerability_type = null,
        .confidence = 0.0,
        .evidence = null,
        .severity = .informational,
    };

    // Check for reflected input (XSS indicator)
    if (std.mem.indexOf(u8, response.body, input) != null) {
        result.confidence += 0.3;
        result.vulnerability_type = .xss_reflected;
        result.severity = .high;
    }

    // Check status code patterns
    if (response.status_code >= 500) {
        result.confidence += 0.4;
        result.severity = .medium;
    }

    // Check response time anomalies (timing attacks)
    if (response.response_time_us > 1000000) { // > 1 second
        result.confidence += 0.1;
    }

    // Check body for vulnerability patterns (case-sensitive for simplicity)
    for (vulnerability_patterns) |pattern| {
        for (pattern.patterns) |sig| {
            // Simple case-sensitive search
            if (std.mem.indexOf(u8, response.body, sig)) |pos| {
                result.confidence += pattern.confidence_boost;
                if (result.vulnerability_type == null) {
                    result.vulnerability_type = pattern.vuln_type;
                }
                result.severity = pattern.severity;
                result.evidence = response.body[pos..@min(pos + 100, response.body.len)];
                break;
            }
        }
    }

    // Check headers for security issues
    checkSecurityHeaders(&result, response);

    // Cap confidence at 1.0
    result.confidence = @min(result.confidence, 1.0);

    return result;
}

/// Check for missing security headers
fn checkSecurityHeaders(result: *VulnerabilityInfo, response: http_client.Response) void {
    const security_headers = [_][]const u8{
        "X-Frame-Options",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "Referrer-Policy",
        "Permissions-Policy",
    };

    var missing_count: usize = 0;
    for (security_headers) |header_name| {
        if (response.getHeader(header_name) == null) {
            missing_count += 1;
        }
    }

    if (missing_count > 3) {
        result.confidence += 0.3;
        result.vulnerability_type = .misconfiguration;
        result.severity = .low;
    }
}

/// Get vulnerability description
pub fn getDescription(vuln_type: VulnerabilityType) []const u8 {
    return switch (vuln_type) {
        .sql_injection => "SQL Injection vulnerability detected. Database error messages or SQL syntax errors visible in response.",
        .xss_reflected => "Reflected Cross-Site Scripting (XSS) detected. User input is reflected in the response without proper sanitization.",
        .xss_stored => "Stored Cross-Site Scripting (XSS) detected. Malicious script may be persisted and executed by other users.",
        .path_traversal => "Path Traversal vulnerability detected. Application may be accessing files outside web root.",
        .open_redirect => "Open Redirect vulnerability detected. Application redirects to user-controlled URLs.",
        .ssrf => "Server-Side Request Forgery (SSRF) indicators detected. Application may make requests to internal resources.",
        .information_disclosure => "Information Disclosure detected. Sensitive information may be exposed in responses.",
        .authentication_bypass => "Authentication Bypass indicators detected. Authentication mechanisms may be circumventable.",
        .idor => "Insecure Direct Object Reference (IDOR) indicators detected. Users may access other users' data.",
        .csrf => "Cross-Site Request Forgery (CSRF) vulnerability detected. Missing or weak CSRF protection.",
        .command_injection => "Command Injection vulnerability detected. System commands may be executed by attackers.",
        .xxsi => "XML External Entity (XXE) injection indicators detected. XML parser may be vulnerable.",
        .deserialization => "Insecure Deserialization vulnerability detected. Untrusted data may be deserialized.",
        .crypto_weakness => "Cryptographic weakness detected. Weak or insecure cryptographic implementations.",
        .misconfiguration => "Security misconfiguration detected. Missing security headers or insecure configurations.",
        .rate_limit_bypass => "Rate Limit Bypass possible. Application lacks proper rate limiting.",
        .unknown => "Unknown vulnerability pattern detected. Manual investigation recommended.",
    };
}

/// Get remediation advice
pub fn getRemediation(vuln_type: VulnerabilityType) []const u8 {
    return switch (vuln_type) {
        .sql_injection => "Use parameterized queries or prepared statements. Validate and sanitize all user input.",
        .xss_reflected, .xss_stored => "Encode all user-controlled data before rendering. Implement Content-Security-Policy headers.",
        .path_traversal => "Validate and sanitize file paths. Use allowlists for file access. Avoid user input in file paths.",
        .open_redirect => "Validate and sanitize redirect URLs. Use allowlists for permitted redirect destinations.",
        .ssrf => "Validate and sanitize URLs before making requests. Block requests to internal IP ranges.",
        .information_disclosure => "Disable detailed error messages in production. Remove sensitive information from responses.",
        .authentication_bypass => "Implement proper authentication checks. Use secure session management.",
        .idor => "Implement proper access control checks. Validate user permissions before data access.",
        .csrf => "Implement anti-CSRF tokens. Use SameSite cookie attribute.",
        .command_injection => "Avoid shell commands with user input. Use allowlists for command arguments.",
        .xxsi => "Disable external entity processing in XML parsers. Use JSON instead of XML when possible.",
        .deserialization => "Avoid deserializing untrusted data. Use safe deserialization libraries.",
        .crypto_weakness => "Use strong, modern cryptographic algorithms. Keep cryptographic libraries updated.",
        .misconfiguration => "Implement security headers. Review and harden server configuration.",
        .rate_limit_bypass => "Implement rate limiting at application and network level.",
        .unknown => "Investigate the finding manually. Consult security documentation.",
    };
}

test "vulnerability pattern matching" {
    const allocator = std.testing.allocator;

    const body = "Error: SQL syntax error near 'SELECT'";
    const mock_response = http_client.Response{
        .allocator = allocator,
        .status_code = 500,
        .status_text = "Internal Server Error",
        .headers = &.{},
        .body = body,
        .content_length = body.len,
        .content_type = null,
        .response_time_us = 50000,
    };

    const result = analyzeResponse(mock_response, "test");

    try std.testing.expect(result.vulnerability_type == .sql_injection);
    try std.testing.expect(result.confidence > 0.5);
}
