# ZigHunter 🛡️


**High-Performance HTTP Security Scanner for Bug Bounty Hunters**

![Zig](https://img.shields.io/badge/Zig-0.13.0-orange?logo=zig&logoColor=white)

![License](https://img.shields.io/badge/License-MIT-blue.svg)

![Security](https://img.shields.io/badge/Security-Scanner-red.svg)

![Stars](https://img.shields.io/github/stars/mistyrain/zighunter?style=social)

## Overview

ZigHunter is a blazing-fast, memory-safe HTTP security scanner built entirely in [Zig](https://ziglang.org). It leverages Zig's comptime features for compile-time configured fuzzing strategies and provides professional-grade security scanning for bug bounty hunting.

## Features

- 🚀 **Blazing Fast** - Native Zig performance with concurrent thread pool
- 🔒 **Memory Safe** - No memory leaks, no buffer overflows by design
- 🎯 **Comptime Fuzzing** - Compile-time configured mutation strategies
- 🕵️ **Path Discovery** - Built-in wordlists + custom wordlist support
- 🛡️ **Vulnerability Detection** - SQL injection, XSS, SSRF, path traversal & more
- 📊 **Multiple Output Formats** - JSON, HTML, and TXT reports
- ⚙️ **Highly Configurable** - Threads, timeouts, rate limiting, depth control

## Installation

### From Source

```bash
git clone https://github.com/mistyrain/zighunter.git
cd zighunter
zig build --release=fast
./zig-out/zighunter --help
```

### Pre-built Binary

Download from the Releases page.

## Quick Start

```bash
# Basic scan
zighunter https://example.com

# Scan with more threads
zighunter -t 20 https://example.com

# Deep scan with fuzzing
zighunter -d deep --fuzz --fuzz-iterations 5000 https://example.com

# Custom wordlist and output
zighunter -w paths.txt -o report.json -f json https://example.com
```

## Usage

```markdown
Usage: zighunter [OPTIONS] <TARGET_URL>

Arguments:
  <TARGET_URL>          Target URL to scan (e.g., https://example.com)

Options:
  -w, --wordlist <PATH>     Custom wordlist for path discovery
  -t, --threads <NUM>       Number of concurrent threads (default: 10)
  --timeout <MS>            Request timeout in milliseconds (default: 5000)
  -o, --output <PATH>       Output file path
  -f, --format <FORMAT>     Output format: json, html, txt (default: json)
  --rate-limit <MS>         Rate limit between requests in milliseconds
  --no-redirects            Don't follow redirects
  --max-redirects <NUM>     Maximum redirects to follow (default: 5)
  -u, --user-agent <UA>     Custom User-Agent string
  -H, --header <HEADER>     Add custom header
  -d, --depth <LEVEL>       Scan depth: quick, standard, deep (default: standard)
  --fuzz                    Enable fuzzing mode
  --fuzz-iterations <NUM>   Number of fuzzing iterations (default: 1000)
  -h, --help                Show this help message
  -v, --version             Show version information

Examples:
  zighunter https://example.com
  zighunter -w paths.txt -t 20 https://example.com
  zighunter --fuzz --fuzz-iterations 5000 https://api.example.com
  zighunter -H "Authorization: Bearer token123" https://api.example.com
```

## Architecture

### Comptime Fuzzing

ZigHunter uses Zig's powerful comptime features to configure fuzzing strategies at compile time:

```zig
pub fn MutationStrategy(comptime T: type) type {
    _ = T; // Reserved for future extensibility
    return struct {
        name: []const u8,
        mutateFn: fn (std.mem.Allocator, []const u8, u64) []const u8,
    };
}
```

### Supported Vulnerability Types

| Type | Severity | Description |
| --- | --- | --- |
| SQL Injection | Critical | Database error detection |
| XSS (Reflected/Stored) | High | Cross-site scripting |
| Path Traversal | High | Directory traversal attacks |
| SSRF | High | Server-side request forgery |
| Command Injection | Critical | OS command execution |
| XXE | High | XML external entity |
| Open Redirect | Medium | Unvalidated redirects |
| IDOR | High | Insecure direct object reference |
| Information Disclosure | Medium | Sensitive data exposure |

### Thread Pool Architecture

```markdown
┌─────────────────────────────────────────────┐
│              ZigHunter Scanner              │
├─────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐     │
│  │Worker 1 │  │Worker 2 │  │Worker N │     │
│  └────┬────┘  └────┬────┘  └────┬────┘     │
│       │             │             │         │
│  ┌────▼─────────────▼─────────────▼────┐    │
│  │      Shared Wordlist (atomic idx)   │    │
│  └─────────────────────────────────────┘    │
│                    │                        │
│  ┌─────────────────▼───────────────────┐    │
│  │     Results (mutex-protected)       │    │
│  └─────────────────────────────────────┘    │
└─────────────────────────────────────────────┘
```

## Output Examples

### JSON Output

```json
{
  "target": "https://example.com",
  "scan_time": "2024-01-15T10:30:00Z",
  "results": [
    {
      "url": "/admin",
      "method": "GET",
      "status_code": 200,
      "vulnerabilities": [
        {
          "type": "information_disclosure",
          "confidence": 0.7,
          "severity": "medium"
        }
      ]
    }
  ]
}
```

## Roadmap

- [ ]  HTTPS/TLS support

- [ ]  WebSocket scanning

- [ ]  GraphQL fuzzing

- [ ]  CI/CD integration examples

- [ ]  Burp Suite extension

- [ ]  Distributed scanning mode

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Zig Software Foundation](https://ziglang.org/) for the amazing language
- [OWASP](https://owasp.org/) for vulnerability classification standards
- All bug bounty hunters who inspire tool development

## Disclaimer

ZigHunter is for authorized security testing only. Always get proper authorization before scanning any target. The authors are not responsible for misuse of this tool.

---

**Made with ❤️ and Zig**