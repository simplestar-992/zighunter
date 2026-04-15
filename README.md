# Zighunter | Advanced HTTP Security Scanner

![Security Scanner](https://img.shields.io/badge/Type-Security%20Scanner-red?style=for-the-badge)
![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Stars](https://img.shields.io/github/stars/simplestar-992/zighunter?style=for-the-badge)

---

## Why Zighunter?

Every security professional needs a fast, reliable way to audit HTTP endpoints. Most tools are bloated, require complex setup, or miss critical vulnerabilities. Zighunter changes that.

**Built for:**
- Bug bounty hunters who need speed
- Security researchers auditing APIs
- DevOps teams validating configurations
- Developers testing their own code

---

## Features

| Category | What You Get |
|----------|-------------|
| **Speed** | Concurrent scanning with configurable threads |
| **Coverage** | 50+ vulnerability patterns built-in |
| **Precision** | Low false positive rate with confidence scoring |
| **Simplicity** | Single binary, zero dependencies |
| **Fuzzing** | Built-in mutation engine for custom payloads |
| **Reports** | JSON output for CI/CD integration |

### Vulnerability Types Detected

- SQL Injection indicators
- Cross-Site Scripting (XSS)
- Path Traversal
- Open Redirects
- SSRF indicators
- Information Disclosure
- Authentication Bypass patterns
- Missing Security Headers
- And more...

---

## Installation

### Binary (Recommended)

```bash
# Download from releases
curl -sL https://github.com/simplestar-992/zighunter/releases | grep -o 'zighunter-.*-linux-amd64' | head -1

# Or build from source
git clone https://github.com/simplestar-992/zighunter.git
cd zighunter
go build -o zighunter -ldflags="-s -w"
```

### From Source

```bash
# Requires Go 1.21+
git clone https://github.com/simplestar-992/zighunter.git
cd zighunter
go build -o zighunter .
```

---

## Quick Start

### Basic Scan

```bash
# Scan a single URL
./zighunter -u https://example.com

# Scan with custom wordlist
./zighunter -u https://example.com -w /path/to/wordlist.txt
```

### Advanced Usage

```bash
# Concurrent scan with 20 threads
./zighunter -u https://example.com -t 20

# Fuzz a parameter
./zighunter -u https://example.com/api?id=FUZZ -m fuzz

# Scan multiple URLs from file
./zighunter -l urls.txt -o results.json

# Enable verbose output
./zighunter -u https://example.com -v
```

### Command Reference

| Flag | Description | Example |
|------|-------------|---------|
| `-u` | Target URL | `-u https://example.com` |
| `-w` | Wordlist path | `-w /usr/share/wordlist.txt` |
| `-t` | Number of threads | `-t 20` |
| `-o` | Output file | `-o results.json` |
| `-m` | Scan mode | `-m fuzz`, `-m quick`, `-m deep` |
| `-v` | Verbose output | `-v` |
| `-h` | Show help | `-h` |

---

## Output Examples

### Standard Output

```
[~] Zighunter v1.0 - Advanced HTTP Security Scanner
[~] Starting scan of: https://example.com

[+] Discovered: /admin
[+] Discovered: /api
[+] Discovered: /robots.txt

[LOW] Missing Security Headers
    Confidence: 0.7
    Impact: Server lacks X-Frame-Options, CSP headers

[MEDIUM] Potential SQL Injection
    Endpoint: /api/users?id=1
    Confidence: 0.85
    Evidence: Error message detected in response

[~] Scan complete: 45 paths tested in 3.2s
```

### JSON Output (for CI/CD)

```json
{
  "target": "https://example.com",
  "scan_time": "3.2s",
  "vulnerabilities": [
    {
      "type": "sql_injection",
      "severity": "medium",
      "confidence": 0.85,
      "endpoint": "/api/users?id=1",
      "evidence": "Error message in response"
    }
  ]
}
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ZIGHUNTER                            │
├─────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐         │
│  │   CLI    │  │ Scanner  │  │  Fuzzer      │         │
│  │  Parser  │──│  Engine  │──│  Engine      │         │
│  └──────────┘  └──────────┘  └──────────────┘         │
│       │              │               │                  │
│       v              v               v                  │
│  ┌─────────────────────────────────────────────┐      │
│  │           Vulnerability Detector             │      │
│  │  • Pattern Matching  • Response Analysis   │      │
│  │  • Header Check      • Timing Attacks      │      │
│  └─────────────────────────────────────────────┘      │
│                         │                             │
│                         v                             │
│  ┌─────────────────────────────────────────────┐      │
│  │              Report Generator               │      │
│  └─────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────┘
```

---

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing`)
5. Open a Pull Request

---

## Roadmap

- [ ] HTTPS support with TLS inspection
- [ ] Custom vulnerability template system
- [ ] Proxy support (HTTP/SOCKS)
- [ ] Web UI dashboard
- [ ] Integration with popular CI/CD tools

---

## License

MIT © 2024 [simplestar-992](https://github.com/simplestar-992)

---

<p align="center">
  <a href="https://github.com/simplestar-992/zighunter/stargazers">
    <img src="https://img.shields.io/github/stars/simplestar-992/zighunter?style=social" alt="Stars"/>
  </a>
  <a href="https://github.com/simplestar-992/zighunter/network/members">
    <img src="https://img.shields.io/github/forks/simplestar-992/zighunter?style=social" alt="Forks"/>
  </a>
</p>
