# AIBuster v2.5.0 - Quick Reference Card

## 🚀 Quick Start Commands

### Basic Scan
```bash
python3 aibuster.py -u https://example.com
```

### AI Scan with Claude
```bash
python3 aibuster.py -u https://example.com --ai-model claude -v
```

### WordPress Audit
```bash
python3 aibuster.py -u https://wp-site.com --plugins wordpress,sensitive-files -v
```

### API Discovery
```bash
python3 aibuster.py -u https://api.example.com --plugins api-scanner -v
```

### Full Security Audit
```bash
python3 aibuster.py -u https://target.com \
    --ai-model claude \
    --plugins wordpress,sensitive-files,api-scanner \
    -t 15 -v -o report.html --format html
```

## 📋 Essential Options

| Option | Description | Example |
|--------|-------------|---------|
| `-u` | Target URL | `-u https://example.com` |
| `-t` | Threads | `-t 20` |
| `-v` | Verbose | `-v` |
| `-o` | Output file | `-o results.json` |
| `--ai-model` | AI model | `--ai-model claude` |
| `--plugins` | Enable plugins | `--plugins wordpress,api-scanner` |
| `--format` | Output format | `--format html` |
| `--delay` | Request delay | `--delay 1` |

## 🔌 Available Plugins

| Plugin | Description |
|--------|-------------|
| `wordpress` | WordPress security scanner |
| `sensitive-files` | Sensitive file detector |
| `api-scanner` | API endpoint analyzer |

## 🎨 Output Symbols

| Symbol | Meaning |
|--------|---------|
| `[+]` | Found/Success (200) |
| `[-]` | Forbidden (403) |
| `[*]` | Information |
| `[!]` | Warning/Unauthorized (401) |
| `[>]` | Redirect (3xx) |
| `[~]` | AI Processing |
| `[#]` | Plugin Activity |

## 🔧 Setup

```bash
# Install
pip install -r requirements.txt

# Set API key
export ANTHROPIC_API_KEY="your-key"

# Test
python3 aibuster.py --help
```

## 📊 Output Formats

- `json` - Machine-readable
- `html` - Professional reports
- `csv` - Spreadsheet import
- `xml` - Structured data
- `md` - Markdown docs

## ⚡ Performance

| Scan Type | Threads | Delay | Rate Limit |
|-----------|---------|-------|------------|
| Quick | 10 | 0 | None |
| Normal | 15 | 0 | None |
| Stealth | 5 | 1s | 30/min |
| Aggressive | 25 | 0 | None |

## 🛡️ Best Practices

1. ✅ Get authorization first
2. ✅ Start with low threads
3. ✅ Use rate limiting on production
4. ✅ Enable verbose mode
5. ✅ Save results with `-o`
6. ✅ Use plugins for deep scans

## 🔒 Legal

**Always obtain authorization before scanning!**

Unauthorized scanning is illegal.

---

For full documentation, see:
- `README.md` - Complete guide
- `SETUP_GUIDE.md` - Detailed setup
- `aibuster.py --help` - CLI help