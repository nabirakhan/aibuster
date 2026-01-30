# AIBuster v2.5.0 🚀

**AI-Powered Intelligent Directory & File Discovery Tool**

AIBuster is a professional penetration testing tool that uses AI models (Claude, OpenAI) to generate context-aware, technology-specific paths for directory enumeration.

## ✨ Key Features

### 🎨 Professional Design
- Clean ASCII art banner with proper alignment
- Gobuster-style output with professional indicators
- No clutter - pure efficiency

### 🤖 AI-Driven Path Generation
- **Claude AI Integration**: Enhanced prompts generating 60-100 high-quality paths
- **OpenAI Support**: GPT-powered intelligent path suggestions
- **Local Mode**: No API required fallback with enhanced patterns
- **Context-Aware**: Adapts to detected technologies and keywords

### 🔍 Reconnaissance-First Approach
- Identifies frameworks, CMSs, and CDNs
- Extracts keywords from page content
- Detects technologies automatically
- Prioritizes high-probability paths

### ⚡ Performance & Control
- Multi-threaded scanning (1-100 threads)
- Rate limiting and request delays
- Retry logic with exponential backoff
- Progress bars with ETA

### 🔌 Advanced Plugin System

#### 1. WordPress Scanner
- Version detection, plugin & theme enumeration, user enumeration detection, vulnerability scanning, security misconfiguration checks

#### 2. Sensitive Files Scanner
- Environment files (.env, configs), backup file detection, log file discovery, version control artifacts (.git, .svn), severity-based classification (Critical/High/Medium/Low)

#### 3. API Scanner
- REST/GraphQL/SOAP detection, endpoint enumeration, authentication analysis, security issue detection, API documentation discovery

#### 4. Shopify Scanner (NEW!)
- Store information gathering, product & collection enumeration, exposed endpoint detection, API accessibility checks, security misconfiguration identification

### 📊 Professional Reporting
- Real-time console output (Gobuster-style)
- JSON, CSV, HTML, XML, Markdown formats
- Interactive HTML reports with statistics
- Detailed security findings

## 🚀 Installation

```bash
git clone https://github.com/yourusername/aibuster.git
cd aibuster
pip install -r requirements.txt
chmod +x aibuster.py
export ANTHROPIC_API_KEY="your-claude-api-key"
```

## 📖 Quick Start

### Basic Scan
```bash
python3 aibuster.py -u https://example.com
```

### AI-Powered Scan
```bash
python3 aibuster.py -u https://target.com --ai-model claude -v
```

### Full Security Audit
```bash
python3 aibuster.py -u https://target.com \
    --ai-model claude \
    --plugins wordpress,sensitive-files,api-scanner,shopify \
    -t 15 -v \
    -o report.html --format html
```

## 💻 Usage Examples

### WordPress Security Scan
```bash
python3 aibuster.py -u https://wordpress-site.com \
    --plugins wordpress,sensitive-files \
    -v -o wp-audit.json
```

### Shopify Store Analysis
```bash
python3 aibuster.py -u https://store.myshopify.com \
    --plugins shopify,api-scanner,sensitive-files \
    -v -o shopify-report.html --format html
```

### API Endpoint Discovery
```bash
python3 aibuster.py -u https://api.example.com \
    --plugins api-scanner \
    --extensions json,xml,graphql \
    -v
```

### Stealth Scan
```bash
python3 aibuster.py -u https://target.com \
    -t 5 --delay 1 --rate-limit 10 \
    --ai-model local
```

## 🎯 Command-Line Options

### Required
```
-u, --url          Target URL
```

### Performance
```
-t, --threads      Number of threads (default: 10)
--timeout          Request timeout seconds (default: 5)
--delay            Delay between requests
--retries          Number of retries (default: 2)
--rate-limit       Max requests per minute
```

### AI & Path Generation
```
--ai-model         AI model: claude, openai, local (default: local)
--api-key          API key for AI services
--no-ai            Disable AI path generation
--wordlist         Use custom wordlist
--extensions       File extensions (default: php,html,js,txt,json)
--depth            Directory depth 1-3
```

### Output
```
-o, --output       Save results to file
--format           Output format: json, csv, html, xml, md
-v, --verbose      Verbose output
--quiet            Minimal output
--debug            Debug mode
```

### Advanced
```
--plugins          Enable plugins (comma-separated: wordpress,api-scanner,sensitive-files,shopify)
--proxy            HTTP proxy
--cookies          Custom cookies
--headers          Custom headers (JSON)
--user-agent       Custom User-Agent
```

## 📊 Output Format

Professional Gobuster-style output with proper alignment:

```
╔═════════════════════════════════════════════════════════════════════════╗
║                                                                         ║
║    █████╗ ██╗██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗         ║
║   ██╔══██╗██║██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗        ║
║   ███████║██║██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝        ║
║   ██╔══██║██║██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗        ║
║   ██║  ██║██║██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║        ║
║   ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝        ║
║                                                                         ║
╚═════════════════════════════════════════════════════════════════════════╝

[+] /admin                     [Status: 200] [Size: 4.2KB]
[+] /api/v1                    [Status: 200] [Size: 156B]
[-] /config.php                [Status: 403] [Size: 278B]
[!] /.env                      [Status: 401] [Size: 0B]
[>] /old-site                  [Status: 301] [Size: 185B]
```

### Symbol Legend
- `[+]` - Success / Found (200)
- `[-]` - Error / Forbidden (403)
- `[*]` - Information / Status
- `[!]` - Warning / Unauthorized (401)
- `[>]` - Redirect (301/302)
- `[~]` - Processing / AI Activity
- `[#]` - Plugin Activity

## 🔌 Plugin System

### WordPress Scanner
Comprehensive WordPress security analysis: automatic detection, version identification, plugin/theme enumeration, user enumeration testing, XMLRPC detection, debug log exposure, config backup detection

### Sensitive Files Scanner
Discovers exposed sensitive files with severity ratings:
- 🔴 **Critical**: .env, passwords, secrets, credentials
- 🟠 **High**: Configs, database files, .git directories
- 🟡 **Medium**: Logs, backup files
- 🟢 **Low**: Version disclosure files

### API Scanner
Analyzes API endpoints for security: REST/GraphQL/SOAP detection, authentication analysis, parameter extraction, documentation discovery

### Shopify Scanner
Comprehensive Shopify store analysis: store information gathering, product/collection enumeration, cart API detection, GraphQL endpoint identification, admin area accessibility checks

## 🛡️ Security Best Practices

1. **Authorization**: Only scan systems you have permission to test
2. **Rate Limiting**: Use `--rate-limit` to avoid overwhelming servers
3. **Stealth**: Use delays and low thread counts for sensitive targets
4. **Results Security**: Store scan results securely
5. **API Keys**: Keep API keys secure, use environment variables

## 📈 Performance Tips

1. **Start Conservative**: Begin with 5-10 threads
2. **Use AI Wisely**: AI models provide best results for unknown targets
3. **Combine Plugins**: Use multiple plugins for comprehensive assessment
4. **HTML Reports**: Generate professional reports for clients
5. **Verbose Mode**: Use `-v` for detailed progress tracking

## 🎓 AI Models

| Model | Speed | Quality | Cost | Best For |
|-------|-------|---------|------|----------|
| **local** | ⚡⚡⚡ | ⭐⭐⭐ | Free | Quick scans, known targets |
| **claude** | ⚡⚡ | ⭐⭐⭐⭐⭐ | Low | Unknown targets, best quality |
| **openai** | ⚡⚡ | ⭐⭐⭐⭐ | Medium | Alternative to Claude |

## 🆕 What's New in v2.5.0

### Design Improvements
- ✅ Fixed banner alignment - perfect box borders
- ✅ Removed all code comments and extra lines
- ✅ Clean, compact, professional code
- ✅ Improved Gobuster-style output

### AI Enhancements
- ✅ Enhanced Claude prompts (60-100 paths vs 30-50)
- ✅ Better context awareness and categorization
- ✅ Improved prompt structure with 10 categories
- ✅ Technology-specific and keyword-based path generation

### Plugin System
- ✅ Enhanced WordPress scanner
- ✅ Improved Sensitive Files scanner
- ✅ Better API scanner
- ✅ **NEW: Shopify Scanner** - comprehensive store analysis

### Code Quality
- ✅ Removed all unnecessary comments
- ✅ Compact, efficient code
- ✅ Better error handling
- ✅ Improved performance

## 📂 Project Structure

```
aibuster/
├── aibuster.py         # Main entry point (v2.5.0)
├── ai.py              # Enhanced AI path generation
├── buster.py          # Path enumeration engine
├── output.py          # Professional output formatting
├── plugins.py         # Plugin system (4 plugins)
├── recon.py           # Reconnaissance module
├── requirements.txt   # Dependencies
├── README.md          # This file
└── quickref.md        # Quick reference card
```

## 📄 License

MIT License - see LICENSE file for details

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional plugins
- New AI models
- Enhanced detection patterns
- Performance optimizations
- Documentation improvements

## 📧 Contact & Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check quickref.md for quick reference
- Enable `--debug` mode for troubleshooting

---

**AIBuster v2.5.0** - Professional AI-Powered Directory Enumeration  
*Security Research Tool - Use Responsibly*