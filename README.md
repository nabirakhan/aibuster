# AIBuster v2.5.0 🚀

**AI-Powered Intelligent Directory & File Discovery Tool**

AIBuster is a professional penetration testing tool that uses AI models (Claude, OpenAI) to generate context-aware, technology-specific paths for directory enumeration. Designed with a WraithXSS-inspired interface and Gobuster/Dirbuster-style output.

---

## ✨ Key Features

### 🎨 Professional Design
- **WraithXSS-Inspired Banner**: Clean ASCII art with system status
- **Gobuster-Style Output**: Professional `[+]`, `[-]`, `[*]`, `[!]` indicators
- **No Emoji Clutter**: Clean, professional security tool aesthetics

### 🤖 AI-Driven Path Generation
- **Claude AI Integration**: Best-in-class path generation with improved prompts
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
- Version detection
- Plugin & theme enumeration  
- User enumeration detection
- Vulnerability scanning
- Security misconfiguration checks

#### 2. Sensitive Files Scanner
- Environment files (.env, configs)
- Backup file detection
- Log file discovery
- Version control artifacts (.git, .svn)
- Severity-based classification (Critical/High/Medium/Low)

#### 3. API Scanner
- REST/GraphQL/SOAP detection
- Endpoint enumeration
- Authentication analysis
- Security issue detection
- API documentation discovery

### 📊 Professional Reporting
- Real-time console output (Gobuster-style)
- JSON, CSV, HTML, XML, Markdown formats
- Interactive HTML reports with statistics
- Detailed security findings

---

## 🚀 Installation

```bash
# Clone repository
git clone https://github.com/yourusername/aibuster.git
cd aibuster

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x aibuster.py

# Set up API key (optional)
export ANTHROPIC_API_KEY="your-claude-api-key"
```

---

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
    --plugins wordpress,sensitive-files,api-scanner \
    -t 15 -v \
    -o report.html --format html
```

---

## 💻 Usage Examples

### WordPress Security Scan
```bash
python3 aibuster.py -u https://wordpress-site.com \
    --plugins wordpress,sensitive-files \
    -v -o wp-audit.json
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

### Custom Wordlist Scan
```bash
python3 aibuster.py -u https://target.com \
    --wordlist custom-paths.txt \
    --extensions php,html \
    -t 20
```

---

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
--plugins          Enable plugins (comma-separated)
--proxy            HTTP proxy
--cookies          Custom cookies
--headers          Custom headers (JSON)
--user-agent       Custom User-Agent
```

---

## 📊 Output Format

Professional Gobuster/Dirbuster-style output:

```
═══════════════════════════════════════════════════════════════════════════════
                             » SYSTEM STATUS «                                
═══════════════════════════════════════════════════════════════════════════════

[+] [12:34:56] INITIATING SYSTEM SCAN
[*] [12:34:57] PERFORMING RECONNAISSANCE
[~] [12:34:58] GENERATING AI PATHS - MODEL: CLAUDE
[>] [12:34:59] INITIATING PATH ENUMERATION - THREADS: 10

[+] /admin                                              [Status: 200] [Size: 4.2KB]
[+] /api/v1                                            [Status: 200] [Size: 156B]
[-] /config.php                                         [Status: 403] [Size: 278B]
[!] /.env                                              [Status: 401] [Size: 0B]
[>] /old-site                                          [Status: 301] [Size: 185B]

═══════════════════════════════════════════════════════════════════════════════
                           » SCAN COMPLETE «                                   
═══════════════════════════════════════════════════════════════════════════════
```

### Symbol Legend
- `[+]` - Success / Found (200)
- `[-]` - Error / Forbidden (403)
- `[*]` - Information / Status
- `[!]` - Warning / Unauthorized (401)
- `[>]` - Redirect (301/302)
- `[~]` - Processing / AI Activity
- `[#]` - Plugin Activity

---

## 🔌 Plugin System

### WordPress Scanner
Comprehensive WordPress security analysis:
- ✅ Automatic WordPress detection
- ✅ Version identification
- ✅ Plugin enumeration
- ✅ Theme discovery
- ✅ User enumeration testing
- ✅ XMLRPC detection
- ✅ Debug log exposure
- ✅ Config backup detection

### Sensitive Files Scanner
Discovers exposed sensitive files with severity ratings:
- 🔴 **Critical**: .env, passwords, secrets, credentials
- 🟠 **High**: Configs, database files, .git directories
- 🟡 **Medium**: Logs, backup files
- 🟢 **Low**: Version disclosure files

### API Scanner
Analyzes API endpoints for security:
- REST API detection
- GraphQL endpoint discovery
- SOAP service identification
- Authentication analysis
- Parameter extraction
- Documentation discovery

---

## 🛡️ Security Best Practices

1. **Authorization**: Only scan systems you have permission to test
2. **Rate Limiting**: Use `--rate-limit` to avoid overwhelming servers
3. **Stealth**: Use delays and low thread counts for sensitive targets
4. **Results Security**: Store scan results securely
5. **API Keys**: Keep API keys secure, use environment variables

---

## 📈 Performance Tips

1. **Start Conservative**: Begin with 5-10 threads
2. **Use AI Wisely**: AI models provide best results for unknown targets
3. **Combine Plugins**: Use multiple plugins for comprehensive assessment
4. **HTML Reports**: Generate professional reports for clients
5. **Verbose Mode**: Use `-v` for detailed progress tracking

---

## 🎓 AI Models

| Model | Speed | Quality | Cost | Best For |
|-------|-------|---------|------|----------|
| **local** | ⚡⚡⚡ | ⭐⭐⭐ | Free | Quick scans, known targets |
| **claude** | ⚡⚡ | ⭐⭐⭐⭐⭐ | Low | Unknown targets, best quality |
| **openai** | ⚡⚡ | ⭐⭐⭐⭐ | Medium | Alternative to Claude |

---

## 📁 Project Structure

```
aibuster/
├── aibuster.py         # Main entry point (v2.5.0)
├── ai.py              # AI path generation (improved prompts)
├── buster.py          # Path enumeration engine
├── output.py          # Professional output formatting
├── plugins.py         # Plugin system (3 plugins)
├── recon.py           # Reconnaissance module
├── requirements.txt   # Dependencies
├── README.md          # This file
└── SETUP_GUIDE.md    # Complete setup guide
```

---

## 🆕 What's New in v2.5.0

### Design Improvements
- ✅ WraithXSS-inspired professional banner
- ✅ Gobuster/Dirbuster-style output formatting
- ✅ Removed emoji clutter, using professional symbols
- ✅ Timestamped status messages
- ✅ Clean progress bars with ETA

### AI Enhancements
- ✅ Improved Claude prompts (40-80 paths vs 30-50)
- ✅ Better context awareness
- ✅ Enhanced prompt structure
- ✅ Technology-specific path generation
- ✅ Keyword-based path variations

### Plugin System
- ✅ Enhanced WordPress scanner (version, plugins, themes, vulnerabilities)
- ✅ New Sensitive Files scanner (with severity ratings)
- ✅ Improved API scanner (REST/GraphQL/SOAP support)
- ✅ Better error handling
- ✅ Detailed security findings

### Output & Reporting
- ✅ Professional HTML reports (dark theme)
- ✅ Reconnaissance summary display
- ✅ Performance metrics
- ✅ Top findings highlight
- ✅ Interesting paths detection

---

## 🐛 Troubleshooting

### API Key Issues
```bash
# Verify key is set
echo $ANTHROPIC_API_KEY

# Pass key directly
python3 aibuster.py -u https://example.com --ai-model claude --api-key YOUR_KEY
```

### Debug Mode
```bash
python3 aibuster.py -u https://example.com --debug
```

### Check Logs
```bash
tail -f aibuster.log
```

---

## 🔒 Legal Notice

**IMPORTANT**: AIBuster is designed for authorized security testing only.

Unauthorized scanning of systems you don't own or have permission to test is **illegal** and **unethical**. Always obtain proper authorization before conducting any security assessments.

You are solely responsible for how you use this tool.

---

## 📄 License

MIT License - see LICENSE file for details

---

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional plugins
- New AI models
- Enhanced detection patterns
- Performance optimizations
- Documentation improvements

---

## 📧 Contact & Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check SETUP_GUIDE.md for detailed documentation
- Enable `--debug` mode for troubleshooting

---

## 🙏 Acknowledgments

- Inspired by Gobuster, Dirbuster, and WraithXSS
- Built with Python, Anthropic Claude, and OpenAI
- Community feedback and contributions

---

**AIBuster v2.5.0** - Professional AI-Powered Directory Enumeration  
*Security Research Tool - Use Responsibly*