````md
# AIBuster 2.0 🚀

**AI-Powered Intelligent Directory & File Discovery Tool**

AIBuster is a next-generation directory and file discovery tool that uses **AI models (Claude, OpenAI, or local logic)** to generate context-aware, technology-specific paths instead of relying only on static wordlists.

It is designed for **penetration testers, bug bounty hunters, and security researchers** who want smarter reconnaissance with fewer requests.

---

## Features

### AI-Driven Path Generation
- Uses LLMs (Claude / OpenAI) to generate intelligent paths
- Adapts to detected technologies and extracted keywords
- Automatically falls back to local logic if AI is unavailable

### Reconnaissance-First Approach
- Identifies frameworks, CMSs, and CDNs
- Extracts keywords from responses
- Prioritizes high-probability directories and files

### Performance & Control
- Multi-threaded scanning (1–100 threads)
- Rate limiting, delays, and retries
- Stealth scanning mode
- Recursive depth scanning (1–3 levels)

### Plugin System
- WordPress scanning
- Sensitive file detection
- API endpoint discovery
- Extensible plugin architecture

### Output & Reporting
- Real-time console progress bar
- JSON, CSV, HTML, XML, Markdown
- Interactive HTML reports with statistics

---

## Installation

```bash
git clone https://github.com/yourusername/aibuster.git
cd aibuster

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

# Optional AI providers
pip install anthropic openai

chmod +x aibuster.py
````

### Optional System-Wide Install

```bash
sudo ln -s $(pwd)/aibuster.py /usr/bin/aibuster
```

---

## API Key Setup

AIBuster uses AI models to generate paths. You may use **Claude (Anthropic)** or **OpenAI**.

```bash
# Claude
export ANTHROPIC_API_KEY="your-api-key"

# OpenAI
export OPENAI_API_KEY="your-api-key"
```

Make it permanent:

```bash
echo 'export ANTHROPIC_API_KEY="your-api-key"' >> ~/.bashrc
source ~/.bashrc
```

Or pass the key directly:

```bash
./aibuster.py -u https://target.com --ai-model claude --api-key YOUR_KEY
```

---

## Supported AI Models

| Model    | Description                                 |
| -------- | ------------------------------------------- |
| `claude` | Claude 3 (Haiku / Sonnet) – fast & low cost |
| `openai` | GPT-based models                            |
| `local`  | No API required (fallback mode)             |

---

## Basic Usage

```bash
./aibuster.py -u https://target.com
```

This will:

1. Perform reconnaissance
2. Generate AI-powered paths
3. Test paths using 10 threads
4. Display results in real time

---

## Scan Examples

### 1. Quick Reconnaissance Scan

```bash
./aibuster.py -u https://target.com --ai-model claude -v
```

### 2. Deep Scan with HTML Report

```bash
./aibuster.py -u https://target.com --ai-model claude -t 20 --depth 2 -v -o report.html --format html
```

### 3. WordPress Site Scan

```bash
./aibuster.py -u https://wordpress-site.com --ai-model claude --plugins wordpress,sensitive-files -v
```

### 4. API Endpoint Discovery

```bash
./aibuster.py -u https://api.example.com --ai-model claude --extensions json,xml,graphql -v
```

### 5. Stealth Scan (Low Noise)

```bash
./aibuster.py -u https://target.com --ai-model local -t 5 --delay 1 --rate-limit 10 -v
```

### 6. Custom Wordlist Scan

```bash
./aibuster.py -u https://target.com --wordlist /path/to/wordlist.txt --extensions php,html -t 15
```

---

## Command-Line Options

### Required

| Option      | Description |
| ----------- | ----------- |
| `-u, --url` | Target URL  |

### Performance

| Option          | Default   |
| --------------- | --------- |
| `-t, --threads` | 10        |
| `--timeout`     | 5 seconds |
| `--delay`       | 0         |
| `--retries`     | 2         |
| `--rate-limit`  | Unlimited |

### AI & Path Generation

| Option         | Default              |
| -------------- | -------------------- |
| `--ai-model`   | claude               |
| `--no-ai`      | Disabled             |
| `--wordlist`   | None                 |
| `--extensions` | php,html,js,txt,json |
| `--depth`      | 1                    |

### Output

| Option          | Default  |
| --------------- | -------- |
| `-o, --output`  | None     |
| `--format`      | json     |
| `-v, --verbose` | Disabled |
| `--quiet`       | Disabled |
| `--debug`       | Disabled |

### Advanced

| Option         | Description                      |
| -------------- | -------------------------------- |
| `--plugins`    | Enable plugins (comma-separated) |
| `--proxy`      | HTTP proxy                       |
| `--cookies`    | Custom cookies                   |
| `--headers`    | Custom headers (JSON)            |
| `--user-agent` | Custom User-Agent                |

---

## Understanding Results

### Symbols

| Symbol | Meaning            |
| ------ | ------------------ |
| ✓      | Accessible (200)   |
| →      | Redirect (301/302) |
| ✗      | Forbidden (403)    |
| 🔒     | Unauthorized (401) |

**Note:** Redirects and forbidden responses often indicate real, protected resources.

---

## Project Structure

```
aibuster/
├── aibuster.py
├── recon.py
├── ai.py
├── buster.py
├── output.py
├── plugins.py
├── requirements.txt
└── README.md
```

---

## Performance Tips

* Start with low threads on unknown targets
* Use AI models for higher-quality results
* Apply rate limiting on production sites
* Use HTML reports for client deliverables
* Run plugins after initial scans

---

## Troubleshooting

### API Key Issues

```bash
echo $ANTHROPIC_API_KEY
```

### Debug Mode

```bash
./aibuster.py -u https://target.com --debug
```

---

## Legal & Ethical Notice

**Use AIBuster only on systems you are authorized to test.**

Unauthorized scanning is illegal and unethical.
You are responsible for how you use this tool.

---

## Why AIBuster?

**Traditional Dirbusters**

* Static wordlists
* High noise
* Poor context awareness

**AIBuster**

* AI-generated paths
* Context-aware reconnaissance
* Fewer, smarter requests
* Cleaner results

---

## License

MIT License

---

*AI-driven reconnaissance for the modern web.*

```
```
