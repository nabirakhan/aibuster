# AIBuster 2.0 🚀

**AI-Powered Intelligent Directory & File Discovery Tool**

## ✨ Enhanced Features

### 🤖 **Advanced AI Integration**
- Multiple AI models (Claude, GPT-4, Local)
- Context-aware path generation
- Technology-specific predictions
- Adaptive learning from scan results

### 📊 **Smart Output Formats**
- JSON, CSV, HTML, XML, Markdown
- Interactive HTML reports
- Real-time progress tracking
- Comprehensive statistics

### ⚡ **Performance & Reliability**
- Intelligent rate limiting
- Connection pooling
- Automatic retries with backoff
- Concurrent scanning with thread management

### 🔌 **Plugin System**
- WordPress vulnerability scanner
- API endpoint discovery
- Sensitive file detector
- Extensible architecture

### 🎯 **Advanced Scanning Modes**
- Stealth mode (random delays, User-Agent rotation)
- Smart mode (adaptive path prioritization)
- Recursive scanning (depth control)
- Custom extensions testing

## 🚀 Installation

```bash
# Clone repository
git clone https://github.com/yourusername/aibuster.git
cd aibuster

# Create python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install with enhanced features
pip install -r requirements.txt

# Optional: Install AI dependencies
pip install openai anthropic

# Make executable
chmod +x aibuster.py

# Install system-wide
sudo ln -s $(pwd)/aibuster.py /usr/bin/aibuster

## API Key Setup

AIBuster uses an LLM to intelligently generate directory paths.

1. Obtain an API key from your provider
2. Export it as an environment variable:

```bash
# For Claude (Anthropic)
export ANTHROPIC_API_KEY="your-api-key-here"

# For OpenAI
export OPENAI_API_KEY="your-api-key-here"

# Make it permanent (add to ~/.bashrc or ~/.zshrc)
echo 'export ANTHROPIC_API_KEY="your-api-key-here"' >> ~/.bashrc
source ~/.bashrc

# OR Pass API key via command line
./aibuster.py -u https://tesla.com --ai-model claude --api-key "your-api-key-here"
