# Enhanced Personal Bug Bounty Assistant v2.0

## 🎯 AI-Powered Security Testing with Platform Integration

A comprehensive, AI-driven bug bounty automation framework that combines advanced reconnaissance, intelligent vulnerability testing, WAF evasion, and seamless platform integration for HackerOne and Bugcrowd.

---

## 📁 Project Structure

```
.
├── README.md                # Main documentation
├── LICENSE                  # MIT License
├── setup.sh                 # Installation script
├── requirements.txt         # Python dependencies
├── config.yaml              # Default configuration
├── .env.template            # Environment variables template
├── .gitignore               # Git ignore file
│
├── src/                     # Source code
│   ├── enhanced_personal_assistant.py   # Main entry point
│   ├── platform_integration.py          # Platform APIs
│   ├── aggressive_testing_waf_evasion.py # WAF evasion
│   ├── enhanced_vulnerability_testing.py # Core vulnerability testing
│   ├── js_analysis_module.py            # JavaScript analysis
│   └── utils/                           # Utility modules
│
├── configs/                 # Config templates (aggressive, conservative, etc.)
├── templates/               # Report templates (HackerOne, Bugcrowd, generic)
├── scripts/                 # Utility scripts (update, backup, etc.)
├── tests/                   # Test suite
├── examples/                # Usage examples
├── docs/                    # Guides, API reference, troubleshooting
├── env/                     # Python virtual environment (excluded from git)
└── file-structure.txt       # Detailed file structure
```

---

## 🚀 Key Features

- **AI-Powered Analysis:** GPT-4 integration for intelligent target analysis and vulnerability assessment
- **Scope Validation:** Built-in scope checking to prevent out-of-bounds testing
- **Aggressive Testing:** Advanced WAF evasion techniques and payload generation
- **Platform Integration:** Direct integration with HackerOne and Bugcrowd APIs
- **JavaScript Analysis:** AI-powered analysis of client-side code for endpoints and secrets
- **Chain Detection:** Automatic identification of vulnerability chains and attack paths
- **Professional Reporting:** Platform-specific report generation and submission
- **Tool Integration:** Seamless integration with popular security tools

---

## 📥 Installation & Setup

### Prerequisites
- Python 3.8+
- Go 1.19+ (for security tools)
- Git
- 4GB+ RAM
- Internet connection

### One-Line Install
```zsh
curl -sSL https://raw.githubusercontent.com/yourusername/enhanced-bb-assistant/main/setup.sh | zsh
```

### Manual Installation
```zsh
git clone https://github.com/yourusername/enhanced-bb-assistant.git
cd enhanced-bb-assistant
chmod +x setup.sh
./setup.sh
```

---

## ⚙️ Configuration

### 1. API Keys Setup
```zsh
cp .env.template .env
nano .env
```

**Required:**
```env
OPENAI_API_KEY=sk-your-openai-api-key-here
```

**Optional (for platform integration):**
```env
# HackerOne
HACKERONE_USERNAME=your_username
HACKERONE_API_TOKEN=your_api_token

# Bugcrowd  
BUGCROWD_API_TOKEN=your_api_token
```

### 2. Configuration Customization
```zsh
nano config.yaml
```
Or use a template from `configs/` (e.g., `aggressive-config.yaml`, `conservative-config.yaml`).

---

## 🎮 Usage Workflow

### Basic Usage
```zsh
# Simple target scan
bb-assistant example.com

# With platform context
bb-assistant example.com --platform hackerone --program example-program

# Verbose output
bb-assistant example.com --verbose
```

### Advanced Usage
```zsh
# Aggressive testing with WAF evasion
bb-assistant target.com --aggressive

# Custom configuration
bb-assistant target.com --config configs/aggressive-config.yaml

# Disable scope validation (dangerous)
bb-assistant target.com --no-scope-validation
```

### Professional Bug Bounty Workflow
```zsh
# 1. Research and validate program
bb-assistant target.com --platform hackerone --program company-program

# 2. Aggressive testing (if authorized)
bb-assistant target.com --platform hackerone --program company-program --aggressive

# 3. Review results and submit
# Reports are automatically formatted for the specified platform
```

---

## 📊 Output & Reports

### Workspace Structure
```
hunt_target_com_YYYYMMDD_HHMMSS/
├── session.json              # Hunt metadata
├── ai_analysis.json          # AI target analysis
├── recon_results.json        # Reconnaissance data
├── findings.json             # Vulnerability findings
├── vulnerability_chains.json # Attack chains
├── exploits.json             # Generated exploits
├── report_hackerone_target.md # Platform-specific report
├── technical_report_target.md # Technical details
├── executive_summary_target.md # Executive summary
├── report_target.html        # Visual report
├── poc_scripts/              # Proof-of-concept scripts
└── waf_contingency_guide.md  # WAF evasion reference
```

### Report Types
- **Platform-Specific Reports:** For HackerOne/Bugcrowd, with CVSS/CWE/VRT
- **Technical Reports:** Detailed analysis and methodology
- **Executive Summaries:** High-level business impact
- **Interactive HTML Reports:** Visual dashboards and evidence

---

## 🔧 Tool & Platform Integration

- **Core Tools:** Subfinder, HTTPx, Nuclei, FFUF, Amass
- **Optional:** Burp Suite Pro, Nmap, Gobuster, Nikto
- **Platform APIs:** HackerOne, Bugcrowd (API tokens in `.env`)
- **Tool Management:**
  ```zsh
  bb-assistant --check-tools
  bb-assistant --update-tools
  ```

---

## 🛡️ Security & Safety
- **Scope validation** (default: strict)
- **Aggressive mode**: WAF detection, evasion, rate limiting
- **Blocked domains**: localhost, internal, cloud metadata, RFC1918
- **Abort conditions**: IP block, legal notice, high error rate

---

## 🔍 JavaScript Analysis
- **Endpoint & secret discovery**
- **AI-powered code review**
- **Client-side vulnerability patterns**

---

## ⛓️ Vulnerability Chaining
- **Chain detection**: Privilege escalation, data exfiltration, account takeover
- **Impact assessment**: CVSS, business impact, exploit complexity

---

## 🐛 Troubleshooting & Maintenance
- See `docs/TROUBLESHOOTING.md` for common issues
- Update with `bb-assistant --update-tools`
- Backup configs/results with `scripts/backup_results.sh`

---

## 🤝 Contributing
- See `docs/CONTRIBUTING.md`
- Run tests: `pytest tests/`
- Lint: `black . && flake8 .`

---

## 📄 License
MIT License. See `LICENSE`.

---

## 🙏 Acknowledgments
- OpenAI, ProjectDiscovery, Bug Bounty Community, Platform Providers

---

**Happy Bug Hunting! 🎯**

*With great power comes great responsibility. Use this tool ethically and legally.*
