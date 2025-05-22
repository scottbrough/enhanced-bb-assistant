# Enhanced Personal Bug Bounty Assistant v2.0

## 🎯 AI-Powered Security Testing with Platform Integration

A comprehensive, AI-driven bug bounty automation framework that combines advanced reconnaissance, intelligent vulnerability testing, WAF evasion, and seamless platform integration for HackerOne and Bugcrowd.

### 🚀 Key Features

- **🤖 AI-Powered Analysis**: GPT-4 integration for intelligent target analysis and vulnerability assessment
- **🛡️ Scope Validation**: Built-in scope checking to prevent out-of-bounds testing
- **⚡ Aggressive Testing**: Advanced WAF evasion techniques and payload generation
- **🔗 Platform Integration**: Direct integration with HackerOne and Bugcrowd APIs
- **📝 JavaScript Analysis**: AI-powered analysis of client-side code for endpoints and secrets
- **⛓️ Chain Detection**: Automatic identification of vulnerability chains and attack paths
- **📋 Professional Reporting**: Platform-specific report generation and submission
- **🔧 Tool Integration**: Seamless integration with popular security tools

---

## 📥 Quick Installation

### Prerequisites
- Python 3.8+
- Go 1.19+ (recommended for security tools)
- Git
- 4GB+ RAM
- Internet connection

### One-Line Install
```bash
curl -sSL https://raw.githubusercontent.com/yourusername/enhanced-bb-assistant/main/setup.sh | bash
```

### Manual Installation
```bash
git clone https://github.com/yourusername/enhanced-bb-assistant.git
cd enhanced-bb-assistant
chmod +x setup.sh
./setup.sh
```

---

## ⚙️ Configuration

### 1. API Keys Setup
```bash
cp ~/.config/enhanced-bb-assistant/.env.template ~/.config/enhanced-bb-assistant/.env
nano ~/.config/enhanced-bb-assistant/.env
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
```bash
nano ~/.config/enhanced-bb-assistant/config.yaml
```

**Key Settings:**
```yaml
# Enable scope validation (CRITICAL for safety)
scope_validation:
  enabled: true
  strict_mode: true

# Aggressive testing (use with caution)
aggressive_testing:
  enabled: false  # Set to true for WAF evasion

# Platform integration
platforms:
  hackerone:
    enabled: true
    auto_submit: false  # Manual review recommended
```

---

## 🎮 Usage Examples

### Basic Usage
```bash
# Simple target scan
bb-assistant example.com

# With platform context
bb-assistant example.com --platform hackerone --program example-program

# Verbose output
bb-assistant example.com --verbose
```

### Advanced Usage
```bash
# Aggressive testing with WAF evasion
bb-assistant target.com --aggressive

# Custom configuration
bb-assistant target.com --config /path/to/custom-config.yaml

# Disable scope validation (dangerous - only for authorized testing)
bb-assistant target.com --no-scope-validation
```

### Professional Bug Bounty Workflow
```bash
# 1. Research and validate program
bb-assistant target.com --platform hackerone --program company-program

# 2. Aggressive testing (if authorized)
bb-assistant target.com --platform hackerone --program company-program --aggressive

# 3. Review results and submit
# Reports are automatically formatted for the specified platform
```

---

## 📊 Understanding Output

### Workspace Structure
```
hunt_target_com_20241222_143052/
├── session.json              # Hunt metadata
├── ai_analysis.json          # AI target analysis
├── recon_results.json        # Reconnaissance data
├── findings.json             # Vulnerability findings
├── vulnerability_chains.json # Attack chains
├── exploits.json            # Generated exploits
├── report_hackerone_target.md # Platform-specific report
├── technical_report_target.md # Technical details
├── executive_summary_target.md # Executive summary
├── report_target.html        # Visual report
├── poc_scripts/              # Proof-of-concept scripts
│   ├── exploit_1_xss.py
│   └── exploit_2_sqli.py
└── waf_contingency_guide.md  # WAF evasion reference
```

### Finding Analysis
Each finding includes:
- **Vulnerability Type**: XSS, SQLi, SSRF, etc.
- **Severity**: Critical, High, Medium, Low
- **Discovery Method**: How it was found
- **WAF Information**: If detected and bypassed
- **Evidence**: Proof of vulnerability
- **Remediation**: Fix recommendations

### Attack Chains
- **Chain Description**: Combined vulnerability impact
- **Attack Path**: Step-by-step exploitation
- **Business Impact**: Real-world consequences
- **CVSS Score**: Industry-standard severity rating

---

## 🛡️ Security & Safety

### Scope Validation
The system includes built-in scope validation to prevent testing unauthorized targets:

```yaml
scope_validation:
  enabled: true          # Always keep enabled
  strict_mode: true      # Reject anything not explicitly in scope
  domain_validation: true
  ip_validation: true
```

**How it works:**
1. Fetches program scope from platform APIs
2. Validates each discovered target against scope
3. Excludes out-of-scope domains/IPs
4. Logs validation decisions

### Aggressive Mode Safeguards
When aggressive testing is enabled:

- **WAF Detection**: Automatically detects and adapts to WAFs
- **Rate Limiting**: Intelligent request throttling
- **Evasion Logging**: Tracks all evasion attempts
- **Safety Limits**: Maximum payload counts and severities

### Blocked Domains
Default safety list prevents testing:
- localhost / 127.0.0.1
- internal / corp domains  
- RFC 1918 private IPs
- Cloud metadata endpoints

---

## 🚨 WAF Evasion & Contingencies

### WAF Detection
The system automatically detects:
- **Cloudflare**: Rate limiting, challenge pages
- **AWS WAF**: Block responses, headers
- **Akamai**: Reference numbers, error pages
- **Imperva**: Session cookies, redirects
- **F5 BIG-IP**: Server headers
- **Generic**: Blocked keywords, status codes

### Evasion Techniques
- **Encoding**: URL, Unicode, HTML entity
- **Case Variation**: Mixed case payloads
- **Comment Insertion**: SQL/HTML comments
- **Whitespace Manipulation**: Tabs, newlines
- **Parameter Pollution**: Multiple parameters
- **Header Manipulation**: IP spoofing, content-type

### Risk Levels
- **🟢 Green (Low)**: Standard testing, <1 req/3sec
- **🟡 Yellow (Medium)**: WAF detected, some blocks
- **🔴 Red (High)**: High block rate, IP flagged

### Abort Conditions
- IP blocked/rate limited
- Legal notices received
- Account suspension
- High error rates (>50%)

---

## 🔧 Tool Integration

### Core Tools
- **Subfinder**: Subdomain enumeration
- **HTTPx**: HTTP probing and analysis
- **Nuclei**: Vulnerability scanning
- **FFUF**: Web fuzzing
- **Amass**: Asset discovery

### Optional Tools
- **Burp Suite Pro**: Advanced scanning via API
- **Nmap**: Port scanning and service detection
- **Gobuster**: Directory brute forcing
- **Nikto**: Web server scanning

### Installation Verification
```bash
# Check tool availability
bb-assistant --check-tools

# Update tools
bb-assistant --update-tools

# Tool-specific help
subfinder -h
httpx -h
nuclei -h
```

---

## 📋 Platform Integration

### HackerOne Integration

**Setup:**
1. Generate API token in HackerOne settings
2. Add credentials to `.env` file
3. Enable in configuration

**Features:**
- Program scope retrieval
- Automatic report formatting
- Bounty range analysis
- Submission via API (optional)

**Example:**
```bash
bb-assistant target.com --platform hackerone --program uber
```

### Bugcrowd Integration

**Setup:**
1. Generate API token in Bugcrowd settings
2. Add token to `.env` file
3. Enable in configuration

**Features:**
- Target scope parsing
- VRT mapping
- Report formatting
- Program statistics

**Example:**
```bash
bb-assistant target.com --platform bugcrowd --program tesla
```

### Manual Program Research
If no platform is specified, the tool will:
1. Search for bug bounty programs covering the target
2. Recommend the best program based on scope and bounties
3. Provide intelligence on competition and potential

---

## 📊 Reporting & Output

### Report Types

1. **Platform-Specific Reports**
   - Formatted for HackerOne/Bugcrowd submission
   - Includes CVSS scores and CWE mappings
   - Professional language and structure

2. **Technical Reports**
   - Detailed vulnerability analysis
   - Methodology documentation
   - Raw findings and evidence

3. **Executive Summaries**
   - High-level business impact
   - Risk assessment
   - Remediation priorities

4. **Interactive HTML Reports**
   - Visual dashboards
   - Severity breakdowns
   - Evidence galleries

### Customization
```yaml
reporting:
  formats: [markdown, html, json]
  include_poc_scripts: true
  include_screenshots: false
  cvss_calculation: true
  
  platform_templates:
    hackerone:
      include_cvss: true
      include_cwe: true
    bugcrowd:
      include_vrt: true
```

---

## 🔍 JavaScript Analysis

### Capabilities
- **Endpoint Discovery**: Extract API endpoints from JS files
- **Secret Detection**: Find API keys, tokens, credentials
- **Vulnerability Patterns**: Identify client-side flaws
- **AI Analysis**: LLM-powered code review for complex patterns

### Secret Types Detected
- API keys and access tokens
- Database connection strings
- AWS/GCP/Azure credentials
- JWT tokens
- Hardcoded passwords
- Debug information

### Example Output
```json
{
  "secrets_found": [
    {
      "type": "api_key",
      "value": "ak_live_...",
      "source": "app.js",
      "confidence": "high"
    }
  ],
  "endpoints_discovered": [
    {
      "endpoint": "/api/v1/users",
      "method": "GET",
      "source": "dashboard.js"
    }
  ]
}
```

---

## ⛓️ Vulnerability Chaining

### Chain Detection
The AI analyzes findings to identify:
- **Privilege Escalation**: Low → High privilege paths
- **Data Exfiltration**: Information disclosure → Access
- **Account Takeover**: Multiple vulnerabilities → Full compromise
- **Business Logic**: Application flow exploitation

### Example Chain
```
1. IDOR in /api/users/{id} → Access other user profiles
2. XSS in profile field → Execute JavaScript
3. CSRF token extraction → Perform actions as victim
4. Password reset → Account takeover
```

### Impact Assessment
- **CVSS Base Score**: Technical severity
- **Business Impact**: Real-world consequences  
- **Exploit Complexity**: Difficulty to execute
- **Bounty Estimation**: Expected reward range

---

## 🐛 Troubleshooting

### Common Issues

**1. OpenAI API Errors**
```bash
# Check API key
echo $OPENAI_API_KEY

# Test API access
curl -H "Authorization: Bearer $OPENAI_API_KEY" \
     https://api.openai.com/v1/models
```

**2. Tool Not Found**
```bash
# Check PATH
echo $PATH

# Reinstall tools
bb-assistant --update-tools

# Manual install
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

**3. Permission Errors**
```bash
# Fix permissions
chmod +x ~/.local/bin/bb-assistant

# Check directory permissions
ls -la ~/.config/enhanced-bb-assistant/
```

**4. WAF Blocking**
```bash
# Reduce aggression
bb-assistant target.com --config conservative-config.yaml

# Check logs
tail -f /tmp/bb_assistant_setup.log
```

**5. Scope Validation Issues**
```bash
# Verify program handle
bb-assistant target.com --platform hackerone --program correct-handle

# Check API credentials
curl -u "$HACKERONE_USERNAME:$HACKERONE_API_TOKEN" \
     https://api.hackerone.com/v1/me
```

### Debug Mode
```bash
# Enable debug logging
bb-assistant target.com --verbose --debug

# Save debug info
bb-assistant target.com --save-debug
```

### Performance Issues
```yaml
# Reduce resource usage
performance:
  max_memory_usage: "1GB"
  max_cpu_usage: 50
  
recon:
  max_subdomains: 20
  max_endpoints_per_target: 50
  threads: 3
```

---

## 🔄 Updates & Maintenance

### Updating the System
```bash
# Update Python packages
cd ~/enhanced-bb-assistant
source venv/bin/activate
pip install --upgrade -r requirements.txt

# Update Go tools
bb-assistant --update-tools

# Update wordlists
cd ~/.wordlists/SecLists
git pull
```

### Backup & Recovery
```bash
# Backup configuration
tar -czf bb-assistant-backup.tar.gz ~/.config/enhanced-bb-assistant/

# Backup hunt results
tar -czf hunt-results.tar.gz ~/enhanced-bb-assistant/hunts/

# Restore configuration
tar -xzf bb-assistant-backup.tar.gz -C ~/
```

---

## ⚖️ Legal & Ethical Considerations

### ⚠️ CRITICAL DISCLAIMERS

**1. Authorization Required**
- Only test systems you own or have explicit written permission to test
- Verify scope boundaries before testing
- Respect rate limits and testing windows

**2. Responsible Disclosure**
- Follow coordinated disclosure timelines
- Don't publicly disclose until patched
- Provide clear reproduction steps

**3. Platform Compliance**
- Read and follow program terms of service
- Respect safe harbor provisions
- Don't test out-of-scope assets

**4. Legal Compliance**
- Follow local laws and regulations
- Don't access sensitive data
- Stop testing if asked by asset owner

### Best Practices
1. **Start Conservative**: Begin with minimal testing
2. **Validate Scope**: Always double-check target authorization
3. **Document Everything**: Keep detailed records
4. **Communicate Clearly**: Provide helpful, actionable reports
5. **Be Professional**: Maintain positive relationships

---

## 🤝 Contributing

### Development Setup
```bash
git clone https://github.com/yourusername/enhanced-bb-assistant.git
cd enhanced-bb-assistant
python -m venv dev-env
source dev-env/bin/activate
pip install -r requirements-dev.txt
```

### Testing
```bash
# Run unit tests
pytest tests/

# Run integration tests
pytest tests/integration/

# Run linting
black .
flake8 .
```

### Submitting Issues
1. Check existing issues first
2. Provide reproduction steps
3. Include system information
4. Attach relevant logs

### Feature Requests
1. Describe the use case
2. Explain the expected behavior
3. Consider security implications
4. Provide implementation ideas

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Third-Party Licenses
- OpenAI API: Subject to OpenAI terms of service
- Security tools: Various open-source licenses
- Python packages: See individual package licenses

---

## 🙏 Acknowledgments

- **OpenAI**: For GPT-4 API enabling intelligent analysis
- **ProjectDiscovery**: For excellent open-source security tools
- **Bug Bounty Community**: For sharing knowledge and techniques
- **Platform Providers**: HackerOne and Bugcrowd for APIs
- **Security Researchers**: For vulnerability disclosure best practices

---

## 📞 Support

### Community
- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: General questions and community support
- **Security Issues**: Responsible disclosure via private channel

### Documentation
- **Wiki**: Detailed tutorials and guides
- **Examples**: Real-world usage scenarios
- **FAQ**: Common questions and solutions

### Professional Support
For enterprise deployments or custom integrations, contact the maintainers for professional support options.

---

**Happy Bug Hunting! 🎯**

*Remember: With great power comes great responsibility. Use this tool ethically and legally.*
