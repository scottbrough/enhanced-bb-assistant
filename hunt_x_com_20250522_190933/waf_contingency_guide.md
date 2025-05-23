
# WAF Detection and Evasion Contingencies

## What WAFs Detect
1. **Signature-based detection**: Known malicious patterns
2. **Behavioral analysis**: Abnormal request patterns
3. **Rate limiting**: Too many requests too quickly
4. **IP reputation**: Known malicious IPs
5. **User-Agent analysis**: Suspicious or missing user agents

## Detection Contingencies

### If WAF is Detected:
1. **Immediate Actions**:
   - Switch to evasion mode automatically
   - Reduce request rate by 50%
   - Rotate user agents and sessions
   - Use proxy rotation if available

2. **Evasion Strategy Selection**:
   - **Cloudflare**: Focus on encoding and case variations
   - **AWS WAF**: Use parameter pollution and header manipulation
   - **Akamai**: Employ whitespace and comment insertion
   - **Imperva**: Try protocol confusion and IP obfuscation

3. **Escalation Path**:
   - Start with subtle evasions (encoding)
   - Progress to structural changes (parameter pollution)
   - Finally attempt aggressive techniques (header manipulation)

### Risk Levels:

#### LOW RISK (Green):
- Standard payloads on unprotected endpoints
- Basic encoding evasion
- Request rate < 1 per 3 seconds

#### MEDIUM RISK (Yellow):
- WAF detected but evasion working
- Some requests blocked (< 20%)
- Request rate 1-2 per second

#### HIGH RISK (Red):
- High block rate (> 50%)
- IP getting flagged/blocked
- Aggressive payloads triggering alerts

### Abort Conditions:
1. **IP blocked** - Stop immediately, switch IP/proxy
2. **Rate limited** - Increase delays significantly
3. **Legal notices** - Abort testing entirely
4. **Account locked** (if testing authenticated) - Stop session

## Recommended Evasion Order:
1. URL encoding variations
2. Case manipulation
3. Whitespace insertion
4. Comment injection
5. Parameter pollution
6. Header manipulation
7. Protocol confusion (SSRF only)
8. Advanced encoding (Unicode, hex)

## Monitoring Indicators:
- Response status codes (403, 406, 429)
- Response time increases
- Challenge pages (CAPTCHA)
- Error messages containing WAF identifiers
- Session termination
