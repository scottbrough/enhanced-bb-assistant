#!/usr/bin/env python3
"""
AI-Powered JavaScript Analysis Module
Extracts endpoints, secrets, and vulnerabilities from JavaScript files
"""

import requests
import re
import json
import logging
from typing import Dict, List, Optional, Tuple
import urllib.parse
from pathlib import Path
import base64

logger = logging.getLogger(__name__)

class JavaScriptAnalyzer:
    """AI-powered JavaScript analysis for bug bounty hunting"""
    
    def __init__(self, openai_client):
        self.client = openai_client
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Common JS file patterns
        self.js_file_patterns = [
            r'\.js$',
            r'\.min\.js$',
            r'\.bundle\.js$',
            r'\.chunk\.js$'
        ]
        
        # Secret patterns
        self.secret_patterns = {
            'api_key': [
                r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
                r'apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
                r'api[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']'
            ],
            'access_token': [
                r'access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
                r'bearer[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
                r'auth[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']'
            ],
            'aws_key': [
                r'AKIA[0-9A-Z]{16}',
                r'aws[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([A-Z0-9]{20,})["\']',
                r'aws[_-]?secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40,})["\']'
            ],
            'google_api': [
                r'AIza[0-9A-Za-z\\-_]{35}',
                r'google[_-]?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{35,})["\']'
            ],
            'jwt_token': [
                r'eyJ[A-Za-z0-9_/+-]*\.eyJ[A-Za-z0-9_/+-]*\.[A-Za-z0-9_/+-]*',
                r'jwt[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9._-]{100,})["\']'
            ],
            'database_url': [
                r'mongodb://[^\s"\']+',
                r'mysql://[^\s"\']+',
                r'postgres://[^\s"\']+',
                r'redis://[^\s"\']+',
                r'db[_-]?url["\']?\s*[:=]\s*["\']([^"\']{20,})["\']'
            ],
            'private_key': [
                r'-----BEGIN PRIVATE KEY-----',
                r'-----BEGIN RSA PRIVATE KEY-----',
                r'private[_-]?key["\']?\s*[:=]\s*["\']([^"\']{100,})["\']'
            ],
            'webhook_url': [
                r'https://hooks\.slack\.com/services/[A-Z0-9/]+',
                r'https://discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+',
                r'webhook[_-]?url["\']?\s*[:=]\s*["\']([^"\']{50,})["\']'
            ]
        }
        
        # Endpoint extraction patterns
        self.endpoint_patterns = [
            r'["\']([/][a-zA-Z0-9._/-]*)["\']',  # Absolute paths
            r'["\']([a-zA-Z0-9._/-]+\.php)["\']',  # PHP files
            r'["\']([a-zA-Z0-9._/-]+\.asp[x]?)["\']',  # ASP files
            r'["\']([a-zA-Z0-9._/-]+\.jsp)["\']',  # JSP files
            r'["\']([a-zA-Z0-9._/-]+\.cgi)["\']',  # CGI files
            r'\/api\/[a-zA-Z0-9._/-]*',  # API endpoints
            r'\/v[0-9]+\/[a-zA-Z0-9._/-]*',  # Versioned APIs
            r'\/graphql[a-zA-Z0-9._/-]*',  # GraphQL endpoints
        ]
        
        # Vulnerability patterns
        self.vuln_patterns = {
            'xss_sinks': [
                r'document\.write\s*\(',
                r'innerHTML\s*=',
                r'outerHTML\s*=',
                r'insertAdjacentHTML\s*\(',
                r'eval\s*\(',
                r'setTimeout\s*\(["\'][^"\']*\+',
                r'setInterval\s*\(["\'][^"\']*\+'
            ],
            'dangerous_functions': [
                r'eval\s*\(',
                r'Function\s*\(',
                r'setTimeout\s*\(["\'][^"\']*[+]',
                r'setInterval\s*\(["\'][^"\']*[+]',
                r'execScript\s*\(',
                r'document\.write\s*\('
            ],
            'prototype_pollution': [
                r'__proto__',
                r'constructor\s*\.\s*prototype',
                r'Object\.prototype',
                r'merge\s*\(',
                r'extend\s*\(',
                r'assign\s*\('
            ],
            'open_redirect': [
                r'location\s*=\s*[^;]*\+',
                r'location\.href\s*=\s*[^;]*\+',
                r'window\.open\s*\([^)]*\+',
                r'document\.location\s*=\s*[^;]*\+'
            ]
        }
    
    def discover_and_analyze_js(self, target: str, endpoints: List[Dict]) -> Dict:
        """Discover and analyze JavaScript files from target"""
        logger.info(f"🔍 Discovering and analyzing JavaScript files for {target}")
        
        analysis_results = {
            'js_files_found': 0,
            'endpoints_discovered': [],
            'secrets_found': [],
            'vulnerabilities_detected': [],
            'ai_analysis': [],
            'files_analyzed': []
        }
        
        # Discover JS files from endpoints
        js_files = self._discover_js_files(target, endpoints)
        analysis_results['js_files_found'] = len(js_files)
        
        # Analyze each JS file
        for js_file in js_files:
            file_analysis = self._analyze_js_file(js_file)
            analysis_results['files_analyzed'].append(file_analysis)
            
            # Aggregate results
            analysis_results['endpoints_discovered'].extend(file_analysis.get('endpoints', []))
            analysis_results['secrets_found'].extend(file_analysis.get('secrets', []))
            analysis_results['vulnerabilities_detected'].extend(file_analysis.get('vulnerabilities', []))
            
            # AI analysis for complex files
            if file_analysis.get('size', 0) > 1000:  # Only AI analyze larger files
                ai_analysis = self._ai_analyze_js_content(file_analysis.get('content', ''), js_file)
                if ai_analysis:
                    analysis_results['ai_analysis'].append(ai_analysis)
        
        logger.info(f"✅ JS analysis complete: {len(js_files)} files, {len(analysis_results['endpoints_discovered'])} endpoints, {len(analysis_results['secrets_found'])} secrets")
        return analysis_results
    
    def _discover_js_files(self, target: str, endpoints: List[Dict]) -> List[str]:
        """Discover JavaScript files from endpoints and common paths"""
        js_files = set()
        
        # Extract JS files from discovered endpoints
        for endpoint in endpoints:
            url = endpoint.get('url', '')
            if any(re.search(pattern, url) for pattern in self.js_file_patterns):
                js_files.add(url)
        
        # Common JS file paths
        common_js_paths = [
            '/js/app.js',
            '/js/main.js',
            '/js/script.js',
            '/js/bundle.js',
            '/js/chunk.js',
            '/assets/js/app.js',
            '/static/js/main.js',
            '/public/js/script.js',
            '/dist/js/app.js',
            '/build/static/js/main.js'
        ]
        
        # Test common paths
        for path in common_js_paths:
            test_url = f"https://{target}{path}"
            try:
                response = self.session.head(test_url, timeout=5, verify=False)
                if response.status_code == 200:
                    content_type = response.headers.get('content-type', '').lower()
                    if 'javascript' in content_type or 'application/js' in content_type:
                        js_files.add(test_url)
            except:
                pass
        
        # Look for JS files in HTML responses
        for endpoint in endpoints[:10]:  # Limit to avoid too many requests
            try:
                response = self.session.get(endpoint.get('url', ''), timeout=10, verify=False)
                if response.status_code == 200:
                    js_refs = self._extract_js_references(response.text, endpoint.get('url', ''))
                    js_files.update(js_refs)
            except:
                pass
        
        return list(js_files)[:15]  # Limit to 15 files to avoid overload
    
    def _extract_js_references(self, html_content: str, base_url: str) -> List[str]:
        """Extract JavaScript file references from HTML"""
        js_files = []
        
        # Find script tags
        script_patterns = [
            r'<script[^>]+src\s*=\s*["\']([^"\']+\.js[^"\']*)["\']',
            r'<script[^>]+src\s*=\s*([^\s>]+\.js[^\s>]*)'
        ]
        
        for pattern in script_patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                js_url = self._resolve_url(match, base_url)
                if js_url:
                    js_files.append(js_url)
        
        return js_files
    
    def _resolve_url(self, url: str, base_url: str) -> Optional[str]:
        """Resolve relative URLs to absolute URLs"""
        try:
            if url.startswith(('http://', 'https://')):
                return url
            
            parsed_base = urllib.parse.urlparse(base_url)
            base_domain = f"{parsed_base.scheme}://{parsed_base.netloc}"
            
            if url.startswith('/'):
                return f"{base_domain}{url}"
            else:
                # Relative path
                base_path = '/'.join(parsed_base.path.split('/')[:-1])
                return f"{base_domain}{base_path}/{url}"
        except:
            return None
    
    def _analyze_js_file(self, js_url: str) -> Dict:
        """Analyze a single JavaScript file"""
        logger.debug(f"Analyzing JS file: {js_url}")
        
        analysis = {
            'url': js_url,
            'size': 0,
            'content': '',
            'endpoints': [],
            'secrets': [],
            'vulnerabilities': [],
            'functions_found': [],
            'comments': []
        }
        
        try:
            response = self.session.get(js_url, timeout=15, verify=False)
            if response.status_code == 200:
                content = response.text
                analysis['size'] = len(content)
                analysis['content'] = content[:10000]  # Store first 10KB for AI analysis
                
                # Extract endpoints
                analysis['endpoints'] = self._extract_endpoints(content, js_url)
                
                # Find secrets
                analysis['secrets'] = self._find_secrets(content, js_url)
                
                # Detect vulnerabilities
                analysis['vulnerabilities'] = self._detect_vulnerabilities(content, js_url)
                
                # Extract function names
                analysis['functions_found'] = self._extract_functions(content)
                
                # Extract comments
                analysis['comments'] = self._extract_comments(content)
                
        except Exception as e:
            logger.debug(f"Failed to analyze {js_url}: {e}")
            analysis['error'] = str(e)
        
        return analysis
    
    def _extract_endpoints(self, content: str, source_url: str) -> List[Dict]:
        """Extract API endpoints and paths from JavaScript"""
        endpoints = []
        found_paths = set()
        
        for pattern in self.endpoint_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match) > 3 and match not in found_paths:
                    found_paths.add(match)
                    endpoints.append({
                        'endpoint': match,
                        'source': source_url,
                        'type': self._classify_endpoint(match)
                    })
        
        # Look for API base URLs
        api_patterns = [
            r'["\']https?://[^"\']+api[^"\']*["\']',
            r'["\']https?://api\.[^"\']+["\']',
            r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
            r'apiUrl\s*[:=]\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match not in found_paths:
                    found_paths.add(match)
                    endpoints.append({
                        'endpoint': match,
                        'source': source_url,
                        'type': 'api_base_url'
                    })
        
        return endpoints[:20]  # Limit results
    
    def _classify_endpoint(self, endpoint: str) -> str:
        """Classify the type of endpoint"""
        endpoint_lower = endpoint.lower()
        
        if '/api/' in endpoint_lower:
            return 'api_endpoint'
        elif '/admin' in endpoint_lower:
            return 'admin_endpoint'
        elif '/auth' in endpoint_lower or '/login' in endpoint_lower:
            return 'auth_endpoint'
        elif '/upload' in endpoint_lower:
            return 'upload_endpoint'
        elif endpoint_lower.endswith(('.php', '.asp', '.aspx', '.jsp')):
            return 'server_script'
        elif '/graphql' in endpoint_lower:
            return 'graphql_endpoint'
        else:
            return 'generic_endpoint'
    
    def _find_secrets(self, content: str, source_url: str) -> List[Dict]:
        """Find secrets and sensitive information in JavaScript"""
        secrets = []
        
        for secret_type, patterns in self.secret_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    # Skip obvious false positives
                    if self._is_likely_secret(match):
                        secrets.append({
                            'type': secret_type,
                            'value': match[:50] + '...' if len(match) > 50 else match,
                            'source': source_url,
                            'confidence': self._assess_secret_confidence(match, secret_type)
                        })
        
        return secrets
    
    def _is_likely_secret(self, value: str) -> bool:
        """Check if a value is likely to be a real secret"""
        # Skip obvious test/dummy values
        dummy_indicators = [
            'test', 'example', 'dummy', 'fake', 'placeholder',
            'your_key_here', 'insert_key', 'replace_me', 'xxxx',
            '1234567890', 'abcdefgh'
        ]
        
        value_lower = value.lower()
        return not any(indicator in value_lower for indicator in dummy_indicators)
    
    def _assess_secret_confidence(self, value: str, secret_type: str) -> str:
        """Assess confidence level of secret detection"""
        if secret_type == 'jwt_token' and value.count('.') == 2:
            return 'high'
        elif secret_type == 'aws_key' and value.startswith('AKIA'):
            return 'high'
        elif secret_type == 'google_api' and value.startswith('AIza'):
            return 'high'
        elif len(value) > 30 and not value.isalnum():
            return 'medium'
        else:
            return 'low'
    
    def _detect_vulnerabilities(self, content: str, source_url: str) -> List[Dict]:
        """Detect potential vulnerabilities in JavaScript"""
        vulnerabilities = []
        
        for vuln_type, patterns in self.vuln_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    vulnerabilities.append({
                        'type': vuln_type,
                        'pattern': pattern,
                        'matches': len(matches),
                        'source': source_url,
                        'severity': self._assess_vuln_severity(vuln_type),
                        'evidence': matches[:3]  # First 3 matches as evidence
                    })
        
        return vulnerabilities
    
    def _assess_vuln_severity(self, vuln_type: str) -> str:
        """Assess vulnerability severity"""
        severity_map = {
            'xss_sinks': 'medium',
            'dangerous_functions': 'high',
            'prototype_pollution': 'medium',
            'open_redirect': 'low'
        }
        return severity_map.get(vuln_type, 'low')
    
    def _extract_functions(self, content: str) -> List[str]:
        """Extract function names from JavaScript"""
        function_patterns = [
            r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(',
            r'([a-zA-Z_$][a-zA-Z0-9_$]*)\s*:\s*function\s*\(',
            r'const\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\(',
            r'let\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\(',
            r'var\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*function'
        ]
        
        functions = set()
        for pattern in function_patterns:
            matches = re.findall(pattern, content)
            functions.update(matches)
        
        return list(functions)[:20]  # Limit results
    
    def _extract_comments(self, content: str) -> List[str]:
        """Extract comments from JavaScript"""
        comment_patterns = [
            r'//\s*(.+)',
            r'/\*\s*(.*?)\s*\*/'
        ]
        
        comments = []
        for pattern in comment_patterns:
            matches = re.findall(pattern, content, re.DOTALL)
            for match in matches:
                if len(match.strip()) > 10:  # Only meaningful comments
                    comments.append(match.strip()[:100])  # Limit length
        
        return comments[:10]  # Limit results
    
    def _ai_analyze_js_content(self, content: str, source_url: str) -> Dict:
        """Use AI to analyze complex JavaScript content"""
        logger.debug(f"AI analyzing JS file: {source_url}")
        
        # Truncate content for AI analysis
        truncated_content = content[:4000] if len(content) > 4000 else content
        
        prompt = f"""
        Analyze this JavaScript code for security issues and interesting patterns:
        
        Source: {source_url}
        
        JavaScript Content:
        {truncated_content}
        
        Identify:
        1. Potential security vulnerabilities (XSS sinks, dangerous functions, etc.)
        2. Hidden API endpoints or URLs
        3. Authentication/authorization logic flaws
        4. Hardcoded secrets or sensitive data
        5. Client-side business logic that could be bypassed
        6. Input validation weaknesses
        
        Return findings as JSON with type, description, severity, and line/context.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.3
            )
            
            ai_analysis = json.loads(response.choices[0].message.content)
            ai_analysis['source'] = source_url
            ai_analysis['content_size'] = len(content)
            
            return ai_analysis
            
        except Exception as e:
            logger.error(f"AI analysis failed for {source_url}: {e}")
            return {
                'source': source_url,
                'error': str(e),
                'ai_analysis_failed': True
            }
    
    def generate_js_focused_payloads(self, js_analysis: Dict) -> List[Dict]:
        """Generate JavaScript-focused test payloads based on analysis"""
        payloads = []
        
        # XSS payloads based on detected sinks
        for vuln in js_analysis.get('vulnerabilities_detected', []):
            if vuln.get('type') == 'xss_sinks':
                payloads.extend([
                    {
                        'type': 'xss',
                        'payload': '<script>alert("XSS_TEST")</script>',
                        'parameter': 'input',
                        'description': f'XSS test for {vuln.get("pattern")}'
                    },
                    {
                        'type': 'xss',
                        'payload': 'javascript:alert("XSS_TEST")',
                        'parameter': 'url',
                        'description': 'JavaScript protocol XSS'
                    },
                    {
                        'type': 'xss',
                        'payload': '<img src=x onerror=alert("XSS_TEST")>',
                        'parameter': 'input',
                        'description': 'Event handler XSS'
                    }
                ])
        
        # Prototype pollution payloads
        for vuln in js_analysis.get('vulnerabilities_detected', []):
            if vuln.get('type') == 'prototype_pollution':
                payloads.append({
                    'type': 'prototype_pollution',
                    'payload': '{"__proto__":{"polluted":"true"}}',
                    'parameter': 'json',
                    'description': 'Prototype pollution test'
                })
        
        # API endpoint testing based on discovered endpoints
        for endpoint in js_analysis.get('endpoints_discovered', []):
            if endpoint.get('type') == 'api_endpoint':
                payloads.extend([
                    {
                        'type': 'idor',
                        'payload': '1',
                        'parameter': 'id',
                        'description': f'IDOR test for {endpoint.get("endpoint")}'
                    },
                    {
                        'type': 'auth_bypass',
                        'payload': '{"admin":true}',
                        'parameter': 'json',
                        'description': f'Auth bypass for {endpoint.get("endpoint")}'
                    }
                ])
        
        return payloads[:15]  # Limit payload count
