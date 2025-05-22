#!/usr/bin/env python3
"""
Platform Integration Module for HackerOne and Bugcrowd
Handles program data retrieval, scope validation, and report submission
"""

import requests
import json
import time
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import re
import urllib.parse
from pathlib import Path
import base64

logger = logging.getLogger(__name__)

class PlatformIntegration:
    """Integration with bug bounty platforms"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # Platform configurations
        self.platforms = {
            'hackerone': {
                'base_url': 'https://api.hackerone.com/v1',
                'public_url': 'https://hackerone.com',
                'auth_header': 'Authorization'
            },
            'bugcrowd': {
                'base_url': 'https://api.bugcrowd.com/v2',
                'public_url': 'https://bugcrowd.com',
                'auth_header': 'Authorization'
            }
        }
        
    def setup_authentication(self, platform: str, username: str, api_token: str):
        """Setup authentication for platform APIs"""
        if platform == 'hackerone':
            # HackerOne uses Basic Auth with username:token
            credentials = base64.b64encode(f"{username}:{api_token}".encode()).decode()
            auth_header = f"Basic {credentials}"
        elif platform == 'bugcrowd':
            # Bugcrowd uses Bearer token
            auth_header = f"Bearer {api_token}"
        else:
            raise ValueError(f"Unsupported platform: {platform}")
        
        self.session.headers[self.platforms[platform]['auth_header']] = auth_header
        logger.info(f"✅ Authentication configured for {platform}")
        
    def get_program_info(self, platform: str, program_handle: str) -> Dict:
        """Retrieve program information and scope"""
        logger.info(f"🔍 Fetching program info for {program_handle} on {platform}")
        
        try:
            if platform == 'hackerone':
                return self._get_hackerone_program(program_handle)
            elif platform == 'bugcrowd':
                return self._get_bugcrowd_program(program_handle)
            else:
                raise ValueError(f"Unsupported platform: {platform}")
                
        except Exception as e:
            logger.error(f"❌ Failed to fetch program info: {e}")
            return self._get_program_info_fallback(platform, program_handle)
    
    def _get_hackerone_program(self, handle: str) -> Dict:
        """Get HackerOne program details via API"""
        url = f"{self.platforms['hackerone']['base_url']}/programs/{handle}"
        
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            program_data = data.get('data', {})
            attributes = program_data.get('attributes', {})
            
            # Extract scope information
            scope = self._parse_hackerone_scope(attributes.get('structured_scopes', []))
            
            return {
                'platform': 'hackerone',
                'handle': handle,
                'name': attributes.get('name', handle),
                'scope': scope,
                'bounty_range': self._extract_bounty_range(attributes),
                'submission_state': attributes.get('submission_state', 'unknown'),
                'managed': attributes.get('managed', False),
                'offers_bounties': attributes.get('offers_bounties', False),
                'raw_data': data
            }
            
        except requests.RequestException as e:
            logger.warning(f"API request failed, trying public fallback: {e}")
            return self._scrape_hackerone_public(handle)
    
    def _get_bugcrowd_program(self, handle: str) -> Dict:
        """Get Bugcrowd program details via API"""
        url = f"{self.platforms['bugcrowd']['base_url']}/programs/{handle}"
        
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            program_data = data.get('data', {})
            attributes = program_data.get('attributes', {})
            
            # Extract scope information
            scope = self._parse_bugcrowd_scope(attributes.get('targets', []))
            
            return {
                'platform': 'bugcrowd',
                'handle': handle,
                'name': attributes.get('name', handle),
                'scope': scope,
                'bounty_range': self._extract_bugcrowd_bounty_range(attributes),
                'status': attributes.get('status', 'unknown'),
                'managed': attributes.get('managed_by_bugcrowd', False),
                'raw_data': data
            }
            
        except requests.RequestException as e:
            logger.warning(f"API request failed, trying public fallback: {e}")
            return self._scrape_bugcrowd_public(handle)
    
    def _parse_hackerone_scope(self, structured_scopes: List[Dict]) -> Dict:
        """Parse HackerOne structured scope"""
        scope = {
            'in_scope': [],
            'out_of_scope': [],
            'domains': set(),
            'wildcards': set(),
            'ips': set(),
            'excluded_domains': set()
        }
        
        for scope_item in structured_scopes:
            attributes = scope_item.get('attributes', {})
            asset_identifier = attributes.get('asset_identifier', '')
            asset_type = attributes.get('asset_type', '')
            eligible_for_bounty = attributes.get('eligible_for_bounty', False)
            
            scope_entry = {
                'target': asset_identifier,
                'type': asset_type,
                'bounty_eligible': eligible_for_bounty,
                'instruction': attributes.get('instruction', '')
            }
            
            if attributes.get('eligible_for_submission', True):
                scope['in_scope'].append(scope_entry)
                
                # Categorize targets
                if asset_type == 'DOMAIN':
                    if '*' in asset_identifier:
                        scope['wildcards'].add(asset_identifier)
                    else:
                        scope['domains'].add(asset_identifier)
                elif asset_type == 'IP_ADDRESS':
                    scope['ips'].add(asset_identifier)
            else:
                scope['out_of_scope'].append(scope_entry)
                if asset_type == 'DOMAIN':
                    scope['excluded_domains'].add(asset_identifier)
        
        return scope
    
    def _parse_bugcrowd_scope(self, targets: List[Dict]) -> Dict:
        """Parse Bugcrowd target scope"""
        scope = {
            'in_scope': [],
            'out_of_scope': [],
            'domains': set(),
            'wildcards': set(),
            'ips': set(),
            'excluded_domains': set()
        }
        
        for target in targets:
            name = target.get('name', '')
            category = target.get('category', '')
            in_scope = target.get('in_scope', True)
            
            scope_entry = {
                'target': name,
                'type': category,
                'bounty_eligible': target.get('bounty_eligible', False),
                'instruction': target.get('description', '')
            }
            
            if in_scope:
                scope['in_scope'].append(scope_entry)
                
                # Categorize targets
                if category.lower() in ['website', 'domain']:
                    if '*' in name:
                        scope['wildcards'].add(name)
                    else:
                        scope['domains'].add(name)
                elif category.lower() in ['ip', 'ip_address']:
                    scope['ips'].add(name)
            else:
                scope['out_of_scope'].append(scope_entry)
                if category.lower() in ['website', 'domain']:
                    scope['excluded_domains'].add(name)
        
        return scope
    
    def _scrape_hackerone_public(self, handle: str) -> Dict:
        """Fallback: scrape public HackerOne page"""
        logger.info(f"📄 Scraping public HackerOne page for {handle}")
        
        url = f"https://hackerone.com/{handle}"
        
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            # Basic extraction from public page
            scope = self._extract_scope_from_html(response.text, 'hackerone')
            
            return {
                'platform': 'hackerone',
                'handle': handle,
                'name': handle,
                'scope': scope,
                'bounty_range': 'Unknown',
                'source': 'public_scrape',
                'raw_html': response.text[:5000]  # Store sample for debugging
            }
            
        except Exception as e:
            logger.error(f"Public scraping failed: {e}")
            return self._get_minimal_program_info(handle, 'hackerone')
    
    def _scrape_bugcrowd_public(self, handle: str) -> Dict:
        """Fallback: scrape public Bugcrowd page"""
        logger.info(f"📄 Scraping public Bugcrowd page for {handle}")
        
        url = f"https://bugcrowd.com/{handle}"
        
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            scope = self._extract_scope_from_html(response.text, 'bugcrowd')
            
            return {
                'platform': 'bugcrowd',
                'handle': handle,
                'name': handle,
                'scope': scope,
                'bounty_range': 'Unknown',
                'source': 'public_scrape',
                'raw_html': response.text[:5000]
            }
            
        except Exception as e:
            logger.error(f"Public scraping failed: {e}")
            return self._get_minimal_program_info(handle, 'bugcrowd')
    
    def _extract_scope_from_html(self, html: str, platform: str) -> Dict:
        """Extract scope information from HTML"""
        scope = {
            'in_scope': [],
            'out_of_scope': [],
            'domains': set(),
            'wildcards': set(),
            'ips': set(),
            'excluded_domains': set()
        }
        
        # Common patterns for domains in scope sections
        domain_patterns = [
            r'(?:https?://)?([a-zA-Z0-9*.-]+\.[a-zA-Z]{2,})',
            r'(\*\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
            r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        ]
        
        for pattern in domain_patterns:
            matches = re.findall(pattern, html)
            for match in matches:
                if self._is_valid_domain(match):
                    if '*' in match:
                        scope['wildcards'].add(match)
                    else:
                        scope['domains'].add(match)
                    
                    scope['in_scope'].append({
                        'target': match,
                        'type': 'DOMAIN',
                        'bounty_eligible': True,
                        'instruction': 'Extracted from public page'
                    })
        
        return scope
    
    def _get_minimal_program_info(self, handle: str, platform: str) -> Dict:
        """Create minimal program info when all else fails"""
        return {
            'platform': platform,
            'handle': handle,
            'name': handle,
            'scope': {
                'in_scope': [],
                'out_of_scope': [],
                'domains': set(),
                'wildcards': set(),
                'ips': set(),
                'excluded_domains': set()
            },
            'bounty_range': 'Unknown',
            'source': 'minimal_fallback',
            'warning': 'Could not retrieve program data - manual scope validation required'
        }
    
    def _get_program_info_fallback(self, platform: str, handle: str) -> Dict:
        """Fallback method when API fails"""
        if platform == 'hackerone':
            return self._scrape_hackerone_public(handle)
        elif platform == 'bugcrowd':
            return self._scrape_bugcrowd_public(handle)
        else:
            return self._get_minimal_program_info(handle, platform)
    
    def _extract_bounty_range(self, attributes: Dict) -> str:
        """Extract bounty range from HackerOne attributes"""
        try:
            bounty_table = attributes.get('bounty_table', {})
            if bounty_table:
                ranges = []
                for severity, amount in bounty_table.items():
                    if amount and amount > 0:
                        ranges.append(f"{severity}: ${amount}")
                return ", ".join(ranges) if ranges else "Bounties available"
            
            if attributes.get('offers_bounties'):
                return "Bounties available (amount not specified)"
            
            return "No bounties / VDP only"
            
        except Exception:
            return "Unknown"
    
    def _extract_bugcrowd_bounty_range(self, attributes: Dict) -> str:
        """Extract bounty range from Bugcrowd attributes"""
        try:
            min_bounty = attributes.get('min_bounty_amount')
            max_bounty = attributes.get('max_bounty_amount')
            
            if min_bounty and max_bounty:
                return f"${min_bounty} - ${max_bounty}"
            elif max_bounty:
                return f"Up to ${max_bounty}"
            elif attributes.get('offers_bounties'):
                return "Bounties available"
            
            return "VDP only"
            
        except Exception:
            return "Unknown"
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate if string is a valid domain"""
        if not domain or len(domain) < 3:
            return False
        
        # Basic domain validation
        domain_pattern = r'^[a-zA-Z0-9*.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(domain_pattern, domain))
    
    def get_program_statistics(self, platform: str, handle: str) -> Dict:
        """Get program statistics for intelligence"""
        logger.info(f"📊 Gathering program statistics for {handle}")
        
        try:
            if platform == 'hackerone':
                return self._get_hackerone_stats(handle)
            elif platform == 'bugcrowd':
                return self._get_bugcrowd_stats(handle)
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
        
        return {
            'total_reports': 'Unknown',
            'resolved_reports': 'Unknown',
            'average_bounty': 'Unknown',
            'response_time': 'Unknown',
            'last_activity': 'Unknown'
        }
    
    def _get_hackerone_stats(self, handle: str) -> Dict:
        """Get HackerOne program statistics"""
        url = f"{self.platforms['hackerone']['base_url']}/programs/{handle}/reports"
        
        try:
            response = self.session.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                # Process stats from reports data
                return self._process_hackerone_stats(data)
        except:
            pass
        
        # Fallback to public stats
        return self._scrape_hackerone_stats(handle)
    
    def _get_bugcrowd_stats(self, handle: str) -> Dict:
        """Get Bugcrowd program statistics"""
        # Bugcrowd API typically requires special permissions for stats
        return self._scrape_bugcrowd_stats(handle)
    
    def _scrape_hackerone_stats(self, handle: str) -> Dict:
        """Scrape public HackerOne statistics"""
        url = f"https://hackerone.com/{handle}"
        
        try:
            response = self.session.get(url, timeout=30)
            html = response.text
            
            stats = {}
            
            # Extract common statistics from HTML
            stats_patterns = {
                'total_reports': r'(\d+)\s*reports?\s*submitted',
                'resolved_reports': r'(\d+)\s*reports?\s*resolved',
                'bounty_paid': r'\$([0-9,]+)\s*paid\s*in\s*bounties',
                'response_time': r'(\d+)\s*days?\s*median\s*response'
            }
            
            for stat_name, pattern in stats_patterns.items():
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    stats[stat_name] = match.group(1)
            
            return stats
            
        except Exception as e:
            logger.debug(f"Stats scraping failed: {e}")
            return {}
    
    def _scrape_bugcrowd_stats(self, handle: str) -> Dict:
        """Scrape public Bugcrowd statistics"""
        # Similar implementation for Bugcrowd
        return {}
    
    def submit_report(self, platform: str, report_data: Dict) -> Dict:
        """Submit vulnerability report to platform"""
        logger.info(f"📝 Submitting report to {platform}")
        
        try:
            if platform == 'hackerone':
                return self._submit_hackerone_report(report_data)
            elif platform == 'bugcrowd':
                return self._submit_bugcrowd_report(report_data)
        except Exception as e:
            logger.error(f"Report submission failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'manual_submission_required': True
            }
    
    def _submit_hackerone_report(self, report_data: Dict) -> Dict:
        """Submit report to HackerOne via API"""
        url = f"{self.platforms['hackerone']['base_url']}/reports"
        
        payload = {
            "data": {
                "type": "report",
                "attributes": {
                    "title": report_data.get('title'),
                    "vulnerability_information": report_data.get('description'),
                    "severity_rating": report_data.get('severity', 'medium'),
                    "structured_scope_id": report_data.get('scope_id')
                }
            }
        }
        
        try:
            response = self.session.post(url, json=payload, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            return {
                'success': True,
                'report_id': result.get('data', {}).get('id'),
                'url': f"https://hackerone.com/reports/{result.get('data', {}).get('id')}",
                'response': result
            }
            
        except requests.RequestException as e:
            return {
                'success': False,
                'error': f"API submission failed: {e}",
                'manual_submission_required': True
            }
    
    def _submit_bugcrowd_report(self, report_data: Dict) -> Dict:
        """Submit report to Bugcrowd via API"""
        # Bugcrowd submission implementation
        return {
            'success': False,
            'error': 'Bugcrowd API submission not fully implemented',
            'manual_submission_required': True
        }
    
    def format_report_for_platform(self, platform: str, findings: List[Dict], 
                                   program_info: Dict) -> Dict:
        """Format findings into platform-specific report"""
        if platform == 'hackerone':
            return self._format_hackerone_report(findings, program_info)
        elif platform == 'bugcrowd':
            return self._format_bugcrowd_report(findings, program_info)
        
        return {}
    
    def _format_hackerone_report(self, findings: List[Dict], program_info: Dict) -> Dict:
        """Format report for HackerOne submission"""
        if not findings:
            return {}
        
        # Take the highest severity finding as primary
        primary_finding = max(findings, key=lambda x: self._severity_score(x.get('severity', 'low')))
        
        title = f"{primary_finding.get('type', 'Security Vulnerability')} in {primary_finding.get('url', 'Application')}"
        
        description = f"""## Summary
{primary_finding.get('type', 'Vulnerability')} discovered in {program_info.get('name', 'target application')}.

## Vulnerability Details
**Type:** {primary_finding.get('type')}
**URL:** {primary_finding.get('url')}
**Parameter:** {primary_finding.get('parameter', 'N/A')}
**Severity:** {primary_finding.get('severity', 'medium')}

## Proof of Concept
```
{primary_finding.get('payload', 'See evidence below')}
```

## Evidence
{primary_finding.get('evidence', 'Evidence captured during testing')}

## Steps to Reproduce
1. Navigate to {primary_finding.get('url')}
2. Inject payload: {primary_finding.get('payload', '[payload]')}
3. Observe the vulnerability manifestation

## Impact
{self._generate_impact_description(primary_finding)}

## Remediation
{self._generate_remediation_advice(primary_finding)}

---
*Report generated by automated security testing*
"""
        
        return {
            'title': title,
            'description': description,
            'severity': primary_finding.get('severity', 'medium'),
            'vulnerability_type': primary_finding.get('type'),
            'scope_id': self._find_scope_id(primary_finding.get('url'), program_info),
            'findings_count': len(findings),
            'all_findings': findings
        }
    
    def _format_bugcrowd_report(self, findings: List[Dict], program_info: Dict) -> Dict:
        """Format report for Bugcrowd submission"""
        # Similar to HackerOne but with Bugcrowd-specific formatting
        return self._format_hackerone_report(findings, program_info)  # Use same format for now
    
    def _severity_score(self, severity: str) -> int:
        """Convert severity to numeric score for comparison"""
        scores = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'info': 0
        }
        return scores.get(severity.lower(), 1)
    
    def _generate_impact_description(self, finding: Dict) -> str:
        """Generate impact description based on vulnerability type"""
        vuln_type = finding.get('type', '').lower()
        
        impact_templates = {
            'xss': "Cross-Site Scripting allows attackers to execute malicious scripts in user browsers, potentially leading to session hijacking, defacement, or credential theft.",
            'sql injection': "SQL Injection can allow attackers to access, modify, or delete database contents, potentially exposing sensitive user data or system information.",
            'ssrf': "Server-Side Request Forgery can allow attackers to access internal systems, read local files, or perform port scanning of internal networks.",
            'lfi': "Local File Inclusion can expose sensitive system files, configuration data, or source code to unauthorized access.",
            'rce': "Remote Code Execution represents a critical security flaw allowing complete system compromise and unauthorized command execution.",
            'idor': "Insecure Direct Object Reference can allow unauthorized access to other users' data or system resources."
        }
        
        for vuln_key, description in impact_templates.items():
            if vuln_key in vuln_type:
                return description
        
        return "This vulnerability may allow unauthorized access or manipulation of the application."
    
    def _generate_remediation_advice(self, finding: Dict) -> str:
        """Generate remediation advice based on vulnerability type"""
        vuln_type = finding.get('type', '').lower()
        
        remediation_templates = {
            'xss': "Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers and sanitize all user inputs.",
            'sql injection': "Use parameterized queries/prepared statements. Implement input validation and proper error handling.",
            'ssrf': "Validate and whitelist allowed URLs. Implement proper network segmentation and disable unnecessary protocols.",
            'lfi': "Implement proper input validation, use whitelists for file access, and avoid user-controlled file paths.",
            'rce': "Sanitize all user inputs, avoid dangerous functions, and implement proper access controls.",
            'idor': "Implement proper authorization checks and use indirect object references with access control validation."
        }
        
        for vuln_key, advice in remediation_templates.items():
            if vuln_key in vuln_type:
                return advice
        
        return "Review and fix the identified vulnerability following security best practices."
    
    def _find_scope_id(self, url: str, program_info: Dict) -> Optional[str]:
        """Find matching scope ID for the URL"""
        if not url or not program_info.get('scope'):
            return None
        
        # Extract domain from URL
        try:
            parsed = urllib.parse.urlparse(url if url.startswith('http') else f'https://{url}')
            domain = parsed.netloc or parsed.path.split('/')[0]
        except:
            domain = url
        
        # Check against in-scope domains
        scope = program_info['scope']
        
        # Direct domain match
        if domain in scope.get('domains', set()):
            return domain
        
        # Wildcard match
        for wildcard in scope.get('wildcards', set()):
            if self._matches_wildcard(domain, wildcard):
                return wildcard
        
        return None
    
    def _matches_wildcard(self, domain: str, wildcard: str) -> bool:
        """Check if domain matches wildcard pattern"""
        if '*' not in wildcard:
            return domain == wildcard
        
        # Convert wildcard to regex
        pattern = wildcard.replace('.', r'\.').replace('*', r'[^.]*')
        return bool(re.match(f'^{pattern}$', domain))
    
    def get_target_intelligence(self, target: str) -> Dict:
        """Gather intelligence about target across platforms"""
        logger.info(f"🔍 Gathering target intelligence for {target}")
        
        intelligence = {
            'target': target,
            'programs_found': [],
            'total_programs': 0,
            'best_program': None,
            'recommendations': []
        }
        
        # Search both platforms
        for platform in ['hackerone', 'bugcrowd']:
            programs = self._search_programs_by_domain(platform, target)
            intelligence['programs_found'].extend(programs)
        
        intelligence['total_programs'] = len(intelligence['programs_found'])
        
        if intelligence['programs_found']:
            # Rank programs by attractiveness
            intelligence['best_program'] = self._rank_programs(intelligence['programs_found'])[0]
            intelligence['recommendations'] = self._generate_targeting_recommendations(intelligence)
        
        return intelligence
    
    def _search_programs_by_domain(self, platform: str, domain: str) -> List[Dict]:
        """Search for programs that include the domain in scope"""
        # This would require more extensive API access or scraping
        # For now, return empty - would need implementation based on available APIs
        return []
    
    def _rank_programs(self, programs: List[Dict]) -> List[Dict]:
        """Rank programs by attractiveness for hunting"""
        def program_score(program):
            score = 0
            
            # Bounty amount (higher is better)
            bounty_range = program.get('bounty_range', '')
            if 'bounties available' in bounty_range.lower():
                score += 10
            elif '$' in bounty_range:
                # Extract max bounty amount
                amounts = re.findall(r'\$(\d+(?:,\d{3})*)', bounty_range)
                if amounts:
                    max_amount = int(amounts[-1].replace(',', ''))
                    score += min(max_amount / 100, 50)  # Cap at 50 points
            
            # Managed programs often have faster response
            if program.get('managed', False):
                score += 5
            
            # Active programs are better
            if program.get('submission_state') == 'open':
                score += 10
            
            return score
        
        return sorted(programs, key=program_score, reverse=True)
    
    def _generate_targeting_recommendations(self, intelligence: Dict) -> List[str]:
        """Generate recommendations for target selection"""
        recommendations = []
        
        programs = intelligence['programs_found']
        best_program = intelligence['best_program']
        
        if not programs:
            recommendations.append("No known bug bounty programs found for this target")
            recommendations.append("Consider checking if target has private programs")
            return recommendations
        
        if best_program:
            platform = best_program.get('platform', '')
            handle = best_program.get('handle', '')
            recommendations.append(f"Best target: {handle} on {platform}")
            
            bounty_range = best_program.get('bounty_range', '')
            if bounty_range != 'Unknown':
                recommendations.append(f"Bounty range: {bounty_range}")
        
        if len(programs) > 1:
            recommendations.append(f"Multiple programs available ({len(programs)} total)")
            recommendations.append("Consider testing all programs if scope differs")
        
        return recommendations

class ScopeValidator:
    """Validates targets against program scope to prevent out-of-bounds testing"""
    
    def __init__(self, program_info: Dict):
        self.program_info = program_info
        self.scope = program_info.get('scope', {})
        logger.info(f"🛡️ Scope validator initialized for {program_info.get('handle', 'unknown')}")
        
    def is_in_scope(self, target: str) -> Tuple[bool, str]:
        """Check if target is within program scope"""
        if not self.scope:
            return False, "No scope information available"
        
        # Normalize target
        target = self._normalize_target(target)
        
        # Check against excluded domains first
        if self._is_excluded(target):
            return False, f"Target {target} is explicitly out of scope"
        
        # Check against in-scope domains
        if self._is_included(target):
            return True, f"Target {target} is in scope"
        
        return False, f"Target {target} not found in scope definition"
    
    def _normalize_target(self, target: str) -> str:
        """Normalize target URL/domain for comparison"""
        # Remove protocol and path
        if target.startswith(('http://', 'https://')):
            parsed = urllib.parse.urlparse(target)
            target = parsed.netloc
        
        # Remove port
        target = target.split(':')[0]
        
        return target.lower()
    
    def _is_excluded(self, target: str) -> bool:
        """Check if target is in exclusion list"""
        excluded = self.scope.get('excluded_domains', set())
        
        for excluded_domain in excluded:
            if self._domain_matches(target, excluded_domain):
                return True
        
        return False
    
    def _is_included(self, target: str) -> bool:
        """Check if target is in inclusion list"""
        # Check direct domains
        if target in self.scope.get('domains', set()):
            return True
        
        # Check wildcards
        for wildcard in self.scope.get('wildcards', set()):
            if self._matches_wildcard(target, wildcard):
                return True
        
        # Check IPs
        if target in self.scope.get('ips', set()):
            return True
        
        return False
    
    def _domain_matches(self, target: str, scope_domain: str) -> bool:
        """Check if target matches scope domain (including wildcards)"""
        if '*' in scope_domain:
            return self._matches_wildcard(target, scope_domain)
        return target == scope_domain
    
    def _matches_wildcard(self, target: str, wildcard: str) -> bool:
        """Check if target matches wildcard pattern"""
        if wildcard.startswith('*.'):
            # Subdomain wildcard
            base_domain = wildcard[2:]
            return target == base_domain or target.endswith('.' + base_domain)
        
        # Other wildcard patterns
        pattern = wildcard.replace('.', r'\.').replace('*', r'[^.]*')
        return bool(re.match(f'^{pattern}$', target))
    
    def validate_url_list(self, urls: List[str]) -> Tuple[List[str], List[str]]:
        """Validate list of URLs, return (in_scope, out_of_scope)"""
        in_scope = []
        out_of_scope = []
        
        for url in urls:
            is_valid, reason = self.is_in_scope(url)
            if is_valid:
                in_scope.append(url)
            else:
                out_of_scope.append(url)
                logger.warning(f"⚠️ Excluding {url}: {reason}")
        
        logger.info(f"✅ Scope validation: {len(in_scope)} in scope, {len(out_of_scope)} excluded")
        return in_scope, out_of_scope
    
    def get_scope_summary(self) -> str:
        """Get human-readable scope summary"""
        if not self.scope:
            return "No scope information available"
        
        summary_parts = []
        
        domains = self.scope.get('domains', set())
        wildcards = self.scope.get('wildcards', set())
        ips = self.scope.get('ips', set())
        excluded = self.scope.get('excluded_domains', set())
        
        if domains:
            summary_parts.append(f"Domains: {', '.join(list(domains)[:5])}")
            if len(domains) > 5:
                summary_parts.append(f"(+{len(domains)-5} more)")
        
        if wildcards:
            summary_parts.append(f"Wildcards: {', '.join(list(wildcards)[:3])}")
        
        if ips:
            summary_parts.append(f"IPs: {', '.join(list(ips)[:3])}")
        
        if excluded:
            summary_parts.append(f"Excluded: {', '.join(list(excluded)[:3])}")
        
        return " | ".join(summary_parts) if summary_parts else "Empty scope"
