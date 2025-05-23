#!/usr/bin/env python3
"""
Enhanced Personal Bug Bounty Assistant
AI-powered bug bounty automation with platform integration, scope validation, and aggressive testing
"""

import os
import sys
import json
import time
import subprocess
import argparse
import requests
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
import openai

# Import enhanced modules
from platform_integration import PlatformIntegration, ScopeValidator
from aggressive_testing_waf_evasion import WAFEvasionTester, WAF_CONTINGENCY_GUIDE
from enhanced_vulnerability_testing import EnhancedVulnerabilityTester
from js_analysis_module import JavaScriptAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"bb_hunt_{datetime.now().strftime('%Y%m%d')}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("enhanced_bb_assistant")

class EnhancedBugBountyAssistant:
    """Enhanced Personal Bug Bounty Assistant with advanced features"""
    
    def __init__(self, api_key: str, config: Dict = None):
        self.client = openai.OpenAI(api_key=api_key)
        self.config = config or {}
        self.target = None
        self.workspace = None
        self.findings = []
        self.chains = []
        self.session_data = {}
        self.program_info = {}
        self.scope_validator = None
        
        # Initialize enhanced modules
        self.platform_integration = PlatformIntegration(self.config)
        self.vuln_tester = EnhancedVulnerabilityTester()
        self.aggressive_tester = WAFEvasionTester(self.config)
        self.js_analyzer = JavaScriptAnalyzer(self.client)
        
        # Testing configuration
        self.aggressive_mode = self.config.get('aggressive_testing', {}).get('enabled', True)
        self.scope_validation_enabled = self.config.get('scope_validation', {}).get('enabled', True)
        
        logger.info("🚀 Enhanced Bug Bounty Assistant initialized")
        
    def initialize_hunt(self, target: str, platform: str = None, program_handle: str = None):
        """Initialize enhanced hunt with platform integration"""
        self.target = target
        self.workspace = Path(f"hunt_{target.replace('.', '_').replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
        self.workspace.mkdir(exist_ok=True)
        
        logger.info(f"🎯 Starting enhanced hunt on {target}")
        logger.info(f"📁 Workspace: {self.workspace}")
        
        # Get program information if specified
        if platform and program_handle:
            logger.info(f"🔍 Fetching program info from {platform}")
            self.program_info = self.platform_integration.get_program_info(platform, program_handle)
            
            # Initialize scope validator
            if self.scope_validation_enabled:
                self.scope_validator = ScopeValidator(self.program_info)
                logger.info(f"🛡️ Scope validation enabled: {self.scope_validator.get_scope_summary()}")
        else:
            # Try to find programs for this target
            intelligence = self.platform_integration.get_target_intelligence(target)
            if intelligence['programs_found']:
                self.program_info = intelligence['best_program']
                logger.info(f"💡 Found program: {self.program_info.get('handle')} on {self.program_info.get('platform')}")
                if self.scope_validation_enabled:
                    self.scope_validator = ScopeValidator(self.program_info)
        
        # Save session metadata
        self.session_data = {
            "target": target,
            "platform": platform,
            "program_handle": program_handle,
            "program_info": self.program_info,
            "start_time": datetime.now().isoformat(),
            "workspace": str(self.workspace),
            "findings": [],
            "chains": [],
            "reports": [],
            "aggressive_mode": self.aggressive_mode,
            "scope_validation": self.scope_validation_enabled
        }
        self._save_session()
        
    def ai_target_analysis(self) -> Dict:
        """Enhanced AI-powered target analysis with program context"""
        logger.info("🧠 Analyzing target with AI...")
        
        program_context = ""
        if self.program_info:
            program_context = f"""
            Program Information:
            - Platform: {self.program_info.get('platform')}
            - Program: {self.program_info.get('name', self.program_info.get('handle'))}
            - Bounty Range: {self.program_info.get('bounty_range', 'Unknown')}
            - Scope: {len(self.program_info.get('scope', {}).get('in_scope', []))} targets in scope
            """
        
        prompt = f"""
        You are an expert bug bounty hunter analyzing a new target: {self.target}
        
        {program_context}
        
        Provide a comprehensive analysis including:
        1. Technology stack predictions based on domain/subdomain patterns
        2. Likely attack vectors to prioritize based on the program scope
        3. Common vulnerabilities for this type of target
        4. Recon strategy recommendations
        5. Areas most likely to yield high-severity findings
        6. Specific endpoints/features to target first
        7. Budget-conscious testing approach (focus on high-value findings)
        8. WAF detection expectations and evasion strategy
        
        Return your analysis as a JSON object with structured recommendations.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7
            )
            # Expect JSON in content, parse manually
            analysis = json.loads(response.choices[0].message.content)
            
            # Add program-specific insights
            if self.program_info:
                analysis['program_insights'] = {
                    'bounty_potential': self._assess_bounty_potential(),
                    'competition_level': self._assess_competition_level(),
                    'scope_complexity': self._assess_scope_complexity()
                }
            
            # Save analysis
            analysis_file = self.workspace / "ai_analysis.json"
            with open(analysis_file, 'w') as f:
                json.dump(analysis, f, indent=2)
                
            logger.info("✅ Enhanced target analysis complete")
            return analysis
            
        except Exception as e:
            logger.error(f"❌ AI analysis failed: {e}")
            return {"error": str(e)}
    
    def intelligent_recon(self) -> Dict:
        """Enhanced reconnaissance with scope validation and JS analysis"""
        logger.info("🔍 Starting intelligent reconnaissance...")
        
        recon_results = {
            "subdomains": [],
            "endpoints": [],
            "technologies": [],
            "interesting_findings": [],
            "javascript_analysis": {},
            "scope_validation": {
                "in_scope_targets": [],
                "out_of_scope_targets": [],
                "validation_enabled": self.scope_validation_enabled
            }
        }
        
        # Subdomain enumeration
        logger.info("Finding subdomains...")
        subdomains = self._find_subdomains()
        
        # Scope validation
        if self.scope_validator:
            in_scope_subdomains, out_of_scope_subdomains = self.scope_validator.validate_url_list(subdomains)
            recon_results["scope_validation"]["in_scope_targets"] = in_scope_subdomains
            recon_results["scope_validation"]["out_of_scope_targets"] = out_of_scope_subdomains
            recon_results["subdomains"] = in_scope_subdomains
            logger.info(f"🛡️ Scope validation: {len(in_scope_subdomains)} in scope, {len(out_of_scope_subdomains)} excluded")
        else:
            recon_results["subdomains"] = subdomains
            logger.warning("⚠️ No scope validation - testing all discovered targets")
        
        # Content discovery on validated targets
        logger.info("Discovering content...")
        top_targets = [self.target] + recon_results["subdomains"][:5]
        
        for target in top_targets:
            endpoints = self._discover_content(target)
            recon_results["endpoints"].extend(endpoints)
        
        # Scope validation for endpoints
        if self.scope_validator:
            all_endpoint_urls = [ep.get('url', '') if isinstance(ep, dict) else str(ep) for ep in recon_results["endpoints"]]
            in_scope_urls, out_of_scope_urls = self.scope_validator.validate_url_list(all_endpoint_urls)
            
            # Filter endpoints to only in-scope ones
            filtered_endpoints = []
            for endpoint in recon_results["endpoints"]:
                endpoint_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                if endpoint_url in in_scope_urls:
                    filtered_endpoints.append(endpoint)
            
            recon_results["endpoints"] = filtered_endpoints
        
        # AI-powered endpoint analysis
        logger.info("🧠 AI analyzing discovered endpoints...")
        interesting_endpoints = self._ai_classify_endpoints(recon_results["endpoints"])
        recon_results["interesting_findings"] = interesting_endpoints
        
        # Enhanced JavaScript analysis
        logger.info("🔍 Analyzing JavaScript files...")
        js_analysis = self.js_analyzer.discover_and_analyze_js(self.target, recon_results["endpoints"])
        recon_results["javascript_analysis"] = js_analysis
        
        # Validate JS-discovered endpoints
        if self.scope_validator and js_analysis.get("endpoints_discovered"):
            js_endpoints = [ep.get("endpoint", "") for ep in js_analysis["endpoints_discovered"]]
            full_js_urls = []
            for ep in js_endpoints:
                if ep.startswith('http'):
                    full_js_urls.append(ep)
                elif ep.startswith('/'):
                    full_js_urls.append(f"https://{self.target}{ep}")
                else:
                    full_js_urls.append(f"https://{self.target}/{ep}")
            
            in_scope_js, out_of_scope_js = self.scope_validator.validate_url_list(full_js_urls)
            recon_results["javascript_analysis"]["in_scope_endpoints"] = in_scope_js
            recon_results["javascript_analysis"]["out_of_scope_endpoints"] = out_of_scope_js
        
        # Save recon results
        recon_file = self.workspace / "recon_results.json"
        with open(recon_file, 'w') as f:
            json.dump(recon_results, f, indent=2)
            
        logger.info(f"✅ Enhanced recon complete: {len(recon_results['endpoints'])} endpoints, {len(interesting_endpoints)} interesting, {len(js_analysis.get('endpoints_discovered', []))} from JS")
        return recon_results
    
    def ai_vulnerability_hunting(self, recon_data: Dict) -> List[Dict]:
        """Enhanced AI-guided vulnerability testing with aggressive techniques"""
        logger.info("🎯 Starting enhanced vulnerability hunting...")
        
        findings = []
        interesting_endpoints = recon_data.get("interesting_findings", [])
        
        # Test regular endpoints with enhanced techniques
        for endpoint in interesting_endpoints[:20]:
            logger.info(f"Testing: {endpoint['url']}")
            
            # Check scope one more time
            if self.scope_validator:
                is_in_scope, reason = self.scope_validator.is_in_scope(endpoint['url'])
                if not is_in_scope:
                    logger.warning(f"⚠️ Skipping out-of-scope endpoint: {endpoint['url']}")
                    continue
            
            # Generate AI-powered test payloads
            payloads = self._generate_ai_payloads(endpoint)
            
            # Test each payload with enhanced methods
            for payload_data in payloads:
                if self.aggressive_mode:
                    # Use aggressive testing with WAF evasion
                    result = self.aggressive_tester.test_payload_aggressive(endpoint['url'], payload_data)
                else:
                    # Use standard enhanced testing
                    result = self.vuln_tester.test_payload(endpoint['url'], payload_data)
                
                if result.get('vulnerable'):
                    result['discovery_method'] = 'endpoint_analysis'
                    findings.append(result)
                    logger.info(f"🚨 Vulnerability found: {result['type']} in {endpoint['url']}")
                    
                    # If we found something, try variations
                    if self.aggressive_mode:
                        variations = self._generate_payload_variations(payload_data, result)
                        for variation in variations[:3]:  # Limit variations
                            var_result = self.aggressive_tester.test_payload_aggressive(endpoint['url'], variation)
                            if var_result.get('vulnerable') and var_result not in findings:
                                var_result['discovery_method'] = 'payload_variation'
                                findings.append(var_result)
        
        # Test JavaScript-discovered endpoints
        js_analysis = recon_data.get("javascript_analysis", {})
        js_endpoints = js_analysis.get("in_scope_endpoints", js_analysis.get("endpoints_discovered", []))
        
        for js_endpoint_data in js_endpoints[:10]:
            if isinstance(js_endpoint_data, dict):
                endpoint_url = js_endpoint_data.get("endpoint", "")
            else:
                endpoint_url = str(js_endpoint_data)
            
            if not endpoint_url:
                continue
                
            if not endpoint_url.startswith('http'):
                endpoint_url = f"https://{self.target}{endpoint_url}" if endpoint_url.startswith('/') else f"https://{self.target}/{endpoint_url}"
            
            logger.info(f"Testing JS-discovered endpoint: {endpoint_url}")
            
            # Generate JS-specific payloads
            js_payloads = self.js_analyzer.generate_js_focused_payloads(js_analysis)
            
            for payload in js_payloads:
                if self.aggressive_mode:
                    result = self.aggressive_tester.test_payload_aggressive(endpoint_url, payload)
                else:
                    result = self.vuln_tester.test_payload(endpoint_url, payload)
                
                if result.get('vulnerable'):
                    result['discovery_method'] = 'javascript_analysis'
                    findings.append(result)
                    logger.info(f"🚨 JS-discovered vulnerability: {result['type']} in {endpoint_url}")
        
        # Test for secrets found in JS
        js_secrets = js_analysis.get("secrets_found", [])
        for secret in js_secrets:
            # Create a finding for exposed secrets
            secret_finding = {
                'vulnerable': True,
                'type': 'Information Disclosure',
                'subtype': f"Exposed {secret.get('type', 'secret')}",
                'url': secret.get('source', 'JavaScript file'),
                'evidence': secret.get('value', 'Secret value'),
                'severity': 'medium' if 'token' in secret.get('type', '') else 'low',
                'discovery_method': 'javascript_secret_analysis'
            }
            findings.append(secret_finding)
        
        self.findings = findings
        
        # Save findings
        findings_file = self.workspace / "findings.json"
        with open(findings_file, 'w') as f:
            json.dump(findings, f, indent=2)
            
        logger.info(f"✅ Enhanced vulnerability hunting complete: {len(findings)} potential issues found")
        return findings
    
    def ai_chain_detection(self) -> List[Dict]:
        """Enhanced AI-powered vulnerability chaining analysis"""
        if not self.findings:
            logger.info("No findings to chain")
            return []
            
        logger.info("🔗 Analyzing vulnerability chains with AI...")
        
        # Include program context for better chaining analysis
        program_context = ""
        if self.program_info:
            program_context = f"""
            Program Context:
            - Platform: {self.program_info.get('platform')}
            - Bounty Range: {self.program_info.get('bounty_range')}
            - Scope includes {len(self.program_info.get('scope', {}).get('in_scope', []))} targets
            """
        
        prompt = f"""
        You are an expert bug bounty hunter analyzing vulnerabilities for potential chaining.
        
        Target: {self.target}
        {program_context}
        
        Findings: {json.dumps(self.findings, indent=2)}
        
        Analyze these findings and identify:
        1. Potential attack chains that combine multiple vulnerabilities
        2. Privilege escalation paths
        3. Data exfiltration scenarios
        4. Account takeover possibilities
        5. Business logic abuse chains
        6. Cross-domain attack possibilities
        7. API abuse chains (if APIs were discovered)
        
        For each chain, provide:
        - Chain name and description
        - Step-by-step attack path
        - Impact assessment with business context
        - Proof of concept outline
        - CVSS score estimation
        - Estimated bounty value based on program
        
        Prioritize chains that would be most valuable for bug bounty submission.
        
        Return as JSON object with 'chains' array.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7
            )
            
            result = json.loads(response.choices[0].message.content)
            chains = result.get("chains", [])
            self.chains = chains
            
            # Save chains
            chains_file = self.workspace / "vulnerability_chains.json"
            with open(chains_file, 'w') as f:
                json.dump(chains, f, indent=2)
                
            logger.info(f"✅ Enhanced chain analysis complete: {len(chains)} chains identified")
            return chains
            
        except Exception as e:
            logger.error(f"❌ Chain analysis failed: {e}")
            return []
    
    def ai_exploit_generation(self) -> Dict:
        """Enhanced AI-powered exploit and PoC generation"""
        logger.info("💥 Generating exploits and PoCs with AI...")
        
        exploits = {
            "individual_exploits": [],
            "chain_exploits": [],
            "poc_scripts": [],
            "burp_extensions": [],  # For Burp Suite integration
            "manual_steps": []
        }
        
        # Generate exploits for individual findings
        for finding in self.findings:
            exploit = self._generate_enhanced_exploit(finding)
            if exploit:
                exploits["individual_exploits"].append(exploit)
        
        # Generate exploits for chains
        for chain in self.chains:
            chain_exploit = self._generate_enhanced_chain_exploit(chain)
            if chain_exploit:
                exploits["chain_exploits"].append(chain_exploit)
        
        # Generate Burp Suite integration
        if self.config.get('burp_integration', {}).get('enabled', False):
            burp_extensions = self._generate_burp_extensions()
            exploits["burp_extensions"] = burp_extensions
        
        # Save exploits
        exploits_file = self.workspace / "exploits.json"
        with open(exploits_file, 'w') as f:
            json.dump(exploits, f, indent=2)
            
        # Generate PoC scripts
        self._generate_enhanced_poc_scripts(exploits)
        
        logger.info(f"✅ Enhanced exploit generation complete")
        return exploits
    
    def ai_report_generation(self) -> Dict:
        """Enhanced AI-powered professional report generation with platform formatting"""
        logger.info("📝 Generating enhanced professional report...")
        
        report_files = {}
        
        if self.program_info and self.program_info.get('platform'):
            # Generate platform-specific reports
            platform = self.program_info['platform']
            platform_report = self.platform_integration.format_report_for_platform(
                platform, self.findings, self.program_info
            )
            
            if platform_report:
                # Generate platform-specific markdown
                platform_md = self._generate_platform_report_markdown(platform_report, platform)
                platform_file = self.workspace / f"report_{platform}_{self.target}.md"
                
                with open(platform_file, 'w') as f:
                    f.write(platform_md)
                
                report_files[f'{platform}_report'] = str(platform_file)
                
                # Try automatic submission if configured
                if self.config.get('auto_submit', False) and self.config.get(f'{platform}_credentials'):
                    submission_result = self.platform_integration.submit_report(platform, platform_report)
                    report_files[f'{platform}_submission'] = submission_result
        
        # Generate comprehensive technical report
        technical_report = self._generate_technical_report()
        tech_file = self.workspace / f"technical_report_{self.target}.md"
        
        with open(tech_file, 'w') as f:
            f.write(technical_report)
        
        report_files['technical_report'] = str(tech_file)
        
        # Generate executive summary
        exec_report = self._generate_executive_report()
        exec_file = self.workspace / f"executive_summary_{self.target}.md"
        
        with open(exec_file, 'w') as f:
            f.write(exec_report)
        
        report_files['executive_summary'] = str(exec_file)
        
        # Generate HTML report for presentation
        html_report = self._generate_enhanced_html_report()
        html_file = self.workspace / f"report_{self.target}.html"
        
        with open(html_file, 'w') as f:
            f.write(html_report)
        
        report_files['html_report'] = str(html_file)
        
        logger.info(f"✅ Enhanced reports generated: {len(report_files)} files")
        return report_files
    
    def run_full_enhanced_hunt(self, target: str, platform: str = None, program_handle: str = None) -> Dict:
        """Run the complete enhanced bug bounty hunting workflow"""
        start_time = time.time()
        
        try:
            # Initialize with platform integration
            self.initialize_hunt(target, platform, program_handle)
            
            # Display WAF contingency information if aggressive mode
            if self.aggressive_mode:
                logger.info("🚨 Aggressive mode enabled - WAF evasion active")
                logger.info("📖 WAF Contingency Guide available in workspace")
                
                # Save WAF guide
                waf_guide_file = self.workspace / "waf_contingency_guide.md"
                with open(waf_guide_file, 'w') as f:
                    f.write(WAF_CONTINGENCY_GUIDE)
            
            # Phase 1: Enhanced AI Analysis
            analysis = self.ai_target_analysis()
            print(f"\n🎯 Enhanced Target Analysis Complete")
            if analysis.get('program_insights'):
                insights = analysis['program_insights']
                print(f"   💰 Bounty Potential: {insights.get('bounty_potential', 'Unknown')}")
                print(f"   🏆 Competition Level: {insights.get('competition_level', 'Unknown')}")
            print(f"   📋 Recommended focus areas: {', '.join(analysis.get('priority_areas', [])[:3])}")
            
            # Phase 2: Enhanced Reconnaissance
            recon_data = self.intelligent_recon()
            print(f"\n🔍 Enhanced Reconnaissance Complete")
            print(f"   🌐 Subdomains found: {len(recon_data['subdomains'])}")
            print(f"   🔗 Endpoints discovered: {len(recon_data['endpoints'])}")
            print(f"   📝 JavaScript files analyzed: {recon_data['javascript_analysis'].get('js_files_found', 0)}")
            print(f"   🎯 Interesting targets: {len(recon_data['interesting_findings'])}")
            
            if self.scope_validator:
                scope_validation = recon_data['scope_validation']
                print(f"   🛡️ Scope validation: {len(scope_validation['in_scope_targets'])} in scope, {len(scope_validation['out_of_scope_targets'])} excluded")
            
            # Phase 3: Enhanced Vulnerability Hunting
            findings = self.ai_vulnerability_hunting(recon_data)
            print(f"\n🎯 Enhanced Vulnerability Hunting Complete")
            print(f"   🚨 Potential vulnerabilities: {len(findings)}")
            
            if self.aggressive_mode:
                waf_detected_count = sum(1 for f in findings if f.get('waf_detected'))
                evasion_success_count = sum(1 for f in findings if f.get('evasion_technique'))
                print(f"   🛡️ WAF encounters: {waf_detected_count}")
                print(f"   🚀 Evasion successes: {evasion_success_count}")
            
            # Show finding breakdown
            finding_types = {}
            for finding in findings:
                ftype = finding.get('type', 'Unknown')
                finding_types[ftype] = finding_types.get(ftype, 0) + 1
            
            if finding_types:
                print("   📊 Finding breakdown:")
                for ftype, count in sorted(finding_types.items()):
                    print(f"      - {ftype}: {count}")
            
            # Phase 4: Enhanced Chain Detection
            chains = self.ai_chain_detection()
            print(f"\n🔗 Enhanced Chain Analysis Complete")
            print(f"   ⛓️ Attack chains identified: {len(chains)}")
            
            # Phase 5: Enhanced Exploit Generation
            exploits = self.ai_exploit_generation()
            print(f"\n💥 Enhanced Exploit Generation Complete")
            print(f"   🔧 Individual exploits: {len(exploits['individual_exploits'])}")
            print(f"   ⛓️ Chain exploits: {len(exploits['chain_exploits'])}")
            print(f"   📜 PoC scripts generated: {len(exploits['poc_scripts'])}")
            
            # Phase 6: Enhanced Report Generation
            reports = self.ai_report_generation()
            print(f"\n📝 Enhanced Report Generation Complete")
            print(f"   📄 Reports generated: {len(reports)}")
            
            for report_type, report_file in reports.items():
                print(f"      - {report_type}: {report_file}")
            
            # Final enhanced summary
            duration = time.time() - start_time
            print(f"\n🎉 Enhanced Hunt Complete!")
            print(f"   ⏱️ Duration: {duration/60:.1f} minutes")
            print(f"   🎯 Target: {target}")
            
            if self.program_info:
                print(f"   🏪 Program: {self.program_info.get('handle')} on {self.program_info.get('platform')}")
                print(f"   💰 Bounty Range: {self.program_info.get('bounty_range', 'Unknown')}")
            
            print(f"   🚨 Findings: {len(findings)} vulnerabilities, {len(chains)} chains")
            print(f"   📁 Workspace: {self.workspace}")
            
            # Provide next steps
            print(f"\n📋 Next Steps:")
            if findings:
                print(f"   1. Review findings in {self.workspace}/findings.json")
                print(f"   2. Validate vulnerabilities manually")
                if self.program_info and self.program_info.get('platform'):
                    platform = self.program_info['platform']
                    print(f"   3. Submit via {platform} platform")
                    print(f"   4. Use platform-specific report: {reports.get(f'{platform}_report', 'Not generated')}")
                else:
                    print(f"   3. Identify appropriate bug bounty program")
                    print(f"   4. Format reports for submission")
            else:
                print(f"   1. Review reconnaissance data for missed opportunities")
                print(f"   2. Consider expanding scope or trying different techniques")
                print(f"   3. Analyze JavaScript findings for information disclosure")
            
            # Return comprehensive results
            return {
                'success': True,
                'target': target,
                'duration_minutes': duration / 60,
                'findings_count': len(findings),
                'chains_count': len(chains),
                'reports': reports,
                'workspace': str(self.workspace),
                'program_info': self.program_info,
                'aggressive_mode': self.aggressive_mode,
                'scope_validation': self.scope_validation_enabled
            }
            
        except Exception as e:
            logger.error(f"❌ Enhanced hunt failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'workspace': str(self.workspace) if self.workspace else None
            }
    
    # Enhanced helper methods
    def _assess_bounty_potential(self) -> str:
        """Assess bounty potential based on program info"""
        bounty_range = self.program_info.get('bounty_range', '').lower()
        
        if 'vdp' in bounty_range or 'no bounties' in bounty_range:
            return "Low (VDP Only)"
        elif any(amount in bounty_range for amount in ['$1000', '$2000', '$3000', '$4000', '$5000']):
            return "High"
        elif '$' in bounty_range:
            return "Medium"
        else:
            return "Unknown"
    
    def _assess_competition_level(self) -> str:
        """Assess competition level based on program characteristics"""
        if self.program_info.get('managed', False):
            return "High (Managed Program)"
        elif 'bounties available' in self.program_info.get('bounty_range', '').lower():
            return "Medium"
        else:
            return "Unknown"
    
    def _assess_scope_complexity(self) -> str:
        """Assess scope complexity"""
        scope = self.program_info.get('scope', {})
        in_scope_count = len(scope.get('in_scope', []))
        
        if in_scope_count > 20:
            return "High (Large Attack Surface)"
        elif in_scope_count > 5:
            return "Medium"
        elif in_scope_count > 0:
            return "Low (Limited Scope)"
        else:
            return "Unknown"
    
    def _generate_payload_variations(self, original_payload: Dict, successful_result: Dict) -> List[Dict]:
        """Generate variations of successful payloads"""
        variations = []
        payload = original_payload.get('payload', '')
        vuln_type = original_payload.get('type', '')
        
        if 'xss' in vuln_type.lower():
            # XSS payload variations
            xss_variations = [
                payload.replace('<script>', '<ScRiPt>'),
                payload.replace('alert', 'prompt'),
                payload.replace('()', '(1)'),
                f"{payload}%0a",  # Add newline
                f"/*{payload}*/"   # Add comment wrapper
            ]
            
            for var_payload in xss_variations:
                variations.append({
                    **original_payload,
                    'payload': var_payload,
                    'variation_of': payload
                })
        
        elif 'sql' in vuln_type.lower():
            # SQL injection variations
            sql_variations = [
                payload.replace(' ', '/**/'),
                payload.replace('UNION', 'union'),
                payload.replace('SELECT', 'select'),
                f"{payload}-- -",
                f"{payload}#"
            ]
            
            for var_payload in sql_variations:
                variations.append({
                    **original_payload,
                    'payload': var_payload,
                    'variation_of': payload
                })
        
        return variations[:3]  # Limit to 3 variations
    
    def _generate_enhanced_exploit(self, finding: Dict) -> Dict:
        """Generate enhanced exploit with better context"""
        prompt = f"""
        Generate a professional exploit/PoC for this vulnerability:
        {json.dumps(finding, indent=2)}
        
        Target: {self.target}
        Program: {self.program_info.get('handle', 'Unknown')}
        
        Include:
        - Complete exploit code/script
        - Step-by-step reproduction instructions
        - Impact assessment with business context
        - CVSS v3.1 score calculation
        - Remediation advice with code examples
        - Timeline for responsible disclosure
        
        Format for professional bug bounty submission.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3
            )
            
            return {
                "finding_id": finding.get("url", "unknown"),
                "exploit_content": response.choices[0].message.content,
                "vulnerability_type": finding.get("type"),
                "severity": finding.get("severity", "medium"),
                "discovery_method": finding.get("discovery_method", "unknown")
            }
            
        except Exception as e:
            logger.error(f"Enhanced exploit generation failed: {e}")
            return {}
    
    def _generate_enhanced_chain_exploit(self, chain: Dict) -> Dict:
        """Generate enhanced exploit for vulnerability chain"""
        prompt = f"""
        Generate a comprehensive exploit for this vulnerability chain:
        {json.dumps(chain, indent=2)}
        
        Target: {self.target}
        Program: {self.program_info.get('handle', 'Unknown')}
        
        Create a complete attack scenario including:
        - Chain exploitation script
        - Step-by-step attack flow
        - Prerequisites and assumptions
        - Expected outcomes and impact
        - Business logic context
        - Full remediation strategy
        
        Make it submission-ready for bug bounty platforms.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3
            )
            
            return {
                "chain_name": chain.get("name", "Unknown Chain"),
                "exploit_content": response.choices[0].message.content,
                "chain_steps": chain.get("steps", []),
                "estimated_impact": chain.get("impact", "Unknown")
            }
            
        except Exception as e:
            logger.error(f"Enhanced chain exploit generation failed: {e}")
            return {}
    
    def _generate_enhanced_poc_scripts(self, exploits: Dict):
        """Generate enhanced PoC scripts with better functionality"""
        poc_dir = self.workspace / "poc_scripts"
        poc_dir.mkdir(exist_ok=True)
        
        # Generate individual exploit scripts
        for i, exploit in enumerate(exploits.get("individual_exploits", [])):
            script_content = f"""#!/usr/bin/env python3
\"\"\"
PoC for {exploit.get('vulnerability_type', 'Unknown')} vulnerability
Target: {self.target}
Discovery Method: {exploit.get('discovery_method', 'Unknown')}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
\"\"\"

import requests
import sys
import urllib.parse
from typing import Dict, Optional

class VulnerabilityPoC:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({{
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }})
    
    def exploit(self) -> Dict:
        \"\"\"Execute the vulnerability exploit\"\"\"
        try:
            # Exploit implementation would go here
            # Based on the finding data: {exploit.get('finding_id')}
            
            print(f"[+] Testing vulnerability on {{self.target_url}}")
            
            # This is a template - actual exploit code would be generated
            # by the AI based on the specific vulnerability details
            
            return {{"success": True, "message": "PoC template generated"}}
            
        except Exception as e:
            return {{"success": False, "error": str(e)}}

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {{sys.argv[0]}} <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    poc = VulnerabilityPoC(target)
    result = poc.exploit()
    
    if result["success"]:
        print(f"[+] {{result['message']}}")
    else:
        print(f"[-] Error: {{result['error']}}")

if __name__ == "__main__":
    main()
"""
            
            script_file = poc_dir / f"exploit_{i+1}_{exploit.get('vulnerability_type', 'unknown').lower().replace(' ', '_')}.py"
            with open(script_file, 'w') as f:
                f.write(script_content)
            
            # Make executable
            script_file.chmod(0o755)
        
        # Generate chain exploit scripts
        for i, chain_exploit in enumerate(exploits.get("chain_exploits", [])):
            chain_script = f"""#!/usr/bin/env python3
\"\"\"
Chain Exploit PoC: {chain_exploit.get('chain_name', 'Unknown Chain')}
Target: {self.target}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
\"\"\"

import requests
import time
import sys
from typing import Dict, List

class ChainExploitPoC:
    def __init__(self, target: str):
        self.target = target
        self.session = requests.Session()
        self.results = []
    
    def execute_chain(self) -> Dict:
        \"\"\"Execute the complete vulnerability chain\"\"\"
        print(f"[+] Starting chain exploit against {{self.target}}")
        
        # Chain implementation would go here
        # Based on: {chain_exploit.get('chain_name')}
        
        return {{"success": True, "steps_completed": 0}}

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {{sys.argv[0]}} <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    chain_poc = ChainExploitPoC(target)
    result = chain_poc.execute_chain()
    
    print(f"[+] Chain exploit completed: {{result}}")

if __name__ == "__main__":
    main()
"""
            
            chain_file = poc_dir / f"chain_exploit_{i+1}_{chain_exploit.get('chain_name', 'unknown').lower().replace(' ', '_')}.py"
            with open(chain_file, 'w') as f:
                f.write(chain_script)
            
            chain_file.chmod(0o755)
        
        logger.info(f"✅ PoC scripts generated in {poc_dir}")
    
    def _generate_burp_extensions(self) -> List[Dict]:
        """Generate Burp Suite extensions for found vulnerabilities"""
        # This would generate custom Burp extensions based on findings
        # For now, return empty list as this requires complex Burp API integration
        return []
    
    def _generate_platform_report_markdown(self, platform_report: Dict, platform: str) -> str:
        """Generate platform-specific markdown report"""
        return f"""# Bug Bounty Report - {platform.title()}

**Target:** {self.target}  
**Program:** {self.program_info.get('handle', 'Unknown')}  
**Date:** {datetime.now().strftime('%Y-%m-%d')}  
**Researcher:** Automated Bug Bounty Assistant  

## Summary

{platform_report.get('description', 'No description available')}

## Severity

**{platform_report.get('severity', 'medium').title()}**

## Vulnerability Type

{platform_report.get('vulnerability_type', 'Unknown')}

## Findings

Total vulnerabilities found: {platform_report.get('findings_count', 0)}

## Detailed Analysis

{platform_report.get('description', 'Detailed analysis not available')}

---

*This report was generated automatically by Enhanced Bug Bounty Assistant*
*Manual verification recommended before submission*
"""
    
    def _generate_technical_report(self) -> str:
        """Generate comprehensive technical report"""
        findings_summary = []
        for finding in self.findings:
            findings_summary.append(f"- **{finding.get('type', 'Unknown')}** in `{finding.get('url', 'Unknown URL')}` (Severity: {finding.get('severity', 'Unknown')})")
        
        return f"""# Technical Security Assessment Report

**Target:** {self.target}  
**Assessment Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Tool:** Enhanced Bug Bounty Assistant v2.0  
**Mode:** {'Aggressive' if self.aggressive_mode else 'Standard'} Testing  
**Scope Validation:** {'Enabled' if self.scope_validation_enabled else 'Disabled'}  

## Executive Summary

This report contains the results of an automated security assessment performed against {self.target}.

- **Total Vulnerabilities Found:** {len(self.findings)}
- **Attack Chains Identified:** {len(self.chains)}
- **Testing Duration:** {(time.time() - self.session_data.get('start_time', time.time())) / 60:.1f} minutes

## Program Information

{f'**Platform:** {self.program_info.get("platform")}' if self.program_info.get("platform") else '**Platform:** Not specified'}  
{f'**Program:** {self.program_info.get("handle")}' if self.program_info.get("handle") else '**Program:** Not specified'}  
{f'**Bounty Range:** {self.program_info.get("bounty_range")}' if self.program_info.get("bounty_range") else '**Bounty Range:** Unknown'}  

## Methodology

1. **Target Analysis:** AI-powered analysis of target characteristics
2. **Reconnaissance:** Subdomain enumeration and content discovery
3. **JavaScript Analysis:** Automated analysis of client-side code
4. **Vulnerability Testing:** {'Aggressive testing with WAF evasion' if self.aggressive_mode else 'Standard vulnerability testing'}
5. **Chain Analysis:** AI-powered attack chain identification
6. **Exploit Generation:** Automated PoC and exploit development

## Findings

{chr(10).join(findings_summary) if findings_summary else 'No vulnerabilities found.'}

## Scope Validation

{f'Scope validation was enabled. {len(self.session_data.get("scope_validation", {}).get("in_scope_targets", []))} targets were in scope, {len(self.session_data.get("scope_validation", {}).get("out_of_scope_targets", []))} were excluded.' if self.scope_validation_enabled else 'Scope validation was disabled. All discovered targets were tested.'}

## Recommendations

1. **Immediate Actions:**
   - Review and validate all identified vulnerabilities
   - Prioritize critical and high-severity findings
   - Implement temporary mitigations where possible

2. **Long-term Improvements:**
   - Implement comprehensive input validation
   - Deploy Web Application Firewall (WAF) if not present
   - Conduct regular security assessments
   - Implement secure coding practices

## Appendices

- **A.** Detailed vulnerability descriptions (see findings.json)
- **B.** Attack chain analysis (see vulnerability_chains.json)
- **C.** Proof-of-concept scripts (see poc_scripts/ directory)
- **D.** Raw reconnaissance data (see recon_results.json)

---

*Report generated by Enhanced Bug Bounty Assistant*  
*Workspace: {self.workspace}*
"""
    
    def _generate_executive_report(self) -> str:
        """Generate executive summary report"""
        critical_findings = [f for f in self.findings if f.get('severity') == 'critical']
        high_findings = [f for f in self.findings if f.get('severity') == 'high']
        
        return f"""# Executive Summary - Security Assessment

**Target:** {self.target}  
**Assessment Date:** {datetime.now().strftime('%Y-%m-%d')}  

## Key Findings

- **🔴 Critical Issues:** {len(critical_findings)}
- **🟠 High Risk Issues:** {len(high_findings)}
- **📊 Total Vulnerabilities:** {len(self.findings)}
- **⛓️ Attack Chains:** {len(self.chains)}

## Business Impact

{f'This assessment was conducted against a {self.program_info.get("platform")} bug bounty program with bounty range: {self.program_info.get("bounty_range")}' if self.program_info.get("platform") else 'This assessment identified security vulnerabilities that could impact business operations.'}

## Risk Assessment

{'**IMMEDIATE ACTION REQUIRED** - Critical vulnerabilities found that could lead to complete system compromise.' if critical_findings else '**MODERATE RISK** - Vulnerabilities found that require attention but do not pose immediate critical risk.' if self.findings else '**LOW RISK** - No significant vulnerabilities identified during automated testing.'}

## Recommendations

1. **Immediate** (0-24 hours):
   {f'- Address {len(critical_findings)} critical vulnerabilities' if critical_findings else '- Review findings for accuracy'}
   
2. **Short-term** (1-7 days):
   {f'- Remediate {len(high_findings)} high-risk issues' if high_findings else '- Implement additional security controls'}
   
3. **Long-term** (1-3 months):
   - Implement comprehensive security testing program
   - Establish regular vulnerability assessment schedule

---

*For technical details, see the full technical report*
"""
    
    def _generate_enhanced_html_report(self) -> str:
        """Generate enhanced HTML report with charts and interactivity"""
        # Calculate statistics
        severity_counts = {}
        for finding in self.findings:
            severity = finding.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Report - {self.target}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #007acc;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }}
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            display: block;
        }}
        .finding {{
            border: 1px solid #ddd;
            margin: 20px 0;
            padding: 20px;
            border-radius: 8px;
            background: #fafafa;
        }}
        .severity-critical {{ border-left: 5px solid #dc3545; }}
        .severity-high {{ border-left: 5px solid #fd7e14; }}
        .severity-medium {{ border-left: 5px solid #ffc107; }}
        .severity-low {{ border-left: 5px solid #28a745; }}
        .severity-info {{ border-left: 5px solid #17a2b8; }}
        .chain {{
            background: linear-gradient(135deg, #ff9a9e 0%, #fecfef 100%);
            border-radius: 10px;
            padding: 20px;
            margin: 15px 0;
        }}
        .code {{
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 5px;
            padding: 15px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
        }}
        .badge {{
            display: inline-block;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 0.8em;
            font-weight: bold;
            margin: 5px;
        }}
        .badge-aggressive {{ background: #dc3545; color: white; }}
        .badge-scope {{ background: #28a745; color: white; }}
        .badge-platform {{ background: #007acc; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 Enhanced Bug Bounty Report</h1>
            <h2>{self.target}</h2>
            <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <div>
                {f'<span class="badge badge-platform">Platform: {self.program_info.get("platform")}</span>' if self.program_info.get("platform") else ''}
                {f'<span class="badge badge-platform">Program: {self.program_info.get("handle")}</span>' if self.program_info.get("handle") else ''}
                {'<span class="badge badge-aggressive">Aggressive Mode</span>' if self.aggressive_mode else ''}
                {'<span class="badge badge-scope">Scope Validated</span>' if self.scope_validation_enabled else ''}
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <span class="stat-number">{len(self.findings)}</span>
                <span>Vulnerabilities Found</span>
            </div>
            <div class="stat-card">
                <span class="stat-number">{len(self.chains)}</span>
                <span>Attack Chains</span>
            </div>
            <div class="stat-card">
                <span class="stat-number">{severity_counts.get('critical', 0) + severity_counts.get('high', 0)}</span>
                <span>Critical + High</span>
            </div>
            <div class="stat-card">
                <span class="stat-number">{self.session_data.get('javascript_analysis', {}).get('js_files_found', 0)}</span>
                <span>JS Files Analyzed</span>
            </div>
        </div>
        
        {f'<h2>🏪 Program Information</h2><div class="code">Platform: {self.program_info.get("platform", "N/A")}<br>Handle: {self.program_info.get("handle", "N/A")}<br>Bounty Range: {self.program_info.get("bounty_range", "N/A")}<br>Scope Items: {len(self.program_info.get("scope", {}).get("in_scope", []))}</div>' if self.program_info else ''}
        
        <h2>🚨 Vulnerabilities</h2>
        {''.join(f'<div class="finding severity-{finding.get("severity", "unknown")}"><h3>{finding.get("type", "Unknown Vulnerability")}</h3><p><strong>URL:</strong> {finding.get("url", "Unknown")}</p><p><strong>Severity:</strong> {finding.get("severity", "Unknown").title()}</p><p><strong>Discovery Method:</strong> {finding.get("discovery_method", "Unknown")}</p>{f"<p><strong>WAF Detected:</strong> {finding.get('waf_info', {}).get('type', 'None')}</p>" if finding.get('waf_detected') else ""}{f"<p><strong>Evasion Technique:</strong> {finding.get('evasion_technique')}</p>" if finding.get('evasion_technique') else ""}<div class="code">{finding.get("evidence", "No evidence available")}</div></div>' for finding in self.findings) if self.findings else '<p>No vulnerabilities found.</p>'}
        
        <h2>⛓️ Attack Chains</h2>
        {''.join(f'<div class="chain"><h3>{chain.get("name", "Unknown Chain")}</h3><p>{chain.get("description", "No description available")}</p><p><strong>Impact:</strong> {chain.get("impact", "Unknown")}</p></div>' for chain in self.chains) if self.chains else '<p>No attack chains identified.</p>'}
        
        <h2>📊 Testing Summary</h2>
        <div class="code">
            Testing Mode: {'Aggressive (WAF Evasion Enabled)' if self.aggressive_mode else 'Standard'}<br>
            Scope Validation: {'Enabled' if self.scope_validation_enabled else 'Disabled'}<br>
            Total Endpoints Tested: {len(self.session_data.get('endpoints', []))}<br>
            JavaScript Files Analyzed: {self.session_data.get('javascript_analysis', {}).get('js_files_found', 0)}<br>
            Workspace: {self.workspace}
        </div>
        
        <div style="margin-top: 40px; padding: 20px; background: #e3f2fd; border-radius: 8px;">
            <h3>⚠️ Important Notes</h3>
            <ul>
                <li>This report was generated automatically - manual verification is recommended</li>
                <li>All findings should be validated before submission to bug bounty programs</li>
                <li>Ensure you have proper authorization before testing any targets</li>
                {'<li>Aggressive testing mode was used - some requests may have triggered security alerts</li>' if self.aggressive_mode else ''}
                {'<li>Scope validation was enabled - only in-scope targets were tested</li>' if self.scope_validation_enabled else '<li>⚠️ Scope validation was disabled - ensure all testing was authorized</li>'}
            </ul>
        </div>
    </div>
</body>
</html>"""
    
    # Keep existing helper methods from original implementation
    def _find_subdomains(self) -> List[str]:
        """Find subdomains using multiple techniques"""
        # Same implementation as original
        subdomains = set()
        
        # Using subfinder if available
        try:
            result = subprocess.run(
                ["subfinder", "-d", self.target, "-silent"],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                subdomains.update(result.stdout.strip().split('\n'))
        except:
            pass
        
        # Using amass if available
        try:
            result = subprocess.run(
                ["amass", "enum", "-passive", "-d", self.target],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode == 0:
                subdomains.update(result.stdout.strip().split('\n'))
        except:
            pass
        
        # DNS bruteforce with common subdomains
        common_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'test', 'dev', 'staging']
        for sub in common_subs:
            try:
                import socket
                socket.gethostbyname(f"{sub}.{self.target}")
                subdomains.add(f"{sub}.{self.target}")
            except:
                pass
        
        return list(subdomains)[:20]  # Limit results
    
    def _discover_content(self, target: str) -> List[Dict]:
        """Discover content on target"""
        # Same implementation as original
        endpoints = []
        
        # Basic directory discovery
        common_paths = [
            '/', '/admin', '/api', '/login', '/dashboard', '/config',
            '/backup', '/test', '/dev', '/staging', '/uploads',
            '/files', '/docs', '/swagger', '/graphql', '/robots.txt',
            '/sitemap.xml', '/.env', '/.git', '/wp-admin'
        ]
        
        for path in common_paths:
            url = f"https://{target}{path}"
            try:
                response = requests.get(url, timeout=10, verify=False)
                endpoints.append({
                    "url": url,
                    "status": response.status_code,
                    "length": len(response.content),
                    "title": self._extract_title(response.text)
                })
            except:
                pass
        
        return endpoints
    
    def _ai_classify_endpoints(self, endpoints: List[Dict]) -> List[Dict]:
        """Use AI to classify interesting endpoints"""
        # Same implementation as original
        if not endpoints:
            return []
            
        prompt = f"""
        Analyze these discovered endpoints and identify the most interesting ones for bug bounty hunting:
        
        {json.dumps(endpoints[:50], indent=2)}
        
        Return the top 10 most interesting endpoints with:
        - vulnerability types likely to be found
        - attack vectors to try
        - priority level (1-10)
        
        Focus on admin panels, APIs, file uploads, authentication, etc.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.5
            )
            
            result = json.loads(response.choices[0].message.content)
            return result.get("interesting_endpoints", [])
            
        except Exception as e:
            logger.error(f"AI endpoint classification failed: {e}")
            return endpoints[:10]  # Fallback to first 10
    
    def _generate_ai_payloads(self, endpoint: Dict) -> List[Dict]:
        """Generate AI-powered test payloads for an endpoint"""
        # Same implementation as original
        prompt = f"""
        Generate test payloads for this endpoint:
        URL: {endpoint['url']}
        Status: {endpoint.get('status')}
        Context: {endpoint.get('title', '')}
        
        Generate 5-10 targeted payloads for:
        - XSS (reflected, stored, DOM)
        - SQL injection 
        - Command injection
        - Path traversal
        - SSRF
        - Authentication bypass
        
        Return JSON array of payloads with type, parameter, and payload.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.8
            )
            
            result = json.loads(response.choices[0].message.content)
            return result.get("payloads", [])
            
        except Exception as e:
            logger.error(f"AI payload generation failed: {e}")
            return []
    
    def _extract_title(self, html: str) -> str:
        """Extract title from HTML"""
        # Same implementation as original
        try:
            import re
            match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
            return match.group(1) if match else ""
        except:
            return ""
    
    def _save_session(self):
        """Save session data"""
        session_file = self.workspace / "session.json"
        with open(session_file, 'w') as f:
            json.dump(self.session_data, f, indent=2, default=str)

def main():
    parser = argparse.ArgumentParser(description="Enhanced Personal Bug Bounty Assistant")
    parser.add_argument("target", help="Target domain to hunt")
    parser.add_argument("--api-key", help="OpenAI API key (or set OPENAI_API_KEY env var)")
    parser.add_argument("--platform", choices=['hackerone', 'bugcrowd'], help="Bug bounty platform")
    parser.add_argument("--program", help="Program handle on the platform")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--aggressive", action="store_true", help="Enable aggressive testing with WAF evasion")
    parser.add_argument("--no-scope-validation", action="store_true", help="Disable scope validation")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Get API key
    api_key = args.api_key or os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("❌ OpenAI API key required. Set OPENAI_API_KEY env var or use --api-key")
        sys.exit(1)
    
    # Load configuration
    config = {}
    if args.config and Path(args.config).exists():
        with open(args.config, 'r') as f:
            if args.config.endswith('.json'):
                config = json.load(f)
            else:  # YAML
                import yaml
                config = yaml.safe_load(f)
    
    # Override config with CLI arguments
    if args.aggressive:
        config.setdefault('aggressive_testing', {})['enabled'] = True
    
    if args.no_scope_validation:
        config.setdefault('scope_validation', {})['enabled'] = False
    
    # Initialize enhanced assistant
    assistant = EnhancedBugBountyAssistant(api_key, config)
    
    try:
        # Run the enhanced hunt
        result = assistant.run_full_enhanced_hunt(args.target, args.platform, args.program)
        
        if result['success']:
            print(f"\n🎉 Enhanced hunt completed successfully!")
            print(f"📋 Results: {result}")
        else:
            print(f"\n❌ Enhanced hunt failed: {result.get('error')}")
            sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n⚠️ Hunt interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Hunt failed with exception: {e}")
        logger.exception("Hunt failed with exception")
        sys.exit(1)

if __name__ == "__main__":
    main()
