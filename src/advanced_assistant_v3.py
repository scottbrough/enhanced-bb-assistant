#!/usr/bin/env python3
"""
Enhanced Personal Bug Bounty Assistant v3.0
Complete AI-powered bug bounty automation with revenue maximization
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
import asyncio
import threading

# Import all modules
from platform_integration import PlatformIntegration, ScopeValidator
from aggressive_testing_waf_evasion import WAFEvasionTester, WAF_CONTINGENCY_GUIDE
from enhanced_vulnerability_testing import EnhancedVulnerabilityTester
from js_analysis_module import JavaScriptAnalyzer
from revenue_maximizer import RevenueMaximizer, CollaborationManager, AutoSubmitter
from continuous_monitor import ContinuousMonitor, ProgramWatcher
from api_testing_module import APITester

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"bb_hunt_{datetime.now().strftime('%Y%m%d')}.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("enhanced_bb_assistant_v3")

class EnhancedBugBountyAssistantV3:
    """Enhanced Personal Bug Bounty Assistant with Revenue Maximization"""
    
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
        
        # Initialize all modules
        self.platform_integration = PlatformIntegration(self.config)
        self.vuln_tester = EnhancedVulnerabilityTester()
        self.aggressive_tester = WAFEvasionTester(self.config)
        self.js_analyzer = JavaScriptAnalyzer(self.client)
        self.api_tester = APITester(self.config)
        
        # Initialize revenue maximization modules
        self.revenue_maximizer = RevenueMaximizer()
        self.collaboration_manager = CollaborationManager()
        self.auto_submitter = AutoSubmitter(self.revenue_maximizer)
        self.continuous_monitor = ContinuousMonitor()
        self.program_watcher = ProgramWatcher(self.continuous_monitor)
        
        # Testing configuration
        self.aggressive_mode = self.config.get('aggressive_testing', {}).get('enabled', True)
        self.scope_validation_enabled = self.config.get('scope_validation', {}).get('enabled', True)
        self.auto_submit_enabled = self.config.get('auto_submit', {}).get('enabled', False)
        self.continuous_monitoring = self.config.get('continuous_monitoring', {}).get('enabled', True)
        
        # Start continuous monitoring if enabled
        if self.continuous_monitoring:
            self.continuous_monitor.start_monitoring()
        
        # Add notification handler for monitoring
        self.continuous_monitor.add_notification_handler(self._handle_monitoring_notification)
        
        logger.info("🚀 Enhanced Bug Bounty Assistant v3.0 initialized")
        logger.info("💰 Revenue maximization features enabled")
        
    def initialize_hunt(self, target: str, platform: str = None, program_handle: str = None):
        """Initialize enhanced hunt with revenue optimization"""
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
                # Use revenue maximizer to pick best program
                prioritized = self.revenue_maximizer.prioritize_targets(intelligence['programs_found'])
                if prioritized:
                    self.program_info = prioritized[0]
                    logger.info(f"💡 Selected optimal program: {self.program_info.get('handle')} on {self.program_info.get('platform')} (ROI score: {self.program_info.get('roi_score', 0):.2f})")
                    if self.scope_validation_enabled:
                        self.scope_validator = ScopeValidator(self.program_info)
        
        # Add target to continuous monitoring
        if self.continuous_monitoring and self.program_info:
            self.continuous_monitor.add_monitoring_target(
                target, 
                self.program_info.get('platform'),
                self.program_info.get('handle')
            )
        
        # Check if we've tested this target recently
        recent_changes = self.continuous_monitor.get_recent_changes(24)
        if recent_changes:
            logger.info(f"🔄 Found {len(recent_changes)} recent changes on monitored targets")
        
        # Get revenue analytics
        analytics = self.revenue_maximizer.get_earnings_analytics()
        if analytics['total_earnings'] > 0:
            logger.info(f"💵 Career earnings: ${analytics['total_earnings']:.2f}")
            logger.info(f"📈 Success rate: {analytics['success_rate']*100:.1f}%")
            logger.info(f"⏱️ Hourly rate: ${analytics['hourly_rate']:.2f}/hr")
        
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
            "scope_validation": self.scope_validation_enabled,
            "roi_score": self.program_info.get('roi_score', 0) if self.program_info else 0,
            "expected_earnings": self._estimate_earnings()
        }
        self._save_session()
        
    def _estimate_earnings(self) -> float:
        """Estimate potential earnings for this hunt"""
        if not self.program_info:
            return 0.0
        
        # Base estimate on program bounty range and historical success
        bounty_range = self.program_info.get('bounty_range', '')
        amounts = self.revenue_maximizer._extract_amounts(bounty_range)
        
        if amounts:
            avg_bounty = sum(amounts) / len(amounts)
            # Adjust by historical success rate
            analytics = self.revenue_maximizer.get_earnings_analytics()
            success_rate = analytics.get('success_rate', 0.1)
            
            # Estimate 5-10 findings
            estimated_findings = 7 * success_rate
            return avg_bounty * estimated_findings
        
        return 0.0
    
    def ai_target_analysis(self) -> Dict:
        """Enhanced AI-powered target analysis with revenue optimization"""
        logger.info("🧠 Analyzing target with AI...")
        
        # Get revenue optimization data
        revenue_data = ""
        if self.program_info:
            roi_score = self.program_info.get('roi_score', 0)
            revenue_data = f"""
            Revenue Analysis:
            - ROI Score: {roi_score:.2f}
            - Expected Earnings: ${self.session_data.get('expected_earnings', 0):.2f}
            - Competition Level: {self._assess_competition_level()}
            - Testing Schedule: {self.revenue_maximizer.optimize_testing_schedule().get('recommendations', [])}
            """
        
        # Check for recent changes
        recent_changes = self.continuous_monitor.get_recent_changes(168)  # Last week
        changes_context = ""
        if recent_changes:
            changes_context = f"""
            Recent Changes Detected:
            - {len(recent_changes)} changes in the last week
            - Focus on: {', '.join(set(c['change_type'] for c in recent_changes[:5]))}
            """
        
        prompt = f"""
        You are an expert bug bounty hunter analyzing a new target: {self.target}
        
        {self._get_program_context()}
        {revenue_data}
        {changes_context}
        
        Provide a comprehensive analysis including:
        1. Technology stack predictions based on domain/subdomain patterns
        2. Likely attack vectors to prioritize based on ROI
        3. API endpoints likely to exist (REST, GraphQL, etc)
        4. Mobile app API detection strategies
        5. Areas most likely to yield high-bounty findings
        6. Time-efficient testing approach (maximize $/hour)
        7. Collaboration opportunities (which findings to share)
        8. WAF detection expectations and evasion strategy
        9. Quick win opportunities (low effort, high reward)
        10. Long-term monitoring recommendations
        
        Focus on maximizing earnings per hour spent.
        
        Return your analysis as a JSON object with structured recommendations.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.7
            )
            
            analysis = json.loads(response.choices[0].message.content)
            
            # Add revenue insights
            analysis['revenue_optimization'] = {
                'roi_score': self.program_info.get('roi_score', 0) if self.program_info else 0,
                'expected_hourly_rate': self._calculate_expected_hourly_rate(),
                'optimal_testing_hours': self.revenue_maximizer.optimize_testing_schedule().get('best_hours', []),
                'quick_wins': self._identify_quick_wins(analysis)
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
        """Enhanced reconnaissance with API discovery and revenue focus"""
        logger.info("🔍 Starting intelligent reconnaissance...")
        
        recon_results = {
            "subdomains": [],
            "endpoints": [],
            "apis": {
                "rest": [],
                "graphql": [],
                "websocket": [],
                "grpc": []
            },
            "technologies": [],
            "interesting_findings": [],
            "javascript_analysis": {},
            "scope_validation": {
                "in_scope_targets": [],
                "out_of_scope_targets": [],
                "validation_enabled": self.scope_validation_enabled
            },
            "revenue_potential": {}
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
        
        # API Discovery
        logger.info("🔍 Discovering APIs...")
        for subdomain in recon_results["subdomains"][:10]:  # Limit for performance
            api_info = self.api_tester.detect_api_type(f"https://{subdomain}")
            if api_info['type'] != 'unknown':
                recon_results["apis"][api_info['type']].append({
                    'subdomain': subdomain,
                    'info': api_info
                })
                logger.info(f"🎯 Found {api_info['type']} API on {subdomain}")
        
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
        
        # AI-powered endpoint analysis with revenue focus
        logger.info("🧠 AI analyzing discovered endpoints...")
        interesting_endpoints = self._ai_classify_endpoints_revenue_focused(recon_results["endpoints"])
        recon_results["interesting_findings"] = interesting_endpoints
        
        # Enhanced JavaScript analysis
        logger.info("🔍 Analyzing JavaScript files...")
        js_analysis = self.js_analyzer.discover_and_analyze_js(self.target, recon_results["endpoints"])
        recon_results["javascript_analysis"] = js_analysis
        
        # Calculate revenue potential
        recon_results["revenue_potential"] = self._calculate_recon_revenue_potential(recon_results)
        
        # Save recon results
        recon_file = self.workspace / "recon_results.json"
        with open(recon_file, 'w') as f:
            json.dump(recon_results, f, indent=2)
            
        logger.info(f"✅ Enhanced recon complete: {len(recon_results['endpoints'])} endpoints, {sum(len(v) for v in recon_results['apis'].values())} APIs")
        return recon_results
    
    def ai_vulnerability_hunting(self, recon_data: Dict) -> List[Dict]:
        """Enhanced vulnerability hunting with revenue optimization"""
        logger.info("🎯 Starting enhanced vulnerability hunting...")
        
        findings = []
        tested_count = 0
        start_time = time.time()
        
        # Prioritize high-value targets
        interesting_endpoints = recon_data.get("interesting_findings", [])
        prioritized_endpoints = self._prioritize_endpoints_by_value(interesting_endpoints)
        
        # Test APIs first (usually higher bounties)
        for api_type, apis in recon_data.get("apis", {}).items():
            for api_info in apis:
                if api_type == 'graphql':
                    graphql_findings = self.api_tester.test_graphql_vulnerabilities(
                        api_info['info']['documentation_url']
                    )
                    findings.extend(graphql_findings)
                elif api_type == 'rest':
                    api_findings = self.api_tester.test_api_endpoints(
                        f"https://{api_info['subdomain']}",
                        self.api_tester.discovered_endpoints
                    )
                    findings.extend(api_findings)
                
                tested_count += 1
        
        # Test prioritized endpoints
        for endpoint in prioritized_endpoints[:20]:  # Limit for time efficiency
            logger.info(f"Testing: {endpoint['url']} (value score: {endpoint.get('value_score', 0):.2f})")
            
            # Check for duplicates before testing
            endpoint_findings = []
            
            # Generate AI-powered test payloads
            payloads = self._generate_ai_payloads(endpoint)
            
            # Test each payload
            for payload_data in payloads:
                # Check if similar vulnerability already reported
                is_duplicate, dup_info = self.revenue_maximizer.check_duplicate({
                    'type': payload_data.get('type'),
                    'url': endpoint['url'],
                    'parameter': payload_data.get('parameter')
                })
                
                if is_duplicate:
                    logger.warning(f"⚠️ Skipping potential duplicate: {payload_data.get('type')} on {endpoint['url']}")
                    continue
                
                if self.aggressive_mode:
                    result = self.aggressive_tester.test_payload_aggressive(endpoint['url'], payload_data)
                else:
                    result = self.vuln_tester.test_payload(endpoint['url'], payload_data)
                
                if result.get('vulnerable'):
                    result['discovery_method'] = 'endpoint_analysis'
                    result['estimated_bounty'] = self._estimate_finding_value(result)
                    endpoint_findings.append(result)
                    logger.info(f"🚨 Vulnerability found: {result['type']} in {endpoint['url']} (est. ${result['estimated_bounty']})")
            
            # Only add findings if they're worth reporting
            valuable_findings = [f for f in endpoint_findings if f.get('estimated_bounty', 0) > 50]
            findings.extend(valuable_findings)
            
            tested_count += 1
            
            # Time management - stop if taking too long
            elapsed_time = time.time() - start_time
            if elapsed_time > 3600:  # 1 hour limit
                logger.info("⏱️ Time limit reached, stopping vulnerability hunting")
                break
        
        # Test authentication if found
        auth_findings = self._test_authentication_endpoints(recon_data)
        findings.extend(auth_findings)
        
        # Calculate testing efficiency
        testing_time = time.time() - start_time
        findings_value = sum(f.get('estimated_bounty', 0) for f in findings)
        hourly_rate = (findings_value / testing_time) * 3600 if testing_time > 0 else 0
        
        logger.info(f"💰 Testing efficiency: ${hourly_rate:.2f}/hour")
        
        self.findings = findings
        
        # Save findings with revenue data
        findings_file = self.workspace / "findings.json"
        with open(findings_file, 'w') as f:
            json.dump({
                'findings': findings,
                'testing_metrics': {
                    'endpoints_tested': tested_count,
                    'time_spent_seconds': testing_time,
                    'estimated_value': findings_value,
                    'hourly_rate': hourly_rate
                }
            }, f, indent=2)
            
        logger.info(f"✅ Enhanced vulnerability hunting complete: {len(findings)} findings worth ~${findings_value:.2f}")
        return findings
    
    def ai_chain_detection(self) -> List[Dict]:
        """Enhanced chain detection with bounty value estimation"""
        if not self.findings:
            logger.info("No findings to chain")
            return []
            
        logger.info("🔗 Analyzing vulnerability chains with AI...")
        
        prompt = f"""
        You are an expert bug bounty hunter analyzing vulnerabilities for potential chaining.
        Focus on chains that would maximize bounty payouts.
        
        Target: {self.target}
        {self._get_program_context()}
        
        Findings: {json.dumps(self.findings, indent=2)}
        
        Analyze these findings and identify:
        1. High-impact attack chains (prioritize critical business impact)
        2. Account takeover chains (usually highest bounties)
        3. Data exfiltration scenarios (PII = high bounties)
        4. Payment/financial system chains
        5. Admin access chains
        6. Cross-origin attack chains
        
        For each chain, provide:
        - Chain name and description
        - Step-by-step attack path
        - Business impact (focus on financial/data loss)
        - Estimated bounty range (based on similar reports)
        - Proof of concept outline
        - CVSS score estimation
        
        Prioritize chains by potential bounty value.
        
        Return as JSON object with 'chains' array.
        """
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}],
                response_format={"type": "json_object"},
                temperature=0.7
            )
            
            result = json.loads(response.choices[0].message.content)
            chains = result.get("chains", [])
            
            # Add bounty estimates
            for chain in chains:
                chain['estimated_bounty'] = self._estimate_chain_value(chain)
            
            # Sort by estimated value
            chains = sorted(chains, key=lambda x: x.get('estimated_bounty', 0), reverse=True)
            
            self.chains = chains
            
            # Save chains
            chains_file = self.workspace / "vulnerability_chains.json"
            with open(chains_file, 'w') as f:
                json.dump(chains, f, indent=2)
                
            logger.info(f"✅ Chain analysis complete: {len(chains)} chains worth ~${sum(c.get('estimated_bounty', 0) for c in chains):.2f}")
            return chains
            
        except Exception as e:
            logger.error(f"❌ Chain analysis failed: {e}")
            return []
    
    def auto_submit_findings(self) -> Dict:
        """Automatically submit validated findings"""
        logger.info("📤 Processing findings for submission...")
        
        submission_results = {
            'submitted': [],
            'queued': [],
            'rejected': [],
            'total_value': 0
        }
        
        # Process individual findings
        for finding in self.findings:
            if self.auto_submit_enabled and finding.get('confidence') == 'high':
                result = self.auto_submitter.queue_for_submission(
                    finding,
                    self.program_info,
                    self.platform_integration,
                    auto_submit=True
                )
                
                if result and result.get('success'):
                    submission_results['submitted'].append(result)
                    submission_results['total_value'] += finding.get('estimated_bounty', 0)
                else:
                    submission_results['queued'].append(finding)
            else:
                submission_results['queued'].append(finding)
        
        # Process high-value chains
        for chain in self.chains:
            if chain.get('estimated_bounty', 0) > 1000:
                # High-value chains always need manual review
                submission_results['queued'].append({
                    'type': 'chain',
                    'data': chain,
                    'reason': 'High-value chain requires manual review'
                })
        
        logger.info(f"📊 Submission summary: {len(submission_results['submitted'])} auto-submitted, {len(submission_results['queued'])} queued")
        
        return submission_results
    
    def generate_revenue_report(self) -> str:
        """Generate comprehensive revenue and efficiency report"""
        logger.info("💰 Generating revenue report...")
        
        # Get analytics
        analytics = self.revenue_maximizer.get_earnings_analytics()
        schedule = self.revenue_maximizer.optimize_testing_schedule()
        
        # Calculate hunt metrics
        hunt_duration = time.time() - time.mktime(time.strptime(self.session_data['start_time'], "%Y-%m-%dT%H:%M:%S.%f"))
        findings_value = sum(f.get('estimated_bounty', 0) for f in self.findings)
        chains_value = sum(c.get('estimated_bounty', 0) for c in self.chains)
        total_potential = findings_value + chains_value
        
        report = f"""# Revenue Report - {self.target}

## Hunt Summary
- **Duration:** {hunt_duration/3600:.1f} hours
- **Findings:** {len(self.findings)} vulnerabilities
- **Chains:** {len(self.chains)} attack chains
- **Potential Value:** ${total_potential:.2f}
- **Efficiency:** ${(total_potential/hunt_duration)*3600:.2f}/hour

## Career Statistics
- **Total Earnings:** ${analytics['total_earnings']:.2f}
- **Success Rate:** {analytics['success_rate']*100:.1f}%
- **Average Hourly Rate:** ${analytics['hourly_rate']:.2f}/hour
- **Best Platform:** {max(analytics['earnings_by_platform'].items(), key=lambda x: x[1])[0] if analytics['earnings_by_platform'] else 'N/A'}

## Top Earning Vulnerability Types
{chr(10).join(f"- {vtype}: ${amount:.2f} ({count} findings)" for vtype, amount, count in analytics['earnings_by_type'][:5])}

## Optimal Testing Schedule
- **Best Hours:** {', '.join(schedule['best_hours'])}
- **Best Days:** {', '.join(schedule['best_days'])}

## Recommendations
{chr(10).join(f"- {rec}" for rec in analytics['recommendations'])}

## Next Target Suggestion
{self._get_next_target_suggestion()}
"""
        
        # Save report
        revenue_report_file = self.workspace / "revenue_report.md"
        with open(revenue_report_file, 'w') as f:
            f.write(report)
        
        return report
    
    def run_full_enhanced_hunt(self, target: str, platform: str = None, program_handle: str = None) -> Dict:
        """Run the complete enhanced bug bounty hunting workflow with revenue optimization"""
        start_time = time.time()
        
        try:
            # Initialize with platform integration
            self.initialize_hunt(target, platform, program_handle)
            
            # Check if target is worth testing
            if self.program_info and self.program_info.get('roi_score', 0) < 10:
                logger.warning(f"⚠️ Low ROI score ({self.program_info.get('roi_score', 0):.2f}) - consider different target")
            
            # Display revenue optimization info
            if self.revenue_maximizer:
                next_target = self.revenue_maximizer.suggest_next_target([self.program_info]) if self.program_info else None
                if next_target and next_target != self.program_info:
                    logger.info(f"💡 Consider testing {next_target['handle']} instead (ROI: {next_target.get('roi_score', 0):.2f})")
            
            # Phase 1: Enhanced AI Analysis
            analysis = self.ai_target_analysis()
            print(f"\n🎯 Enhanced Target Analysis Complete")
            if analysis.get('revenue_optimization'):
                rev_opt = analysis['revenue_optimization']
                print(f"   💰 Expected hourly rate: ${rev_opt.get('expected_hourly_rate', 0):.2f}/hr")
                print(f"   🎯 Quick wins identified: {len(rev_opt.get('quick_wins', []))}")
            
            # Phase 2: Enhanced Reconnaissance
            recon_data = self.intelligent_recon()
            print(f"\n🔍 Enhanced Reconnaissance Complete")
            print(f"   🌐 Subdomains: {len(recon_data['subdomains'])}")
            print(f"   🔗 Endpoints: {len(recon_data['endpoints'])}")
            print(f"   🚀 APIs found: {sum(len(v) for v in recon_data['apis'].values())}")
            
            # Phase 3: Revenue-Optimized Vulnerability Hunting
            findings = self.ai_vulnerability_hunting(recon_data)
            print(f"\n🎯 Vulnerability Hunting Complete")
            print(f"   🚨 Findings: {len(findings)}")
            print(f"   💵 Estimated value: ${sum(f.get('estimated_bounty', 0) for f in findings):.2f}")
            
            # Phase 4: Chain Detection
            chains = self.ai_chain_detection()
            print(f"\n🔗 Chain Analysis Complete")
            print(f"   ⛓️ Chains: {len(chains)}")
            print(f"   💰 Chain value: ${sum(c.get('estimated_bounty', 0) for c in chains):.2f}")
            
            # Phase 5: Auto-submission
            submission_results = self.auto_submit_findings()
            print(f"\n📤 Submission Processing Complete")
            print(f"   ✅ Auto-submitted: {len(submission_results['submitted'])}")
            print(f"   📋 Queued for review: {len(submission_results['queued'])}")
            
            # Phase 6: Revenue Report
            revenue_report = self.generate_revenue_report()
            
            # Phase 7: Collaboration Check
            collab_opportunities = self._identify_collaboration_opportunities()
            if collab_opportunities:
                print(f"\n🤝 Collaboration Opportunities: {len(collab_opportunities)}")
            
            # Final summary
            duration = time.time() - start_time
            total_value = sum(f.get('estimated_bounty', 0) for f in findings) + sum(c.get('estimated_bounty', 0) for c in chains)
            
            print(f"\n🎉 Enhanced Hunt Complete!")
            print(f"   ⏱️ Duration: {duration/60:.1f} minutes")
            print(f"   💰 Potential earnings: ${total_value:.2f}")
            print(f"   📈 Efficiency: ${(total_value/duration)*3600:.2f}/hour")
            print(f"   📁 Workspace: {self.workspace}")
            
            # Next steps
            print(f"\n📋 Next Steps:")
            print(f"   1. Review queued submissions in {self.workspace}")
            print(f"   2. Submit high-confidence findings immediately")
            if collab_opportunities:
                print(f"   3. Consider collaboration on complex findings")
            print(f"   4. Monitor target for changes (auto-enabled)")
            
            # Return comprehensive results
            return {
                'success': True,
                'target': target,
                'duration_minutes': duration / 60,
                'findings_count': len(findings),
                'chains_count': len(chains),
                'potential_earnings': total_value,
                'hourly_rate': (total_value/duration)*3600 if duration > 0 else 0,
                'workspace': str(self.workspace),
                'program_info': self.program_info,
                'submission_results': submission_results,
                'roi_score': self.program_info.get('roi_score', 0) if self.program_info else 0
            }
            
        except Exception as e:
            logger.error(f"❌ Enhanced hunt failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'workspace': str(self.workspace) if self.workspace else None
            }
    
    # Helper methods
    def _get_program_context(self) -> str:
        """Get program context for prompts"""
        if not self.program_info:
            return ""
        
        return f"""
        Program Information:
        - Platform: {self.program_info.get('platform')}
        - Program: {self.program_info.get('name', self.program_info.get('handle'))}
        - Bounty Range: {self.program_info.get('bounty_range', 'Unknown')}
        - Scope: {len(self.program_info.get('scope', {}).get('in_scope', []))} targets in scope
        - Managed: {self.program_info.get('managed', False)}
        """
    
    def _calculate_expected_hourly_rate(self) -> float:
        """Calculate expected hourly rate for this target"""
        analytics = self.revenue_maximizer.get_earnings_analytics()
        base_rate = analytics.get('hourly_rate', 50)
        
        # Adjust based on program characteristics
        if self.program_info:
            if self.program_info.get('managed'):
                base_rate *= 1.2  # Managed programs typically pay faster
            
            roi_score = self.program_info.get('roi_score', 50)
            rate_multiplier = roi_score / 50  # Normalize around average
            
            return base_rate * rate_multiplier
        
        return base_rate
    
    def _identify_quick_wins(self, analysis: Dict) -> List[Dict]:
        """Identify quick win opportunities"""
        quick_wins = []
        
        # Default quick wins
        quick_win_patterns = [
            {'type': 'Exposed API docs', 'endpoint': '/swagger', 'effort': 'low', 'bounty': 'medium'},
            {'type': 'GraphQL introspection', 'endpoint': '/graphql', 'effort': 'low', 'bounty': 'medium'},
            {'type': 'Exposed .git', 'endpoint': '/.git/config', 'effort': 'low', 'bounty': 'medium'},
            {'type': 'API key in JS', 'endpoint': '/js/', 'effort': 'low', 'bounty': 'high'},
            {'type': 'Default credentials', 'endpoint': '/admin', 'effort': 'low', 'bounty': 'high'}
        ]
        
        return quick_win_patterns[:3]
    
    def _prioritize_endpoints_by_value(self, endpoints: List[Dict]) -> List[Dict]:
        """Prioritize endpoints by potential bounty value"""
        for endpoint in endpoints:
            score = 0
            url = endpoint.get('url', '').lower()
            
            # High-value patterns
            if any(pattern in url for pattern in ['admin', 'payment', 'auth', 'api/user']):
                score += 10
            if any(pattern in url for pattern in ['upload', 'file', 'import']):
                score += 8
            if any(pattern in url for pattern in ['graphql', 'api/v']):
                score += 7
            if any(pattern in url for pattern in ['config', 'setting', 'account']):
                score += 5
            
            endpoint['value_score'] = score
        
        return sorted(endpoints, key=lambda x: x.get('value_score', 0), reverse=True)
    
    def _estimate_finding_value(self, finding: Dict) -> float:
        """Estimate bounty value for a finding"""
        if not self.program_info:
            return 100  # Default estimate
        
        # Base values by severity
        base_values = {
            'critical': 2000,
            'high': 800,
            'medium': 300,
            'low': 100,
            'info': 0
        }
        
        severity = finding.get('severity', 'medium')
        base_value = base_values.get(severity, 100)
        
        # Adjust by vulnerability type
        vuln_type = finding.get('type', '').lower()
        if 'rce' in vuln_type or 'remote code' in vuln_type:
            base_value *= 2.5
        elif 'sql' in vuln_type:
            base_value *= 1.8
        elif 'ssrf' in vuln_type:
            base_value *= 1.5
        elif 'xss' in vuln_type and 'stored' in vuln_type:
            base_value *= 1.3
        
        # Adjust by program bounty range
        bounty_range = self.program_info.get('bounty_range', '')
        if '$10000' in bounty_range or '$20000' in bounty_range:
            base_value *= 2
        elif '$5000' in bounty_range:
            base_value *= 1.5
        
        return base_value
    
    def _estimate_chain_value(self, chain: Dict) -> float:
        """Estimate bounty value for a vulnerability chain"""
        # Chains typically pay 2-3x individual vulnerabilities
        impact = chain.get('impact', '').lower()
        
        if 'takeover' in impact or 'account' in impact:
            return 5000
        elif 'data' in impact or 'exfiltration' in impact:
            return 3000
        elif 'privilege' in impact or 'escalation' in impact:
            return 2000
        else:
            return 1000
    
    def _calculate_recon_revenue_potential(self, recon_data: Dict) -> Dict:
        """Calculate revenue potential from recon data"""
        potential = {
            'endpoints_value': len(recon_data['endpoints']) * 10,
            'apis_value': sum(len(v) for v in recon_data['apis'].values()) * 100,
            'js_secrets_value': len(recon_data.get('javascript_analysis', {}).get('secrets_found', [])) * 200,
            'total_potential': 0
        }
        
        potential['total_potential'] = sum(v for k, v in potential.items() if k != 'total_potential')
        
        return potential
    
    def _test_authentication_endpoints(self, recon_data: Dict) -> List[Dict]:
        """Test authentication endpoints for high-value vulnerabilities"""
        findings = []
        auth_endpoints = []
        
        # Find auth endpoints
        for endpoint in recon_data.get('endpoints', []):
            url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
            if any(pattern in url.lower() for pattern in ['login', 'auth', 'signin', 'oauth', 'token']):
                auth_endpoints.append(url)
        
        # Test each auth endpoint
        for auth_url in auth_endpoints[:5]:  # Limit for efficiency
            # Detect auth type
            parsed_url = requests.utils.urlparse(auth_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            api_info = self.api_tester.detect_api_type(base_url)
            auth_findings = self.api_tester.test_authentication_vulnerabilities(
                base_url, 
                api_info.get('auth_type', 'unknown')
            )
            
            for finding in auth_findings:
                finding['estimated_bounty'] = self._estimate_finding_value(finding)
            
            findings.extend(auth_findings)
        
        return findings
    
    def _identify_collaboration_opportunities(self) -> List[Dict]:
        """Identify findings suitable for collaboration"""
        opportunities = []
        
        # Complex chains often benefit from collaboration
        for chain in self.chains:
            if len(chain.get('steps', [])) > 3 or chain.get('estimated_bounty', 0) > 2000:
                collaborators = self.collaboration_manager.find_collaborators(
                    chain.get('type', 'complex_chain')
                )
                
                if collaborators:
                    opportunities.append({
                        'finding': chain,
                        'collaborators': collaborators,
                        'reason': 'Complex chain requiring specialized skills'
                    })
        
        # Findings requiring specific expertise
        for finding in self.findings:
            if finding.get('type') in ['Cryptographic Issue', 'Race Condition', 'Business Logic']:
                collaborators = self.collaboration_manager.find_collaborators(finding['type'])
                
                if collaborators:
                    opportunities.append({
                        'finding': finding,
                        'collaborators': collaborators,
                        'reason': f'Specialized {finding["type"]} expertise needed'
                    })
        
        return opportunities
    
    def _get_next_target_suggestion(self) -> str:
        """Get suggestion for next target to test"""
        # Get programs from platforms
        available_programs = []
        
        # In practice, this would fetch from platform APIs
        # For now, return generic suggestion
        suggestion = self.revenue_maximizer.suggest_next_target(available_programs)
        
        if suggestion:
            return f"Test {suggestion['handle']} on {suggestion['platform']} next (ROI: {suggestion.get('roi_score', 0):.2f})"
        
        return "Check platform dashboards for new high-value programs"
    
    def _handle_monitoring_notification(self, target: str, changes: Dict, message: str):
        """Handle notifications from continuous monitoring"""
        logger.info(f"🔔 Monitoring notification: {message}")
        
        # If significant changes detected, note for re-testing
        if changes.get('new_endpoints') and len(changes['new_endpoints']) > 5:
            logger.info(f"📌 Marking {target} for priority re-testing")
            # Could trigger automated re-test here
    
    def _ai_classify_endpoints_revenue_focused(self, endpoints: List[Dict]) -> List[Dict]:
        """Classify endpoints with focus on revenue potential"""
        if not endpoints:
            return []
            
        prompt = f"""
        Analyze these discovered endpoints and identify the most valuable ones for bug bounty hunting.
        Focus on endpoints likely to have high-impact vulnerabilities.
        
        {json.dumps(endpoints[:50], indent=2)}
        
        Return the top 15 most valuable endpoints with:
        - vulnerability types likely to yield high bounties
        - estimated bounty range for each vulnerability type
        - attack vectors to try
        - priority level (1-10)
        
        Prioritize:
        1. Authentication/authorization endpoints (account takeover = $$$)
        2. Payment/financial endpoints
        3. Admin panels and internal tools
        4. File upload endpoints
        5. API endpoints with user data
        
        Format: JSON with 'interesting_endpoints' array
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
            return endpoints[:10]
    
    # Keep existing helper methods from original implementation
    def _find_subdomains(self) -> List[str]:
        """Find subdomains using multiple techniques"""
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
        common_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'test', 'dev', 'staging', 
                      'api-dev', 'api-staging', 'mobile', 'app', 'backend', 'internal']
        for sub in common_subs:
            try:
                import socket
                socket.gethostbyname(f"{sub}.{self.target}")
                subdomains.add(f"{sub}.{self.target}")
            except:
                pass
        
        return list(subdomains)[:30]  # Increased limit for better coverage
    
    def _discover_content(self, target: str) -> List[Dict]:
        """Discover content on target"""
        endpoints = []
        
        # Enhanced directory discovery
        common_paths = [
            '/', '/admin', '/api', '/api/v1', '/api/v2', '/api/v3',
            '/login', '/dashboard', '/config', '/backup', '/test',
            '/dev', '/staging', '/uploads', '/files', '/docs',
            '/swagger', '/swagger-ui', '/api-docs', '/graphql',
            '/robots.txt', '/sitemap.xml', '/.env', '/.git',
            '/wp-admin', '/phpmyadmin', '/payment', '/checkout',
            '/user', '/users', '/profile', '/account', '/settings'
        ]
        
        for path in common_paths:
            url = f"https://{target}{path}"
            try:
                response = requests.get(url, timeout=10, verify=False)
                endpoints.append({
                    "url": url,
                    "status": response.status_code,
                    "length": len(response.content),
                    "title": self._extract_title(response.text),
                    "headers": dict(response.headers)
                })
            except:
                pass
        
        return endpoints
    
    def _generate_ai_payloads(self, endpoint: Dict) -> List[Dict]:
        """Generate AI-powered test payloads for an endpoint"""
        prompt = f"""
        Generate test payloads for this endpoint:
        URL: {endpoint['url']}
        Status: {endpoint.get('status')}
        Context: {endpoint.get('title', '')}
        
        Generate 10-15 targeted payloads focusing on HIGH-VALUE vulnerabilities:
        - Account takeover vectors
        - SQL injection (especially on user/admin endpoints)
        - Authentication bypass
        - IDOR with privilege escalation
        - XXE and SSRF (if XML/URL parameters detected)
        - File upload vulnerabilities
        - JWT manipulation
        
        Return JSON array of payloads with type, parameter, payload, and estimated_bounty.
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
    
    def _assess_competition_level(self) -> str:
        """Assess competition level for the program"""
        if not self.program_info:
            return "Unknown"
        
        # Check program statistics
        stats = self.platform_integration.get_program_statistics(
            self.program_info.get('platform'),
            self.program_info.get('handle')
        )
        
        total_reports = stats.get('total_reports', 'Unknown')
        if isinstance(total_reports, int):
            if total_reports > 1000:
                return "Very High"
            elif total_reports > 500:
                return "High"
            elif total_reports > 100:
                return "Medium"
            else:
                return "Low"
        
        return "Unknown"

def main():
    parser = argparse.ArgumentParser(description="Enhanced Personal Bug Bounty Assistant v3.0")
    parser.add_argument("target", help="Target domain to hunt")
    parser.add_argument("--api-key", help="OpenAI API key (or set OPENAI_API_KEY env var)")
    parser.add_argument("--platform", choices=['hackerone', 'bugcrowd'], help="Bug bounty platform")
    parser.add_argument("--program", help="Program handle on the platform")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--aggressive", action="store_true", help="Enable aggressive testing with WAF evasion")
    parser.add_argument("--no-scope-validation", action="store_true", help="Disable scope validation")
    parser.add_argument("--auto-submit", action="store_true", help="Enable automatic submission of high-confidence findings")
    parser.add_argument("--monitor", action="store_true", help="Add target to continuous monitoring")
    parser.add_argument("--revenue-report", action="store_true", help="Generate revenue report only")
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
    
    if args.auto_submit:
        config.setdefault('auto_submit', {})['enabled'] = True
    
    if args.monitor:
        config.setdefault('continuous_monitoring', {})['enabled'] = True
    
    # Initialize enhanced assistant
    assistant = EnhancedBugBountyAssistantV3(api_key, config)
    
    # Handle revenue report request
    if args.revenue_report:
        analytics = assistant.revenue_maximizer.get_earnings_analytics()
        print(f"\n💰 Revenue Analytics")
        print(f"   Total Earnings: ${analytics['total_earnings']:.2f}")
        print(f"   Success Rate: {analytics['success_rate']*100:.1f}%")
        print(f"   Hourly Rate: ${analytics['hourly_rate']:.2f}/hr")
        sys.exit(0)
    
    try:
        # Run the enhanced hunt
        result = assistant.run_full_enhanced_hunt(args.target, args.platform, args.program)
        
        if result['success']:
            print(f"\n🎉 Enhanced hunt completed successfully!")
            print(f"💰 Potential earnings: ${result['potential_earnings']:.2f}")
            print(f"📈 Efficiency: ${result['hourly_rate']:.2f}/hour")
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
