#!/usr/bin/env python3
"""
Revenue Maximization Module for Bug Bounty Assistant
Tracks earnings, optimizes target selection, and maximizes ROI
"""

import json
import sqlite3
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import numpy as np
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class RevenueMaximizer:
    """Maximizes bug bounty earnings through intelligent targeting and tracking"""
    
    def __init__(self, db_path: str = "~/.bb_assistant/revenue.db"):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(exist_ok=True)
        self._init_database()
        
    def _init_database(self):
        """Initialize revenue tracking database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Earnings tracking
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS earnings (
                id INTEGER PRIMARY KEY,
                platform TEXT,
                program TEXT,
                vulnerability_type TEXT,
                severity TEXT,
                amount REAL,
                currency TEXT DEFAULT 'USD',
                date_submitted TIMESTAMP,
                date_paid TIMESTAMP,
                status TEXT,
                report_url TEXT,
                time_spent_hours REAL,
                duplicate BOOLEAN DEFAULT 0
            )
        """)
        
        # Program intelligence
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS program_intelligence (
                program_id TEXT PRIMARY KEY,
                platform TEXT,
                avg_payout REAL,
                response_time_days REAL,
                acceptance_rate REAL,
                competition_level INTEGER,
                last_updated TIMESTAMP,
                scope_size INTEGER,
                technologies TEXT,
                high_value_assets TEXT
            )
        """)
        
        # Target history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS target_history (
                id INTEGER PRIMARY KEY,
                target TEXT,
                last_tested TIMESTAMP,
                vulnerabilities_found INTEGER,
                total_earnings REAL,
                test_duration_hours REAL,
                success_rate REAL
            )
        """)
        
        # Duplicate tracking
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS duplicate_signatures (
                id INTEGER PRIMARY KEY,
                vulnerability_hash TEXT UNIQUE,
                vulnerability_type TEXT,
                target_pattern TEXT,
                first_reported TIMESTAMP,
                platforms TEXT,
                reporters INTEGER DEFAULT 1
            )
        """)
        
        conn.commit()
        conn.close()
    
    def calculate_roi_score(self, program_info: Dict) -> float:
        """Calculate expected ROI for a program"""
        score = 0.0
        
        # Base score from bounty range
        bounty_range = program_info.get('bounty_range', '')
        if '$' in bounty_range:
            amounts = self._extract_amounts(bounty_range)
            if amounts:
                avg_bounty = np.mean(amounts)
                score += min(avg_bounty / 100, 100)  # Normalize to 100
        
        # Adjust for program intelligence
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        program_id = f"{program_info.get('platform')}:{program_info.get('handle')}"
        cursor.execute("""
            SELECT avg_payout, response_time_days, acceptance_rate, competition_level
            FROM program_intelligence WHERE program_id = ?
        """, (program_id,))
        
        intel = cursor.fetchone()
        if intel:
            avg_payout, response_time, acceptance_rate, competition = intel
            
            # Higher payout = higher score
            if avg_payout:
                score += avg_payout / 100
            
            # Faster response = higher score
            if response_time:
                score += max(0, 30 - response_time) * 2
            
            # Higher acceptance = higher score
            if acceptance_rate:
                score += acceptance_rate * 50
            
            # Lower competition = higher score
            if competition:
                score += max(0, 10 - competition) * 5
        
        # Adjust for scope size
        scope_size = len(program_info.get('scope', {}).get('in_scope', []))
        score += min(scope_size * 2, 50)  # More targets = more opportunities
        
        # Adjust for managed programs (usually better)
        if program_info.get('managed', False):
            score *= 1.2
        
        # Historical success rate
        cursor.execute("""
            SELECT success_rate FROM target_history 
            WHERE target LIKE ? ORDER BY last_tested DESC LIMIT 1
        """, (f"%{program_info.get('handle')}%",))
        
        history = cursor.fetchone()
        if history and history[0]:
            score *= (1 + history[0])  # Boost by success rate
        
        conn.close()
        return score
    
    def prioritize_targets(self, programs: List[Dict]) -> List[Dict]:
        """Prioritize programs by expected ROI"""
        scored_programs = []
        
        for program in programs:
            roi_score = self.calculate_roi_score(program)
            program['roi_score'] = roi_score
            scored_programs.append(program)
        
        # Sort by ROI score descending
        return sorted(scored_programs, key=lambda x: x['roi_score'], reverse=True)
    
    def check_duplicate(self, vulnerability: Dict) -> Tuple[bool, Optional[Dict]]:
        """Check if vulnerability is likely a duplicate"""
        vuln_hash = self._generate_vulnerability_hash(vulnerability)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM duplicate_signatures WHERE vulnerability_hash = ?
        """, (vuln_hash,))
        
        duplicate = cursor.fetchone()
        conn.close()
        
        if duplicate:
            return True, {
                'hash': duplicate[1],
                'type': duplicate[2],
                'first_reported': duplicate[4],
                'platforms': duplicate[5],
                'reporters': duplicate[6]
            }
        
        return False, None
    
    def _generate_vulnerability_hash(self, vulnerability: Dict) -> str:
        """Generate hash signature for duplicate detection"""
        import hashlib
        
        # Create signature from key vulnerability attributes
        sig_parts = [
            vulnerability.get('type', '').lower(),
            self._normalize_url(vulnerability.get('url', '')),
            vulnerability.get('parameter', '').lower(),
            vulnerability.get('endpoint_pattern', '')
        ]
        
        signature = ':'.join(sig_parts)
        return hashlib.sha256(signature.encode()).hexdigest()[:16]
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for duplicate detection"""
        import re
        from urllib.parse import urlparse
        
        if not url:
            return ''
        
        parsed = urlparse(url)
        
        # Remove specific IDs and replace with patterns
        path = parsed.path
        # Replace numeric IDs
        path = re.sub(r'/\d+', '/{id}', path)
        # Replace UUIDs
        path = re.sub(r'/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}', '/{uuid}', path)
        # Replace base64-like strings
        path = re.sub(r'/[A-Za-z0-9+/]{16,}={0,2}', '/{token}', path)
        
        return f"{parsed.netloc}{path}"
    
    def record_submission(self, platform: str, program: str, vulnerability: Dict, amount: float = 0):
        """Record a vulnerability submission"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO earnings 
            (platform, program, vulnerability_type, severity, amount, date_submitted, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            platform,
            program,
            vulnerability.get('type'),
            vulnerability.get('severity'),
            amount,
            datetime.now(),
            'submitted'
        ))
        
        # Update duplicate tracking
        vuln_hash = self._generate_vulnerability_hash(vulnerability)
        cursor.execute("""
            INSERT OR IGNORE INTO duplicate_signatures
            (vulnerability_hash, vulnerability_type, target_pattern, first_reported, platforms)
            VALUES (?, ?, ?, ?, ?)
        """, (
            vuln_hash,
            vulnerability.get('type'),
            self._normalize_url(vulnerability.get('url')),
            datetime.now(),
            platform
        ))
        
        conn.commit()
        conn.close()
    
    def get_earnings_analytics(self) -> Dict:
        """Get comprehensive earnings analytics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total earnings
        cursor.execute("SELECT SUM(amount) FROM earnings WHERE status = 'paid'")
        total_earnings = cursor.fetchone()[0] or 0
        
        # Earnings by platform
        cursor.execute("""
            SELECT platform, SUM(amount) FROM earnings 
            WHERE status = 'paid' GROUP BY platform
        """)
        earnings_by_platform = dict(cursor.fetchall())
        
        # Earnings by type
        cursor.execute("""
            SELECT vulnerability_type, SUM(amount), COUNT(*) FROM earnings 
            WHERE status = 'paid' GROUP BY vulnerability_type
            ORDER BY SUM(amount) DESC
        """)
        earnings_by_type = cursor.fetchall()
        
        # Success rate
        cursor.execute("""
            SELECT 
                COUNT(CASE WHEN duplicate = 0 THEN 1 END) as accepted,
                COUNT(*) as total
            FROM earnings
        """)
        accepted, total = cursor.fetchone()
        success_rate = accepted / total if total > 0 else 0
        
        # Average time to payment
        cursor.execute("""
            SELECT AVG(julianday(date_paid) - julianday(date_submitted))
            FROM earnings WHERE date_paid IS NOT NULL
        """)
        avg_payment_time = cursor.fetchone()[0] or 0
        
        # Best programs
        cursor.execute("""
            SELECT program, platform, SUM(amount), COUNT(*), AVG(amount)
            FROM earnings WHERE status = 'paid'
            GROUP BY program, platform
            ORDER BY SUM(amount) DESC LIMIT 10
        """)
        best_programs = cursor.fetchall()
        
        # Hourly rate
        cursor.execute("""
            SELECT SUM(amount), SUM(time_spent_hours)
            FROM earnings WHERE status = 'paid' AND time_spent_hours > 0
        """)
        total_paid, total_hours = cursor.fetchone()
        hourly_rate = (total_paid / total_hours) if total_hours else 0
        
        conn.close()
        
        return {
            'total_earnings': total_earnings,
            'earnings_by_platform': earnings_by_platform,
            'earnings_by_type': earnings_by_type,
            'success_rate': success_rate,
            'avg_payment_time_days': avg_payment_time,
            'best_programs': best_programs,
            'hourly_rate': hourly_rate,
            'recommendations': self._generate_recommendations(earnings_by_type, best_programs)
        }
    
    def _generate_recommendations(self, earnings_by_type: List, best_programs: List) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Recommend focusing on highest earning vulnerability types
        if earnings_by_type:
            top_type = earnings_by_type[0][0]
            recommendations.append(f"Focus on {top_type} vulnerabilities - highest earnings")
        
        # Recommend best programs
        if best_programs:
            top_program = best_programs[0]
            recommendations.append(f"Prioritize {top_program[0]} on {top_program[1]} - best ROI")
        
        # Time-based recommendations
        now = datetime.now()
        if now.weekday() < 5:  # Weekday
            recommendations.append("Test during off-hours for less competition")
        
        return recommendations
    
    def _extract_amounts(self, bounty_range: str) -> List[float]:
        """Extract dollar amounts from bounty range string"""
        import re
        amounts = []
        
        # Find all dollar amounts
        matches = re.findall(r'\$\s*([\d,]+)', bounty_range)
        for match in matches:
            try:
                amount = float(match.replace(',', ''))
                amounts.append(amount)
            except:
                pass
        
        return amounts
    
    def suggest_next_target(self, available_programs: List[Dict]) -> Dict:
        """Suggest the best target to test next"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Filter out recently tested programs
        filtered_programs = []
        for program in available_programs:
            program_id = f"{program.get('platform')}:{program.get('handle')}"
            
            cursor.execute("""
                SELECT last_tested FROM target_history
                WHERE target = ? AND last_tested > ?
            """, (program_id, datetime.now() - timedelta(days=30)))
            
            if not cursor.fetchone():  # Not tested in last 30 days
                filtered_programs.append(program)
        
        conn.close()
        
        # Prioritize by ROI
        prioritized = self.prioritize_targets(filtered_programs)
        
        if prioritized:
            return prioritized[0]
        
        return None
    
    def optimize_testing_schedule(self) -> Dict:
        """Generate optimized testing schedule"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Analyze best testing times
        cursor.execute("""
            SELECT 
                strftime('%H', date_submitted) as hour,
                COUNT(*) as submissions,
                SUM(CASE WHEN duplicate = 0 THEN 1 ELSE 0 END) as accepted
            FROM earnings
            GROUP BY hour
            ORDER BY accepted DESC
        """)
        
        best_hours = cursor.fetchall()
        
        # Analyze best days
        cursor.execute("""
            SELECT 
                strftime('%w', date_submitted) as day,
                COUNT(*) as submissions,
                SUM(CASE WHEN duplicate = 0 THEN 1 ELSE 0 END) as accepted
            FROM earnings
            GROUP BY day
            ORDER BY accepted DESC
        """)
        
        best_days = cursor.fetchall()
        
        conn.close()
        
        schedule = {
            'best_hours': [h[0] for h in best_hours[:3]],
            'best_days': [self._day_name(d[0]) for d in best_days[:3]],
            'recommendations': []
        }
        
        if best_hours:
            schedule['recommendations'].append(
                f"Test during hours: {', '.join(schedule['best_hours'])} for best success rate"
            )
        
        if best_days:
            schedule['recommendations'].append(
                f"Focus on {', '.join(schedule['best_days'])} for highest acceptance"
            )
        
        return schedule
    
    def _day_name(self, day_num: str) -> str:
        """Convert day number to name"""
        days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
        try:
            return days[int(day_num)]
        except:
            return day_num


class CollaborationManager:
    """Manage collaboration with other bug bounty hunters"""
    
    def __init__(self, db_path: str = "~/.bb_assistant/collaboration.db"):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(exist_ok=True)
        self._init_database()
    
    def _init_database(self):
        """Initialize collaboration database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS collaborators (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                platforms TEXT,
                specialties TEXT,
                trust_score REAL DEFAULT 5.0,
                total_collaborations INTEGER DEFAULT 0,
                total_split_earnings REAL DEFAULT 0
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS collaborations (
                id INTEGER PRIMARY KEY,
                vulnerability_id TEXT,
                collaborators TEXT,
                split_percentages TEXT,
                total_bounty REAL,
                status TEXT,
                date_created TIMESTAMP,
                platform TEXT,
                program TEXT
            )
        """)
        
        conn.commit()
        conn.close()
    
    def propose_collaboration(self, vulnerability: Dict, collaborators: List[str], 
                            split: Dict[str, float]) -> str:
        """Propose a collaboration on a finding"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        collab_id = f"collab_{datetime.now().timestamp()}"
        
        cursor.execute("""
            INSERT INTO collaborations
            (vulnerability_id, collaborators, split_percentages, status, date_created)
            VALUES (?, ?, ?, ?, ?)
        """, (
            vulnerability.get('id', 'unknown'),
            json.dumps(collaborators),
            json.dumps(split),
            'proposed',
            datetime.now()
        ))
        
        conn.commit()
        conn.close()
        
        return collab_id
    
    def find_collaborators(self, vulnerability_type: str) -> List[Dict]:
        """Find suitable collaborators for a vulnerability type"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT username, specialties, trust_score, total_collaborations
            FROM collaborators
            WHERE specialties LIKE ?
            ORDER BY trust_score DESC, total_collaborations DESC
            LIMIT 5
        """, (f"%{vulnerability_type}%",))
        
        collaborators = []
        for row in cursor.fetchall():
            collaborators.append({
                'username': row[0],
                'specialties': json.loads(row[1]) if row[1] else [],
                'trust_score': row[2],
                'experience': row[3]
            })
        
        conn.close()
        return collaborators


class AutoSubmitter:
    """Automated report submission with duplicate checking"""
    
    def __init__(self, revenue_maximizer: RevenueMaximizer):
        self.revenue_maximizer = revenue_maximizer
        self.submission_queue = []
        
    def validate_for_submission(self, vulnerability: Dict, program_info: Dict) -> Tuple[bool, str]:
        """Validate if vulnerability should be submitted"""
        # Check for duplicate
        is_duplicate, dup_info = self.revenue_maximizer.check_duplicate(vulnerability)
        if is_duplicate:
            return False, f"Likely duplicate - first reported {dup_info['first_reported']}"
        
        # Check severity threshold
        severity = vulnerability.get('severity', 'low')
        if severity in ['info', 'low'] and not program_info.get('accepts_low_severity', True):
            return False, "Program doesn't accept low severity findings"
        
        # Check confidence level
        confidence = vulnerability.get('confidence', 'medium')
        if confidence == 'low':
            return False, "Low confidence - manual review recommended"
        
        return True, "Ready for submission"
    
    def queue_for_submission(self, vulnerability: Dict, program_info: Dict, 
                           platform_integration, auto_submit: bool = False):
        """Queue vulnerability for submission"""
        is_valid, reason = self.validate_for_submission(vulnerability, program_info)
        
        if not is_valid:
            logger.warning(f"Not submitting: {reason}")
            return None
        
        submission = {
            'vulnerability': vulnerability,
            'program_info': program_info,
            'platform': program_info.get('platform'),
            'timestamp': datetime.now(),
            'auto_submit': auto_submit
        }
        
        if auto_submit and platform_integration:
            # Submit immediately
            result = platform_integration.submit_report(
                submission['platform'],
                platform_integration.format_report_for_platform(
                    submission['platform'],
                    [vulnerability],
                    program_info
                )
            )
            
            if result.get('success'):
                self.revenue_maximizer.record_submission(
                    submission['platform'],
                    program_info.get('handle'),
                    vulnerability
                )
                return result
        else:
            # Add to manual review queue
            self.submission_queue.append(submission)
            logger.info(f"Added to submission queue: {len(self.submission_queue)} pending")
        
        return submission
