#!/usr/bin/env python3
"""
Continuous Monitoring Module for Bug Bounty Assistant
Monitors targets for changes and new vulnerabilities
"""

import asyncio
import aiohttp
import hashlib
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional
from pathlib import Path
import logging
import difflib
import re
from bs4 import BeautifulSoup
import schedule
import threading
import time

logger = logging.getLogger(__name__)

class ContinuousMonitor:
    """Monitor targets for changes and new attack surfaces"""
    
    def __init__(self, db_path: str = "~/.bb_assistant/monitoring.db"):
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(exist_ok=True)
        self._init_database()
        self.monitoring_tasks = {}
        self.notification_handlers = []
        
    def _init_database(self):
        """Initialize monitoring database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS monitored_targets (
                id INTEGER PRIMARY KEY,
                target TEXT UNIQUE,
                platform TEXT,
                program TEXT,
                check_frequency_hours INTEGER DEFAULT 24,
                last_checked TIMESTAMP,
                enabled BOOLEAN DEFAULT 1,
                priority INTEGER DEFAULT 5
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS target_snapshots (
                id INTEGER PRIMARY KEY,
                target TEXT,
                snapshot_time TIMESTAMP,
                endpoints_hash TEXT,
                js_files_hash TEXT,
                response_hashes TEXT,
                new_endpoints TEXT,
                new_js_files TEXT,
                changes_detected BOOLEAN DEFAULT 0
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS content_changes (
                id INTEGER PRIMARY KEY,
                target TEXT,
                url TEXT,
                change_type TEXT,
                old_content_hash TEXT,
                new_content_hash TEXT,
                diff_summary TEXT,
                detected_at TIMESTAMP,
                tested BOOLEAN DEFAULT 0
            )
        """)
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS new_programs (
                id INTEGER PRIMARY KEY,
                platform TEXT,
                program_handle TEXT,
                program_name TEXT,
                bounty_range TEXT,
                discovered_at TIMESTAMP,
                notified BOOLEAN DEFAULT 0,
                tested BOOLEAN DEFAULT 0
            )
        """)
        
        conn.commit()
        conn.close()
    
    def add_monitoring_target(self, target: str, platform: str = None, 
                            program: str = None, frequency_hours: int = 24):
        """Add target for continuous monitoring"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO monitored_targets
            (target, platform, program, check_frequency_hours, last_checked)
            VALUES (?, ?, ?, ?, ?)
        """, (target, platform, program, frequency_hours, datetime.now()))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Added {target} to monitoring (check every {frequency_hours}h)")
    
    async def check_target_changes(self, target: str) -> Dict:
        """Check target for changes"""
        logger.info(f"🔍 Checking {target} for changes...")
        
        changes = {
            'target': target,
            'timestamp': datetime.now(),
            'new_endpoints': [],
            'new_js_files': [],
            'content_changes': [],
            'new_parameters': [],
            'technology_changes': []
        }
        
        # Get current snapshot
        current_snapshot = await self._create_target_snapshot(target)
        
        # Get previous snapshot
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT endpoints_hash, js_files_hash, response_hashes
            FROM target_snapshots
            WHERE target = ?
            ORDER BY snapshot_time DESC LIMIT 1
        """, (target,))
        
        previous = cursor.fetchone()
        
        if previous:
            # Compare snapshots
            changes = self._compare_snapshots(target, previous, current_snapshot)
            
            # Record changes if detected
            if any(changes.values()):
                self._record_changes(target, changes)
        
        # Save current snapshot
        self._save_snapshot(target, current_snapshot)
        
        # Update last checked
        cursor.execute("""
            UPDATE monitored_targets
            SET last_checked = ?
            WHERE target = ?
        """, (datetime.now(), target))
        
        conn.commit()
        conn.close()
        
        return changes
    
    async def _create_target_snapshot(self, target: str) -> Dict:
        """Create snapshot of target's current state"""
        snapshot = {
            'endpoints': set(),
            'js_files': set(),
            'response_hashes': {},
            'parameters': set(),
            'technologies': set()
        }
        
        async with aiohttp.ClientSession() as session:
            # Discover endpoints
            endpoints = await self._async_discover_endpoints(session, target)
            snapshot['endpoints'] = set(endpoints)
            
            # Discover JS files
            js_files = await self._async_discover_js_files(session, target)
            snapshot['js_files'] = set(js_files)
            
            # Get response hashes for key endpoints
            for endpoint in list(endpoints)[:20]:  # Limit to top 20
                try:
                    async with session.get(endpoint, timeout=10, ssl=False) as response:
                        content = await response.text()
                        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
                        snapshot['response_hashes'][endpoint] = content_hash
                        
                        # Extract parameters
                        params = self._extract_parameters(content)
                        snapshot['parameters'].update(params)
                        
                        # Detect technologies
                        techs = self._detect_technologies(content, response.headers)
                        snapshot['technologies'].update(techs)
                except:
                    pass
        
        return snapshot
    
    async def _async_discover_endpoints(self, session: aiohttp.ClientSession, 
                                      target: str) -> List[str]:
        """Asynchronously discover endpoints"""
        endpoints = []
        base_url = f"https://{target}"
        
        # Common paths to check
        paths = [
            '/', '/api', '/api/v1', '/api/v2', '/admin', '/login',
            '/dashboard', '/user', '/account', '/settings', '/profile',
            '/docs', '/swagger', '/graphql', '/sitemap.xml', '/robots.txt'
        ]
        
        tasks = []
        for path in paths:
            url = f"{base_url}{path}"
            tasks.append(self._check_endpoint(session, url))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, str):
                endpoints.append(result)
        
        return endpoints
    
    async def _check_endpoint(self, session: aiohttp.ClientSession, url: str) -> Optional[str]:
        """Check if endpoint exists"""
        try:
            async with session.head(url, timeout=5, ssl=False) as response:
                if response.status < 400:
                    return url
        except:
            pass
        return None
    
    async def _async_discover_js_files(self, session: aiohttp.ClientSession, 
                                     target: str) -> List[str]:
        """Discover JavaScript files"""
        js_files = []
        base_url = f"https://{target}"
        
        try:
            async with session.get(base_url, timeout=10, ssl=False) as response:
                content = await response.text()
                soup = BeautifulSoup(content, 'html.parser')
                
                # Find script tags
                for script in soup.find_all('script', src=True):
                    src = script['src']
                    if src.startswith('/'):
                        src = f"{base_url}{src}"
                    elif not src.startswith('http'):
                        src = f"{base_url}/{src}"
                    
                    if target in src or src.startswith(base_url):
                        js_files.append(src)
                
                # Find JS files in source
                js_pattern = re.compile(r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']')
                for match in js_pattern.findall(content):
                    if match.startswith('/'):
                        js_url = f"{base_url}{match}"
                    elif not match.startswith('http'):
                        js_url = f"{base_url}/{match}"
                    else:
                        js_url = match
                    
                    if target in js_url or js_url.startswith(base_url):
                        js_files.append(js_url)
        except:
            pass
        
        return list(set(js_files))
    
    def _extract_parameters(self, content: str) -> Set[str]:
        """Extract parameters from content"""
        parameters = set()
        
        # Form parameters
        form_params = re.findall(r'name=["\']([^"\']+)["\']', content)
        parameters.update(form_params)
        
        # URL parameters
        url_params = re.findall(r'[?&]([a-zA-Z0-9_]+)=', content)
        parameters.update(url_params)
        
        # JSON keys
        json_keys = re.findall(r'"([a-zA-Z0-9_]+)"\s*:', content)
        parameters.update(json_keys)
        
        return parameters
    
    def _detect_technologies(self, content: str, headers: Dict) -> Set[str]:
        """Detect technologies from response"""
        technologies = set()
        
        # Server header
        server = headers.get('Server', '').lower()
        if 'nginx' in server:
            technologies.add('nginx')
        elif 'apache' in server:
            technologies.add('apache')
        
        # Framework detection
        if 'x-powered-by' in headers:
            technologies.add(headers['x-powered-by'])
        
        # Content-based detection
        tech_patterns = {
            'wordpress': r'wp-content|wordpress',
            'drupal': r'drupal|sites/default',
            'react': r'react\.production\.min\.js|_react',
            'angular': r'angular\.min\.js|ng-',
            'vue': r'vue\.min\.js|v-for',
            'django': r'csrfmiddlewaretoken|django',
            'rails': r'rails|actionpack',
            'laravel': r'laravel|blade\.php'
        }
        
        for tech, pattern in tech_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                technologies.add(tech)
        
        return technologies
    
    def _compare_snapshots(self, target: str, previous: Tuple, current: Dict) -> Dict:
        """Compare snapshots to find changes"""
        changes = {}
        
        # Previous snapshot data
        prev_endpoints_hash, prev_js_hash, prev_response_hashes = previous
        prev_response_hashes = json.loads(prev_response_hashes) if prev_response_hashes else {}
        
        # Current snapshot hashes
        curr_endpoints_hash = hashlib.sha256(
            str(sorted(current['endpoints'])).encode()
        ).hexdigest()
        curr_js_hash = hashlib.sha256(
            str(sorted(current['js_files'])).encode()
        ).hexdigest()
        
        # Check for new endpoints
        if curr_endpoints_hash != prev_endpoints_hash:
            # Need to load previous endpoints from an earlier snapshot
            # For now, we'll flag that endpoints changed
            changes['endpoints_changed'] = True
            changes['new_endpoints'] = list(current['endpoints'])[:10]  # Sample
        
        # Check for new JS files
        if curr_js_hash != prev_js_hash:
            changes['js_files_changed'] = True
            changes['new_js_files'] = list(current['js_files'])[:10]  # Sample
        
        # Check for content changes
        content_changes = []
        for url, new_hash in current['response_hashes'].items():
            if url in prev_response_hashes and prev_response_hashes[url] != new_hash:
                content_changes.append({
                    'url': url,
                    'old_hash': prev_response_hashes[url],
                    'new_hash': new_hash
                })
        
        if content_changes:
            changes['content_changes'] = content_changes
        
        # New parameters
        if current['parameters']:
            changes['parameters_found'] = len(current['parameters'])
        
        # Technology changes
        if current['technologies']:
            changes['technologies'] = list(current['technologies'])
        
        return changes
    
    def _record_changes(self, target: str, changes: Dict):
        """Record detected changes"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Record content changes
        for change in changes.get('content_changes', []):
            cursor.execute("""
                INSERT INTO content_changes
                (target, url, change_type, old_content_hash, new_content_hash, detected_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                target,
                change['url'],
                'content_update',
                change['old_hash'],
                change['new_hash'],
                datetime.now()
            ))
        
        conn.commit()
        conn.close()
        
        # Trigger notifications
        self._notify_changes(target, changes)
    
    def _save_snapshot(self, target: str, snapshot: Dict):
        """Save target snapshot"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        endpoints_hash = hashlib.sha256(
            str(sorted(snapshot['endpoints'])).encode()
        ).hexdigest()
        js_files_hash = hashlib.sha256(
            str(sorted(snapshot['js_files'])).encode()
        ).hexdigest()
        
        cursor.execute("""
            INSERT INTO target_snapshots
            (target, snapshot_time, endpoints_hash, js_files_hash, response_hashes,
             new_endpoints, new_js_files, changes_detected)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            target,
            datetime.now(),
            endpoints_hash,
            js_files_hash,
            json.dumps(snapshot['response_hashes']),
            json.dumps(list(snapshot['endpoints'])[:20]),
            json.dumps(list(snapshot['js_files'])[:20]),
            False
        ))
        
        conn.commit()
        conn.close()
    
    def _notify_changes(self, target: str, changes: Dict):
        """Send notifications about changes"""
        if not any(changes.values()):
            return
        
        message = f"🚨 Changes detected on {target}:\n"
        
        if changes.get('new_endpoints'):
            message += f"- {len(changes['new_endpoints'])} new endpoints found\n"
        
        if changes.get('new_js_files'):
            message += f"- {len(changes['new_js_files'])} new JS files found\n"
        
        if changes.get('content_changes'):
            message += f"- {len(changes['content_changes'])} pages updated\n"
        
        if changes.get('technologies'):
            message += f"- Technologies detected: {', '.join(changes['technologies'])}\n"
        
        logger.info(message)
        
        # Call notification handlers
        for handler in self.notification_handlers:
            try:
                handler(target, changes, message)
            except Exception as e:
                logger.error(f"Notification handler failed: {e}")
    
    def add_notification_handler(self, handler):
        """Add notification handler function"""
        self.notification_handlers.append(handler)
    
    async def scan_new_programs(self, platforms: List[str] = ['hackerone', 'bugcrowd']):
        """Scan for new bug bounty programs"""
        logger.info("🔍 Scanning for new programs...")
        
        for platform in platforms:
            try:
                new_programs = await self._fetch_new_programs(platform)
                
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                for program in new_programs:
                    cursor.execute("""
                        INSERT OR IGNORE INTO new_programs
                        (platform, program_handle, program_name, bounty_range, discovered_at)
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        platform,
                        program['handle'],
                        program['name'],
                        program.get('bounty_range', 'Unknown'),
                        datetime.now()
                    ))
                
                conn.commit()
                conn.close()
                
                if new_programs:
                    logger.info(f"Found {len(new_programs)} new programs on {platform}")
                    self._notify_new_programs(platform, new_programs)
                    
            except Exception as e:
                logger.error(f"Failed to scan {platform}: {e}")
    
    async def _fetch_new_programs(self, platform: str) -> List[Dict]:
        """Fetch new programs from platform"""
        # This would integrate with platform APIs
        # For now, return empty list
        return []
    
    def _notify_new_programs(self, platform: str, programs: List[Dict]):
        """Notify about new programs"""
        message = f"🎯 New programs on {platform}:\n"
        
        for program in programs[:5]:  # Limit to 5
            message += f"- {program['name']} ({program.get('bounty_range', 'Unknown')})\n"
        
        if len(programs) > 5:
            message += f"... and {len(programs) - 5} more\n"
        
        logger.info(message)
        
        # Call notification handlers
        for handler in self.notification_handlers:
            try:
                handler(f"new_programs_{platform}", programs, message)
            except:
                pass
    
    def start_monitoring(self):
        """Start continuous monitoring in background"""
        def run_monitoring():
            while True:
                try:
                    # Get targets due for checking
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    
                    cursor.execute("""
                        SELECT target, check_frequency_hours
                        FROM monitored_targets
                        WHERE enabled = 1 
                        AND (last_checked IS NULL 
                             OR last_checked < datetime('now', '-' || check_frequency_hours || ' hours'))
                        ORDER BY priority DESC
                        LIMIT 10
                    """)
                    
                    targets = cursor.fetchall()
                    conn.close()
                    
                    if targets:
                        # Run async checks
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        
                        tasks = [self.check_target_changes(target[0]) for target in targets]
                        loop.run_until_complete(asyncio.gather(*tasks))
                        
                        loop.close()
                    
                    # Check for new programs daily
                    if datetime.now().hour == 9:  # 9 AM
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        loop.run_until_complete(self.scan_new_programs())
                        loop.close()
                    
                except Exception as e:
                    logger.error(f"Monitoring error: {e}")
                
                # Sleep for 1 hour
                time.sleep(3600)
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=run_monitoring, daemon=True)
        monitor_thread.start()
        logger.info("🚀 Continuous monitoring started")
    
    def get_recent_changes(self, hours: int = 24) -> List[Dict]:
        """Get recent changes across all targets"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT target, url, change_type, detected_at, tested
            FROM content_changes
            WHERE detected_at > datetime('now', '-' || ? || ' hours')
            ORDER BY detected_at DESC
        """, (hours,))
        
        changes = []
        for row in cursor.fetchall():
            changes.append({
                'target': row[0],
                'url': row[1],
                'change_type': row[2],
                'detected_at': row[3],
                'tested': bool(row[4])
            })
        
        conn.close()
        return changes
    
    def mark_change_tested(self, target: str, url: str):
        """Mark a change as tested"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE content_changes
            SET tested = 1
            WHERE target = ? AND url = ?
        """, (target, url))
        
        conn.commit()
        conn.close()


class ProgramWatcher:
    """Watch for program scope changes and new opportunities"""
    
    def __init__(self, monitor: ContinuousMonitor):
        self.monitor = monitor
        self.scope_change_handlers = []
    
    async def check_scope_changes(self, platform: str, program_handle: str, 
                                 current_scope: Dict) -> Dict:
        """Check if program scope has changed"""
        # This would compare with stored scope
        # Implementation would integrate with platform APIs
        return {}
    
    def alert_high_value_opportunities(self):
        """Alert on high-value testing opportunities"""
        # Check for:
        # - New programs with high bounties
        # - Scope expansions
        # - Special promotions/bonuses
        # - Less competitive time windows
        pass
