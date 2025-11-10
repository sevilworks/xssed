"""
Main scanner orchestration logic
Coordinates URL processing, reflection detection, and execution verification
"""

import asyncio
from typing import List, Dict, Optional, Set
from pathlib import Path
from datetime import datetime

from core.payload_manager import PayloadManager
from core.waf_detector import WAFDetector
from engines.reflection_detector import ReflectionDetector
from engines.execution_verifier import ExecutionVerifier
from utils.url_processor import URLProcessor


class XSSScanner:
    def __init__(
        self,
        target: str,
        payload_file: Optional[Path] = None,
        concurrency: int = 10,
        timeout: int = 15,
        waf_check: bool = True,
        screenshots: bool = False,
        max_urls: int = 1000
    ):
        self.target = target
        self.concurrency = concurrency
        self.timeout = timeout
        self.waf_check = waf_check
        self.screenshots = screenshots
        self.max_urls = max_urls
        
        # Initialize components
        self.payload_manager = PayloadManager(payload_file)
        self.url_processor = URLProcessor(target, max_urls)
        self.waf_detector = WAFDetector() if waf_check else None
        self.reflection_detector = ReflectionDetector(concurrency, timeout)
        self.execution_verifier = None  # Lazy init for Playwright
        
        # Results storage
        self.results = {
            'target': target,
            'start_time': None,
            'end_time': None,
            'total_urls_tested': 0,
            'reflected_urls': 0,
            'vulnerabilities': [],
            'waf_detected': None,
            'false_positives_filtered': 0,
            'statistics': {}
        }
        
    async def scan(self) -> Dict:
        """Main scan orchestration"""
        self.results['start_time'] = datetime.now().isoformat()
        
        try:
            # Phase 0: Collect URLs from Wayback
            print("[Phase 1/4] Collecting URLs from Wayback Machine...")
            urls = await self.url_processor.fetch_wayback_urls()
            
            if not urls:
                print("[!] No URLs found for target")
                return self.results
            
            print(f"[+] Found {len(urls)} unique URLs with parameters")
            
            # Phase 1: WAF Detection (optional)
            if self.waf_check:
                print("\n[Phase 2/4] Detecting WAF protection...")
                waf_info = await self.waf_detector.detect(self.target)
                self.results['waf_detected'] = waf_info
                
                if waf_info['detected']:
                    print(f"[!] WAF Detected: {waf_info['type']}")
                    print(f"[*] Confidence: {waf_info['confidence']}")
                else:
                    print("[+] No WAF detected")
            
            # Phase 2: Prepare test URLs with payloads
            print(f"\n[Phase 3/4] Testing reflection (fast check on {len(urls)} URLs)...")
            test_urls = self._prepare_test_urls(urls)
            self.results['total_urls_tested'] = len(test_urls)
            
            # Phase 3: Reflection detection (bulk, async)
            reflected = await self.reflection_detector.detect_reflections(test_urls)
            self.results['reflected_urls'] = len(reflected)
            
            print(f"[+] Found {len(reflected)} URLs with payload reflection")
            
            if not reflected:
                print("[*] No reflections found, scan complete")
                self.results['end_time'] = datetime.now().isoformat()
                return self.results
            
            # Phase 4: Execution verification (selective, Playwright)
            print(f"\n[Phase 4/4] Verifying execution on {len(reflected)} candidates...")
            await self._verify_execution(reflected)
            
            self.results['end_time'] = datetime.now().isoformat()
            return self.results
            
        finally:
            # Cleanup
            await self.reflection_detector.close()
            if self.execution_verifier:
                await self.execution_verifier.close()
    
    def _prepare_test_urls(self, urls: List[str]) -> List[Dict]:
        """Prepare URLs with context-aware payloads"""
        test_urls = []
        
        for url in urls:
            params = self.url_processor.extract_parameters(url)
            
            for param_name in params:
                # Detect context for this parameter
                context = self.url_processor.detect_context(url, param_name)
                
                # Get appropriate payloads for context
                payloads = self.payload_manager.get_payloads_for_context(context)
                
                # Generate test URLs
                for payload in payloads:
                    test_url = self.url_processor.inject_payload(
                        url, param_name, payload
                    )
                    
                    test_urls.append({
                        'url': test_url,
                        'original_url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'context': context
                    })
        
        return test_urls
    
    async def _verify_execution(self, reflected_urls: List[Dict]):
        """Verify actual JavaScript execution using Playwright"""
        # Lazy init Playwright (only when needed)
        if not self.execution_verifier:
            print("[*] Initializing browser for execution verification...")
            self.execution_verifier = ExecutionVerifier(
                concurrency=min(3, self.concurrency),  # Limit browser contexts
                timeout=self.timeout,
                screenshots=self.screenshots
            )
            await self.execution_verifier.initialize()
        
        # Verify each reflected URL
        verified_count = 0
        false_positives = 0
        
        for idx, url_data in enumerate(reflected_urls, 1):
            print(f"[*] Verifying {idx}/{len(reflected_urls)}: {url_data['parameter']}", end='\r')
            
            result = await self.execution_verifier.verify_execution(url_data)
            
            if result['executed']:
                verified_count += 1
                self.results['vulnerabilities'].append({
                    'url': url_data['url'],
                    'parameter': url_data['parameter'],
                    'payload': url_data['payload'],
                    'context': url_data['context'],
                    'evidence': result['evidence'],
                    'screenshot': result.get('screenshot'),
                    'severity': self._calculate_severity(url_data['context']),
                    'verified_at': datetime.now().isoformat()
                })
                
                print(f"\n[+] VERIFIED XSS in '{url_data['parameter']}' parameter")
                print(f"    URL: {url_data['original_url']}")
                print(f"    Payload: {url_data['payload'][:50]}...")
            else:
                false_positives += 1
        
        self.results['false_positives_filtered'] = false_positives
        print(f"\n[+] Execution verification complete: {verified_count} confirmed, {false_positives} false positives")
    
    def _calculate_severity(self, context: str) -> str:
        """Calculate vulnerability severity based on context"""
        severity_map = {
            'script': 'HIGH',
            'html': 'HIGH',
            'attribute': 'MEDIUM',
            'url': 'MEDIUM',
            'style': 'LOW'
        }
        return severity_map.get(context, 'MEDIUM')