"""
Fast reflection detection using async HTTP requests
Filters out non-reflecting URLs before expensive browser verification
"""

import asyncio
import httpx
from typing import List, Dict, Set
from urllib.parse import unquote


class ReflectionDetector:
    def __init__(self, concurrency: int = 10, timeout: int = 15):
        self.concurrency = concurrency
        self.timeout = timeout
        self.client = None
        
        # Track WAF blocks to avoid repeated testing
        self.blocked_domains: Set[str] = set()
        
        # Response indicators of WAF/blocking
        self.block_indicators = [
            'cloudflare', 'access denied', 'forbidden',
            'blocked', 'ray id', 'security', 'incapsula',
            'imperva', 'captcha', 'challenge'
        ]
    
    async def detect_reflections(self, test_urls: List[Dict]) -> List[Dict]:
        """Detect payload reflection in bulk"""
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            limits=httpx.Limits(
                max_keepalive_connections=20,
                max_connections=50
            ),
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        
        try:
            # Process in batches
            reflected = []
            total = len(test_urls)
            
            for i in range(0, total, self.concurrency):
                batch = test_urls[i:i + self.concurrency]
                
                print(f"[*] Testing batch {i//self.concurrency + 1}/{(total + self.concurrency - 1)//self.concurrency}", end='\r')
                
                batch_results = await asyncio.gather(
                    *[self._check_reflection(url_data) for url_data in batch],
                    return_exceptions=True
                )
                
                # Collect successful reflections
                for url_data, result in zip(batch, batch_results):
                    if isinstance(result, dict) and result.get('reflected'):
                        reflected.append({
                            **url_data,
                            'reflection_evidence': result['evidence']
                        })
            
            print()  # New line after progress
            return reflected
            
        finally:
            await self.client.aclose()
    
    async def _check_reflection(self, url_data: Dict) -> Dict:
        """Check if payload reflects in response"""
        result = {
            'reflected': False,
            'evidence': [],
            'blocked': False
        }
        
        try:
            # Skip if domain is known to be blocked
            from urllib.parse import urlparse
            domain = urlparse(url_data['url']).netloc
            if domain in self.blocked_domains:
                return result
            
            # Send request
            response = await self.client.get(url_data['url'])
            
            # Check for WAF block
            if self._is_blocked(response):
                self.blocked_domains.add(domain)
                result['blocked'] = True
                return result
            
            # Check for reflection
            payload = url_data['payload']
            
            # Decode payload variations to match against response
            payload_variants = [
                payload,
                unquote(payload),
                payload.lower(),
                unquote(payload).lower()
            ]
            
            response_body = response.text.lower()
            response_headers = str(response.headers).lower()
            
            # Check body reflection
            for variant in payload_variants:
                if variant.lower() in response_body:
                    result['reflected'] = True
                    result['evidence'].append({
                        'location': 'body',
                        'snippet': self._extract_snippet(response.text, variant)
                    })
                    break
            
            # Check header reflection (less common but important)
            if payload.lower() in response_headers:
                result['reflected'] = True
                result['evidence'].append({
                    'location': 'headers',
                    'snippet': 'Payload reflected in response headers'
                })
            
            # Check for dangerous sinks even without exact reflection
            if not result['reflected']:
                dangerous_patterns = [
                    '<script', 'onerror=', 'onload=', 'javascript:',
                    'eval(', 'settimeout(', 'setinterval('
                ]
                
                for pattern in dangerous_patterns:
                    if pattern in response_body:
                        # Partial match - might indicate encoding/transformation
                        result['reflected'] = True
                        result['evidence'].append({
                            'location': 'body',
                            'snippet': f'Dangerous pattern detected: {pattern}'
                        })
                        break
            
        except httpx.TimeoutException:
            pass  # Silent fail for timeouts
        except httpx.RequestError:
            pass  # Silent fail for network errors
        except Exception as e:
            # Log unexpected errors but don't crash
            print(f"\n[!] Reflection check error: {e}")
        
        return result
    
    def _is_blocked(self, response: httpx.Response) -> bool:
        """Detect if request was blocked by WAF"""
        # Status code indicators
        if response.status_code in [403, 406, 419, 429, 503]:
            return True
        
        # Body content indicators
        body = response.text.lower()
        return any(indicator in body for indicator in self.block_indicators)
    
    @staticmethod
    def _extract_snippet(text: str, payload: str, context: int = 50) -> str:
        """Extract snippet showing payload reflection"""
        try:
            idx = text.lower().find(payload.lower())
            if idx == -1:
                return "Payload reflected (no exact position)"
            
            start = max(0, idx - context)
            end = min(len(text), idx + len(payload) + context)
            
            snippet = text[start:end]
            return f"...{snippet}..."
        except:
            return "Payload reflected"