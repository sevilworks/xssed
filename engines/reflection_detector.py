"""
Fast reflection detection using async HTTP requests
Filters out non-reflecting URLs before expensive browser verification
"""

import asyncio
import httpx
from typing import List, Dict, Set
from urllib.parse import unquote, urlparse, parse_qs
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)


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

                        # Print URL with highlighted parameter in yellow
                        self._print_reflected_url(url_data)
            
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
            # Skip .js files as they are static and cannot execute JavaScript
            parsed_url = urlparse(url_data['url'])
            if '.js' in parsed_url.path:
                return result

            # Skip if domain is known to be blocked
            domain = parsed_url.netloc
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

    def _print_reflected_url(self, url_data: Dict):
        """Print URL with highlighted parameter in yellow"""
        try:
            url = url_data['url']
            param_name = url_data['parameter']

            # Parse URL to highlight the parameter
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            # Rebuild query string with highlighted parameter
            query_parts = []
            for p_name, p_values in params.items():
                if p_name == param_name:
                    # Yellow highlighting for parameter name and value
                    highlighted_name = f"{Fore.YELLOW}{p_name}{Style.RESET_ALL}"
                    if p_values:
                        highlighted_value = f"{Fore.YELLOW}{p_values[0]}{Style.RESET_ALL}"
                        query_parts.append(f"{highlighted_name}={highlighted_value}")
                    else:
                        query_parts.append(f"{highlighted_name}")
                else:
                    if p_values:
                        query_parts.append(f"{p_name}={p_values[0]}")
                    else:
                        query_parts.append(p_name)

            query_string = '&'.join(query_parts)
            display_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

            # Print with reflection indicator
            print(f"\n[✓] REFLECTED: {display_url}")

        except Exception as e:
            # Fallback to simple print if parsing fails
            print(f"\n[✓] REFLECTED: {url_data['url']} (param: {url_data['parameter']})")

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