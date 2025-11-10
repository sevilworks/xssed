"""
URL processing and parameter manipulation
Handles URL collection, parsing, and payload injection
"""

import asyncio
import subprocess
from typing import List, Dict, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote


class URLProcessor:
    def __init__(self, target: str, max_urls: int = 1000):
        self.target = target
        self.max_urls = max_urls
        
        # Ensure target has proper format
        
        
        #if not target.startswith(('http://', 'https://')):
        #    self.target = f"https://{target}"
    
    async def fetch_wayback_urls(self) -> List[str]:
        """Fetch URLs from Wayback Machine using waybackurls tool"""
        print(f"[*] Fetching URLs for {self.target} from Wayback Machine...")

        try:
            # Run waybackurls subprocess
            loop = asyncio.get_event_loop()
            urls = await loop.run_in_executor(
                None,
                self._fetch_wayback_sync
            )

            # Filter URLs with parameters
            urls_with_params = [
                url for url in urls
                if '?' in url and '=' in url
            ]

            # Deduplicate by URL structure (ignore parameter values)
            unique_urls = self._deduplicate_urls(urls_with_params)

            # Limit number of URLs
            return list(unique_urls)[:self.max_urls]

        except Exception as e:
            print(f"[!] Error fetching Wayback URLs: {e}")
            return []

    def _fetch_wayback_sync(self) -> List[str]:
        """Synchronous Wayback fetch using waybackurls tool"""
        urls = set()

        try:
            # Invoke waybackurls tool
            result = subprocess.run(
                ['waybackurls', self.target],
                capture_output=True,
                text=True, # 60 second timeout
            )

            if result.returncode == 0:
                # Parse stdout for URLs
                output_lines = result.stdout.strip().split('\n')
                for line in output_lines:
                    line = line.strip()
                    if line and line.startswith(('http://', 'https://')):
                        # Only keep URLs with parameters
                        if '?' in line and '=' in line:
                            urls.add(line)

                        # Respect max limit
                        if len(urls) >= self.max_urls * 2:  # Fetch more for deduplication
                            break
            else:
                print(f"[!] waybackurls tool failed: {result.stderr}")

        except subprocess.TimeoutExpired:
            print("[!] waybackurls tool timed out")
        except FileNotFoundError:
            print("[!] waybackurls tool not found. Please install it from https://github.com/tomnomnom/waybackurls")
        except Exception as e:
            print(f"[!] Wayback tool error: {e}")

        return list(urls)
    
    def _deduplicate_urls(self, urls: List[str]) -> Set[str]:
        """Deduplicate URLs by structure, keeping unique parameter combinations"""
        seen_structures = set()
        unique_urls = []
        
        for url in urls:
            # Parse URL
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Create structure signature (path + param names)
            param_names = sorted(params.keys())
            structure = f"{parsed.netloc}{parsed.path}?{','.join(param_names)}"
            
            if structure not in seen_structures:
                seen_structures.add(structure)
                unique_urls.append(url)
        
        return set(unique_urls)
    
    def extract_parameters(self, url: str) -> Dict[str, str]:
        """Extract all parameters from URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Flatten lists to single values
        return {k: v[0] if v else '' for k, v in params.items()}
    
    def detect_context(self, url: str, param_name: str) -> str:
        """Detect injection context for a parameter"""
        # Simple heuristic based on parameter name
        param_lower = param_name.lower()
        
        if any(keyword in param_lower for keyword in ['url', 'redirect', 'link', 'href']):
            return 'url'
        elif any(keyword in param_lower for keyword in ['style', 'css', 'color']):
            return 'style'
        elif any(keyword in param_lower for keyword in ['id', 'class', 'name', 'data']):
            return 'attribute'
        elif any(keyword in param_lower for keyword in ['callback', 'jsonp', 'js']):
            return 'script'
        else:
            return 'html'  # Default to HTML context
    
    def inject_payload(self, url: str, param_name: str, payload: str) -> str:
        """Inject payload into specific parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Replace parameter value with payload
        if param_name in params:
            params[param_name] = [payload]
        else:
            # Parameter might have been removed, add it back
            params[param_name] = [payload]
        
        # Rebuild query string
        new_query = urlencode(params, doseq=True, quote_via=quote)
        
        # Rebuild URL
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        
        return new_url