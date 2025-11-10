"""
Payload generation and management
Context-aware payload selection for maximum accuracy
"""

from typing import List, Optional
from pathlib import Path
from config.payloads import DEFAULT_PAYLOADS, WAF_BYPASS_PAYLOADS


class PayloadManager:
    def __init__(self, custom_payload_file: Optional[Path] = None):
        self.custom_payloads = []
        
        if custom_payload_file and custom_payload_file.exists():
            self._load_custom_payloads(custom_payload_file)
    
    def _load_custom_payloads(self, filepath: Path):
        """Load custom payloads from file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                self.custom_payloads = [
                    line.strip() 
                    for line in f 
                    if line.strip() and not line.startswith('#')
                ]
            print(f"[+] Loaded {len(self.custom_payloads)} custom payloads")
        except Exception as e:
            print(f"[!] Error loading custom payloads: {e}")
    
    def get_payloads_for_context(self, context: str) -> List[str]:
        """Get appropriate payloads based on injection context"""
        if self.custom_payloads:
            return self.custom_payloads
        
        # Use default context-aware payloads
        return DEFAULT_PAYLOADS.get(context, DEFAULT_PAYLOADS['generic'])
    
    def get_waf_bypass_payloads(self, waf_type: str, context: str) -> List[str]:
        """Get WAF-specific bypass payloads"""
        if waf_type in WAF_BYPASS_PAYLOADS:
            bypasses = WAF_BYPASS_PAYLOADS[waf_type].get(
                context, 
                WAF_BYPASS_PAYLOADS[waf_type].get('generic', [])
            )
            return bypasses
        
        return self.get_payloads_for_context(context)
    
    def generate_mutation(self, payload: str, mutation_type: str) -> str:
        """Generate payload mutations for evasion"""
        mutations = {
            'case_variation': lambda p: p.swapcase(),
            'encoding': lambda p: self._encode_payload(p),
            'whitespace': lambda p: self._add_whitespace(p),
            'comment_injection': lambda p: self._inject_comments(p),
        }
        
        if mutation_type in mutations:
            return mutations[mutation_type](payload)
        
        return payload
    
    @staticmethod
    def _encode_payload(payload: str) -> str:
        """Apply various encoding techniques"""
        # HTML entity encoding for key characters
        encoded = payload.replace('<', '&lt;')
        encoded = encoded.replace('>', '&gt;')
        return encoded
    
    @staticmethod
    def _add_whitespace(payload: str) -> str:
        """Add whitespace variations"""
        # Add tabs and newlines
        return payload.replace('<', '<\t').replace('>', '\n>')
    
    @staticmethod
    def _inject_comments(payload: str) -> str:
        """Inject HTML/JS comments"""
        if '<script>' in payload:
            return payload.replace('<script>', '<script><!--')
        return payload