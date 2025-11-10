"""
Report generation and formatting
Creates human-readable and machine-readable reports
"""

import json
from typing import Dict
from pathlib import Path
from datetime import datetime


class ReportGenerator:
    def __init__(self, results: Dict):
        self.results = results
    
    def generate_report(self) -> Dict:
        """Generate comprehensive report"""
        report = {
            'scan_info': {
                'target': self.results['target'],
                'start_time': self.results['start_time'],
                'end_time': self.results['end_time'],
                'duration': self._calculate_duration()
            },
            'statistics': {
                'total_urls_tested': self.results['total_urls_tested'],
                'reflected_urls': self.results['reflected_urls'],
                'verified_vulnerabilities': len(self.results['vulnerabilities']),
                'false_positives_filtered': self.results['false_positives_filtered'],
                'accuracy_rate': self._calculate_accuracy()
            },
            'waf_detection': self.results.get('waf_detected'),
            'vulnerabilities': self.results['vulnerabilities']
        }
        
        return report
    
    def get_summary(self) -> str:
        """Get human-readable summary"""
        vuln_count = len(self.results['vulnerabilities'])
        
        summary = f"""
╔════════════════════════════════════════════════════════════╗
║                    SCAN SUMMARY                            ║
╠════════════════════════════════════════════════════════════╣
║ Target:                {self.results['target']:<35} ║
║ URLs Tested:           {self.results['total_urls_tested']:<35} ║
║ Reflected:             {self.results['reflected_urls']:<35} ║
║ Verified XSS:          {vuln_count:<35} ║
║ False Positives:       {self.results['false_positives_filtered']:<35} ║
║ Accuracy Rate:         {self._calculate_accuracy():<35} ║
╚════════════════════════════════════════════════════════════╝
"""
        
        # Add WAF info if detected
        if self.results.get('waf_detected', {}).get('detected'):
            waf_info = self.results['waf_detected']
            summary += f"\n[!] WAF Detected: {waf_info['type']} (Confidence: {waf_info['confidence']:.0%})\n"
        
        # List vulnerabilities
        if vuln_count > 0:
            summary += "\n" + "="*60 + "\n"
            summary += "VERIFIED VULNERABILITIES:\n"
            summary += "="*60 + "\n\n"
            
            for idx, vuln in enumerate(self.results['vulnerabilities'], 1):
                summary += f"[{idx}] {vuln['severity']} - {vuln['parameter']}\n"
                summary += f"    URL: {vuln['url']}\n"
                summary += f"    Payload: {vuln['payload'][:60]}...\n"
                summary += f"    Context: {vuln['context']}\n"
                
                # Show evidence
                if vuln['evidence']:
                    summary += f"    Evidence:\n"
                    for evidence in vuln['evidence'][:2]:  # Show first 2 pieces
                        summary += f"      - {evidence['type']}: {evidence.get('details', 'Detected')}\n"
                
                if vuln.get('screenshot'):
                    summary += f"    Screenshot: {vuln['screenshot']}\n"
                
                summary += "\n"
        else:
            summary += "\n[*] No verified XSS vulnerabilities found.\n"
        
        return summary
    
    def save_json(self, filepath: Path):
        """Save full report as JSON"""
        report = self.generate_report()
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
    
    def save_markdown(self, filepath: Path):
        """Save report as Markdown"""
        report = self.generate_report()
        
        md = f"""# XSS Scan Report

## Scan Information
- **Target**: {report['scan_info']['target']}
- **Start Time**: {report['scan_info']['start_time']}
- **End Time**: {report['scan_info']['end_time']}
- **Duration**: {report['scan_info']['duration']}

## Statistics
- **Total URLs Tested**: {report['statistics']['total_urls_tested']}
- **Reflected URLs**: {report['statistics']['reflected_urls']}
- **Verified Vulnerabilities**: {report['statistics']['verified_vulnerabilities']}
- **False Positives Filtered**: {report['statistics']['false_positives_filtered']}
- **Accuracy Rate**: {report['statistics']['accuracy_rate']}

"""
        
        # Add WAF section
        if report['waf_detection'] and report['waf_detection']['detected']:
            waf = report['waf_detection']
            md += f"""## WAF Detection
- **Detected**: Yes
- **Type**: {waf['type']}
- **Confidence**: {waf['confidence']:.0%}
- **Indicators**: {', '.join(waf['indicators'])}

"""
        
        # Add vulnerabilities
        if report['vulnerabilities']:
            md += "## Vulnerabilities\n\n"
            
            for idx, vuln in enumerate(report['vulnerabilities'], 1):
                md += f"### [{idx}] {vuln['severity']} - {vuln['parameter']}\n\n"
                md += f"- **URL**: `{vuln['url']}`\n"
                md += f"- **Payload**: `{vuln['payload']}`\n"
                md += f"- **Context**: {vuln['context']}\n"
                md += f"- **Verified At**: {vuln['verified_at']}\n\n"
                
                if vuln['evidence']:
                    md += "**Evidence:**\n"
                    for evidence in vuln['evidence']:
                        md += f"- {evidence['type']}: {evidence.get('details', 'Detected')}\n"
                    md += "\n"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(md)
    
    def _calculate_duration(self) -> str:
        """Calculate scan duration"""
        if not self.results['start_time'] or not self.results['end_time']:
            return "Unknown"
        
        try:
            start = datetime.fromisoformat(self.results['start_time'])
            end = datetime.fromisoformat(self.results['end_time'])
            duration = end - start
            
            minutes = int(duration.total_seconds() // 60)
            seconds = int(duration.total_seconds() % 60)
            
            return f"{minutes}m {seconds}s"
        except:
            return "Unknown"
    
    def _calculate_accuracy(self) -> str:
        """Calculate accuracy rate"""
        reflected = self.results['reflected_urls']
        if reflected == 0:
            return "N/A"
        
        verified = len(self.results['vulnerabilities'])
        false_positives = self.results['false_positives_filtered']
        
        if reflected == 0:
            return "100%"
        
        accuracy = (verified / reflected) * 100
        return f"{accuracy:.1f}%"