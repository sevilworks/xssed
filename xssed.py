#!/usr/bin/env python3
"""
xssed - Intelligent XSS Scanner
High-accuracy XSS detection with two-phase verification
"""

import asyncio
import argparse
import sys
from pathlib import Path
from typing import Optional

from core.scanner import XSSScanner
from utils.report_generator import ReportGenerator


def parse_args():
    parser = argparse.ArgumentParser(
        description='xssed - Intelligent XSS Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  xssed -t example.com
  xssed -t example.com -p custom_payloads.txt -c 20
  xssed -t example.com --no-waf-check -T 30
        """
    )
    
    parser.add_argument(
        '-t', '--target',
        required=True,
        help='Target domain (e.g., example.com)'
    )
    
    parser.add_argument(
        '-p', '--payloads',
        help='Custom payload file path',
        type=Path
    )
    
    parser.add_argument(
        '-c', '--concurrency',
        type=int,
        default=10,
        help='Concurrent requests (default: 10)'
    )
    
    parser.add_argument(
        '-T', '--timeout',
        type=int,
        default=15,
        help='Request timeout in seconds (default: 15)'
    )
    
    parser.add_argument(
        '--no-waf-check',
        action='store_true',
        help='Skip WAF detection'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output report file (JSON)',
        type=Path
    )
    
    parser.add_argument(
        '--screenshots',
        action='store_true',
        help='Save screenshots of successful XSS'
    )
    
    parser.add_argument(
        '--max-urls',
        type=int,
        default=1000,
        help='Maximum URLs to test (default: 1000)'
    )
    
    return parser.parse_args()


async def main():
    args = parse_args()
    
    print(f"""
╔═══════════════════════════════════════╗
║           xssed - XSS Scanner         ║
║      High-Accuracy XSS Detection      ║
╚═══════════════════════════════════════╝

[*] Target: {args.target}
[*] Concurrency: {args.concurrency}
[*] Timeout: {args.timeout}s
[*] WAF Detection: {'Disabled' if args.no_waf_check else 'Enabled'}
""")
    
    try:
        # Initialize scanner
        scanner = XSSScanner(
            target=args.target,
            payload_file=args.payloads,
            concurrency=args.concurrency,
            timeout=args.timeout,
            waf_check=not args.no_waf_check,
            screenshots=args.screenshots,
            max_urls=args.max_urls
        )
        
        # Run scan
        print("[*] Starting scan...\n")
        results = await scanner.scan()
        
        # Generate report
        report_gen = ReportGenerator(results)
        report = report_gen.generate_report()
        
        # Print summary
        print("\n" + "="*60)
        print(report_gen.get_summary())
        print("="*60)
        
        # Save to file if requested
        if args.output:
            report_gen.save_json(args.output)
            print(f"\n[+] Full report saved to: {args.output}")
        
        # Exit with appropriate code
        sys.exit(0 if results['vulnerabilities'] else 1)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    asyncio.run(main())