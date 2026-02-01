#!/usr/bin/env python3
"""
Security Headers Auditor
"""

import sys
import requests
import argparse
import json
from datetime import datetime
from urllib.parse import urlparse
from colorama import init, Fore, Back, Style
import os

# Initialize colored output
init(autoreset=True)

class SecurityHeadersAuditor:
    def __init__(self, url, timeout=10, user_agent=None):
        self.url = self.normalize_url(url)
        self.timeout = timeout
        self.user_agent = user_agent or "Security-Headers-Auditor/1.1"
        self.headers = {}
        self.results = {}
        
    def normalize_url(self, url):
        """Normalize URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url
    
    def fetch_headers(self):
        """Fetch headers from the website"""
        try:
            headers = {'User-Agent': self.user_agent}
            response = requests.get(
                self.url, 
                timeout=self.timeout, 
                headers=headers,
                allow_redirects=True
            )
            self.headers = response.headers
            return True
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}Error fetching data: {e}")
            return False
    
    def check_header_exists(self, header_name):
        """Check if header exists"""
        return header_name.lower() in (h.lower() for h in self.headers.keys())
    
    def get_header_value(self, header_name):
        """Get header value (case-insensitive)"""
        for key, value in self.headers.items():
            if key.lower() == header_name.lower():
                return value
        return None
    
    def audit_security_headers(self):
        """Audit security headers"""
        checks = [
            self.check_content_security_policy,
            self.check_x_frame_options,
            self.check_x_content_type_options,
            self.check_strict_transport_security,
            self.check_referrer_policy,
            self.check_permissions_policy,
            self.check_x_xss_protection,
            self.check_cache_control,
            self.check_server_header,
        ]
        
        for check in checks:
            check()
    
    def check_content_security_policy(self):
        """Check Content-Security-Policy"""
        csp = self.get_header_value('Content-Security-Policy')
        
        if csp:
            score = 3
            status = "PRESENT"
            details = []
            
            directives = ['default-src', 'script-src', 'style-src', 'img-src', 'object-src']
            for directive in directives:
                if directive in csp.lower():
                    details.append(f"✓ {directive}")
            
            if "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp:
                score += 1
                details.append("✓ Safe policy (no unsafe-inline/eval)")
            
            if "'none'" in self.get_directive_value(csp, 'object-src'):
                score += 1
                details.append("✓ object-src 'none' (protection against Flash/Java)")
                
        else:
            score = 0
            status = "MISSING"
            details = ["❌ Missing CSP - high risk of XSS attacks"]
        
        self.results['Content-Security-Policy'] = {
            'score': min(score, 5),
            'status': status,
            'details': details,
            'value': csp
        }
    
    def get_directive_value(self, csp, directive):
        """Get directive value from CSP"""
        import re
        pattern = rf"{directive}\s+([^;]+)"
        match = re.search(pattern, csp, re.IGNORECASE)
        return match.group(1) if match else ""
    
    def check_x_frame_options(self):
        """Check X-Frame-Options"""
        xfo = self.get_header_value('X-Frame-Options')
        
        if xfo:
            xfo = xfo.upper()
            if xfo in ['DENY', 'SAMEORIGIN']:
                score = 3
                status = "SECURE"
                details = [f"✓ Secure policy: {xfo}"]
            else:
                score = 1
                status = "WEAK"
                details = [f"⚠ Weak policy: {xfo}"]
        else:
            score = 0
            status = "MISSING"
            details = ["❌ Missing - risk of clickjacking attacks"]
        
        self.results['X-Frame-Options'] = {
            'score': score,
            'status': status,
            'details': details,
            'value': xfo
        }
    
    def check_x_content_type_options(self):
        """Check X-Content-Type-Options"""
        xcto = self.get_header_value('X-Content-Type-Options')
        
        if xcto and xcto.lower() == 'nosniff':
            score = 2
            status = "SECURE"
            details = ["✓ Protection against MIME-sniffing"]
        else:
            score = 0
            status = "MISSING"
            details = ["❌ Missing - risk of MIME-sniffing attacks"]
        
        self.results['X-Content-Type-Options'] = {
            'score': score,
            'status': status,
            'details': details,
            'value': xcto
        }
    
    def check_strict_transport_security(self):
        """Check Strict-Transport-Security"""
        hsts = self.get_header_value('Strict-Transport-Security')
        
        if hsts:
            score = 3
            status = "PRESENT"
            details = []
            
            hsts_lower = hsts.lower()
            if 'max-age=' in hsts_lower:
                details.append("✓ max-age set")
                import re
                match = re.search(r'max-age=(\d+)', hsts_lower)
                if match:
                    max_age = int(match.group(1))
                    if max_age >= 31536000:
                        score += 1
                        details.append(f"✓ Long max-age: {max_age} seconds")
            
            if 'includesubdomains' in hsts_lower:
                score += 1
                details.append("✓ includeSubDomains enabled")
            
            if 'preload' in hsts_lower:
                score += 1
                details.append("✓ preload enabled")
                
        else:
            score = 0
            status = "MISSING"
            details = ["❌ Missing - no forced HTTPS"]
        
        self.results['Strict-Transport-Security'] = {
            'score': min(score, 5),
            'status': status,
            'details': details,
            'value': hsts
        }
    
    def check_referrer_policy(self):
        """Check Referrer-Policy"""
        rp = self.get_header_value('Referrer-Policy')
        secure_values = ['no-referrer', 'no-referrer-when-downgrade', 'strict-origin', 
                        'strict-origin-when-cross-origin', 'same-origin']
        
        if rp:
            if rp.lower() in secure_values:
                score = 2
                status = "SECURE"
                details = [f"✓ Secure policy: {rp}"]
            else:
                score = 1
                status = "WEAK"
                details = [f"⚠ Less secure policy: {rp}"]
        else:
            score = 0
            status = "MISSING"
            details = ["❌ Missing - risk of data leakage through Referer"]
        
        self.results['Referrer-Policy'] = {
            'score': score,
            'status': status,
            'details': details,
            'value': rp
        }
    
    def check_permissions_policy(self):
        """Check Permissions-Policy (formerly Feature-Policy)"""
        pp = self.get_header_value('Permissions-Policy') or self.get_header_value('Feature-Policy')
        
        if pp:
            score = 2
            status = "PRESENT"
            details = ["✓ Permissions policy configured"]
        else:
            score = 0
            status = "MISSING"
            details = ["⚠ Missing - limited control over browser features"]
        
        self.results['Permissions-Policy'] = {
            'score': score,
            'status': status,
            'details': details,
            'value': pp
        }
    
    def check_x_xss_protection(self):
        """Check X-XSS-Protection (deprecated, but we check it)"""
        xxss = self.get_header_value('X-XSS-Protection')
        
        if xxss:
            if '1; mode=block' in xxss:
                score = 1
                status = "LEGACY_SECURE"
                details = ["✓ Block mode enabled (header deprecated but configured correctly)"]
            else:
                score = 0
                status = "LEGACY_WEAK"
                details = [f"⚠ Deprecated header with weak configuration: {xxss}"]
        else:
            score = 0
            status = "MISSING"
            details = ["ℹ Missing (header deprecated, use CSP instead)"]
        
        self.results['X-XSS-Protection'] = {
            'score': score,
            'status': status,
            'details': details,
            'value': xxss
        }
    
    def check_cache_control(self):
        """Check Cache-Control for private data"""
        cc = self.get_header_value('Cache-Control')
        
        if cc:
            score = 1
            status = "PRESENT"
            details = [f"Cache-Control: {cc}"]
        else:
            score = 0
            status = "MISSING"
            details = ["⚠ Missing Cache-Control"]
        
        self.results['Cache-Control'] = {
            'score': score,
            'status': status,
            'details': details,
            'value': cc
        }
    
    def check_server_header(self):
        """Check Server header for server information"""
        server = self.get_header_value('Server')
        
        if server:
            score = 0
            status = "INFO_LEAK"
            details = [f"⚠ Server information exposed: {server}"]
        else:
            score = 1
            status = "SECURE"
            details = ["✓ Server information hidden"]
        
        self.results['Server-Info'] = {
            'score': score,
            'status': status,
            'details': details,
            'value': server
        }
    
    def calculate_total_score(self):
        """Calculate total score"""
        actual_score = sum(item['score'] for item in self.results.values())
        max_possible = 25
        
        percentage = (actual_score / max_possible) * 100 if max_possible > 0 else 0
        
        if percentage >= 90:
            grade = "A"
            color = Fore.GREEN
        elif percentage >= 75:
            grade = "B"
            color = Fore.YELLOW
        elif percentage >= 60:
            grade = "C"
            color = Fore.YELLOW
        elif percentage >= 40:
            grade = "D"
            color = Fore.RED
        else:
            grade = "F"
            color = Fore.RED
            
        return {
            'score': actual_score,
            'max_possible': max_possible,
            'percentage': percentage,
            'grade': grade,
            'color': color
        }
    
    def print_report(self):
        """Print report"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}SECURITY HEADERS AUDIT REPORT")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.WHITE}Website: {Fore.GREEN}{self.url}")
        print(f"{Fore.WHITE}Audit Time: {Fore.GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.CYAN}{'-'*60}")
        
        for header_name, result in self.results.items():
            status_color = {
                'SECURE': Fore.GREEN,
                'PRESENT': Fore.GREEN,
                'WEAK': Fore.YELLOW,
                'MISSING': Fore.RED,
                'INFO_LEAK': Fore.YELLOW,
                'LEGACY_SECURE': Fore.CYAN,
                'LEGACY_WEAK': Fore.YELLOW,
            }.get(result['status'], Fore.WHITE)
            
            print(f"\n{Fore.WHITE}{header_name}: {status_color}{result['status']}")
            if result['value']:
                print(f"  {Fore.CYAN}Value: {Fore.WHITE}{result['value']}")
            for detail in result['details']:
                print(f"  {detail}")
        
        total = self.calculate_total_score()
        print(f"\n{Fore.CYAN}{'-'*60}")
        print(f"{Fore.YELLOW}OVERALL SECURITY SCORE: {total['color']}{total['score']}/{total['max_possible']} "
              f"({total['percentage']:.1f}%)")
        print(f"{Fore.YELLOW}SECURITY GRADE: {total['color']}{total['grade']}")
        print(f"{Fore.CYAN}{'='*60}")
        
        print(f"\n{Fore.YELLOW}RECOMMENDATIONS:")
        recommendations = []
        
        if self.results['Content-Security-Policy']['status'] == 'MISSING':
            recommendations.append("Add Content-Security-Policy for XSS protection")
        
        if self.results['Strict-Transport-Security']['status'] == 'MISSING':
            recommendations.append("Add Strict-Transport-Security for forced HTTPS")
        
        if self.results['X-Frame-Options']['status'] == 'MISSING':
            recommendations.append("Add X-Frame-Options: DENY for clickjacking protection")
        
        if self.results['X-Content-Type-Options']['status'] == 'MISSING':
            recommendations.append("Add X-Content-Type-Options: nosniff")
        
        if not recommendations:
            recommendations.append("Excellent security! Keep maintaining the current configuration.")
        
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
    
    def export_to_json(self, output_file=None):
        """Export results to JSON file"""
        if not output_file:
            # Generate filename: json-report-YYYY-MM-DD-HH-MM-SS.json
            timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
            output_file = f"json-report-{timestamp}.json"
        
        report_data = {
            "audit_info": {
                "url": self.url,
                "audit_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "tool_version": "1.1.0"
            },
            "headers_found": {},
            "security_score": self.calculate_total_score(),
            "detailed_results": {}
        }
        
        # Add all found headers
        for header, value in self.headers.items():
            report_data["headers_found"][header] = value
        
        # Add security analysis results
        for header_name, result in self.results.items():
            report_data["detailed_results"][header_name] = {
                "status": result["status"],
                "score": result["score"],
                "value": result["value"],
                "details": result["details"]
            }
        
        # Add recommendations
        report_data["recommendations"] = []
        if self.results['Content-Security-Policy']['status'] == 'MISSING':
            report_data["recommendations"].append("Add Content-Security-Policy for XSS protection")
        if self.results['Strict-Transport-Security']['status'] == 'MISSING':
            report_data["recommendations"].append("Add Strict-Transport-Security for forced HTTPS")
        if self.results['X-Frame-Options']['status'] == 'MISSING':
            report_data["recommendations"].append("Add X-Frame-Options: DENY for clickjacking protection")
        if self.results['X-Content-Type-Options']['status'] == 'MISSING':
            report_data["recommendations"].append("Add X-Content-Type-Options: nosniff")
        
        # Write to file
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            return output_file
        except Exception as e:
            print(f"{Fore.RED}Error exporting to JSON: {e}")
            return None

def main():
    parser = argparse.ArgumentParser(
        description='Security Headers Auditor - security headers auditing tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  python3 main.py https://example.com
  python3 main.py example.com
  python3 main.py --json https://example.com
  python3 main.py --timeout 15 https://google.com
        """
    )
    
    parser.add_argument('url', help='Website URL to audit')
    parser.add_argument('--timeout', type=int, default=10, 
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--user-agent', help='Custom User-Agent')
    parser.add_argument('--json', action='store_true', 
                       help='Export results to JSON file')
    parser.add_argument('--output', help='Custom output JSON filename')
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    
    # Create auditor
    auditor = SecurityHeadersAuditor(
        url=args.url,
        timeout=args.timeout,
        user_agent=args.user_agent
    )
    
    print(f"{Fore.CYAN}🔍 Security analysis for: {Fore.GREEN}{args.url}")
    print(f"{Fore.CYAN}⏳ Fetching headers...")
    
    if auditor.fetch_headers():
        auditor.audit_security_headers()
        
        if args.json:
            # Export to JSON
            output_file = auditor.export_to_json(args.output)
            if output_file:
                print(f"{Fore.GREEN}✅ Report saved to: {output_file}")
                print(f"{Fore.CYAN}📊 You can also view the text report below:")
                auditor.print_report()
            else:
                print(f"{Fore.RED}❌ Failed to save JSON report")
                auditor.print_report()
        else:
            # Just print report
            auditor.print_report()
    else:
        print(f"{Fore.RED}Failed to fetch data from the website")
        sys.exit(1)

if __name__ == "__main__":
    main()