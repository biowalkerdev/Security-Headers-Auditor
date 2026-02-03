#!/usr/bin/env python3
"""
Security Headers Auditor
"""

import sys
import requests
import argparse
import json
import os
import time
from datetime import datetime
from urllib.parse import urlparse
from colorama import init, Fore, Back, Style

# Initialize colored output
init(autoreset=True)

# Cache configuration
CACHE_DIR = "cache"

def ensure_cache_dir():
    """Create cache directory if it doesn't exist"""
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)

def get_cache_filename(url):
    """Convert URL to cache filename"""
    # Normalize URL first
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else parsed.path
    # Remove www. for consistency
    if domain.startswith('www.'):
        domain = domain[4:]
    # Replace dots with underscores and remove special chars
    filename = domain.replace('.', '_').replace(':', '_').replace('/', '_')
    # Remove trailing underscores
    filename = filename.rstrip('_')
    return f"{filename}.json"

def save_to_cache(url, data):
    """Save scan results to cache"""
    ensure_cache_dir()
    cache_file = os.path.join(CACHE_DIR, get_cache_filename(url))
    
    cache_data = {
        "url": url,
        "scan_timestamp": datetime.now().isoformat(),
        "results": data
    }
    
    try:
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"{Fore.YELLOW}⚠ Could not save to cache: {e}")
        return False

def load_from_cache(url):
    """Load scan results from cache"""
    cache_file = os.path.join(CACHE_DIR, get_cache_filename(url))
    
    if not os.path.exists(cache_file):
        return None
    
    try:
        with open(cache_file, 'r', encoding='utf-8') as f:
            cache_data = json.load(f)
        return cache_data["results"]
    except Exception as e:
        print(f"{Fore.YELLOW}⚠ Corrupted cache file: {e}")
        return None

def clear_cache():
    """Clear all cache files"""
    if os.path.exists(CACHE_DIR):
        import shutil
        shutil.rmtree(CACHE_DIR)
        print(f"{Fore.GREEN}✅ Cache cleared")
        return True
    return False

class SecurityHeadersAuditor:
    def __init__(self, url, timeout=10, user_agent=None, use_cache=False):
        self.url = self.normalize_url(url)
        self.timeout = timeout
        self.user_agent = user_agent or "Security-Headers-Auditor/1.2"
        self.headers = {}
        self.results = {}
        self.use_cache = use_cache
        
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
    
    def audit(self, from_cache=False):
        """Perform audit (or load from cache)"""
        if from_cache:
            print(f"{Fore.YELLOW}📁 Loading from cache...")
            return True
            
        print(f"{Fore.CYAN}⏳ Fetching headers...")
        if not self.fetch_headers():
            return False
            
        self.audit_security_headers()
        return True
    
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
            timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
            output_file = f"json-report-{timestamp}.json"
        
        report_data = {
            "audit_info": {
                "url": self.url,
                "audit_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "tool_version": "1.2.0"
            },
            "headers_found": {},
            "security_score": self.calculate_total_score(),
            "detailed_results": {}
        }
        
        for header, value in self.headers.items():
            report_data["headers_found"][header] = value
        
        for header_name, result in self.results.items():
            report_data["detailed_results"][header_name] = {
                "status": result["status"],
                "score": result["score"],
                "value": result["value"],
                "details": result["details"]
            }
        
        report_data["recommendations"] = []
        if self.results['Content-Security-Policy']['status'] == 'MISSING':
            report_data["recommendations"].append("Add Content-Security-Policy for XSS protection")
        if self.results['Strict-Transport-Security']['status'] == 'MISSING':
            report_data["recommendations"].append("Add Strict-Transport-Security for forced HTTPS")
        if self.results['X-Frame-Options']['status'] == 'MISSING':
            report_data["recommendations"].append("Add X-Frame-Options: DENY for clickjacking protection")
        if self.results['X-Content-Type-Options']['status'] == 'MISSING':
            report_data["recommendations"].append("Add X-Content-Type-Options: nosniff")
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            return output_file
        except Exception as e:
            print(f"{Fore.RED}Error exporting to JSON: {e}")
            return None

def batch_scan(file_path, use_cache=False, timeout=10, user_agent=None, export_json=False):
    """Perform batch scan from file"""
    if not os.path.exists(file_path):
        print(f"{Fore.RED}Error: File '{file_path}' not found")
        return False
    
    try:
        with open(file_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"{Fore.RED}Error reading file: {e}")
        return False
    
    if not urls:
        print(f"{Fore.YELLOW}No URLs found in file")
        return False
    
    print(f"{Fore.CYAN}🔍 Starting batch scan of {len(urls)} sites...")
    print(f"{Fore.CYAN}📁 Cache mode: {'ON' if use_cache else 'OFF'}")
    
    results = []
    start_time = time.time()
    
    for i, url in enumerate(urls, 1):
        print(f"\n{Fore.CYAN}[{i}/{len(urls)}] Scanning: {url}")
        
        # Try to load from cache if enabled
        cached_results = None
        if use_cache:
            cached_results = load_from_cache(url)
        
        if cached_results:
            print(f"{Fore.YELLOW}   📁 Using cached results")
            auditor = SecurityHeadersAuditor(url, timeout, user_agent, use_cache)
            auditor.results = cached_results
            results.append(auditor)
        else:
            auditor = SecurityHeadersAuditor(url, timeout, user_agent, use_cache)
            if auditor.audit():
                results.append(auditor)
                if use_cache:
                    # Save to cache
                    save_to_cache(url, auditor.results)
            else:
                print(f"{Fore.RED}   ❌ Failed to scan")
    
    end_time = time.time()
    duration = end_time - start_time
    
    # Summary
    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"{Fore.YELLOW}✅ BATCH SCAN COMPLETED")
    print(f"{Fore.GREEN}{'='*60}")
    print(f"{Fore.CYAN}📊 Summary:")
    print(f"  • Total sites: {len(urls)}")
    print(f"  • Successfully scanned: {len(results)}")
    print(f"  • Failed: {len(urls) - len(results)}")
    print(f"  • Total time: {duration:.1f} seconds")
    print(f"  • Average time per site: {duration/len(urls):.1f} seconds" if results else "")
    
    if results:
        # Calculate overall statistics
        scores = [a.calculate_total_score()['score'] for a in results]
        avg_score = sum(scores) / len(scores) if scores else 0
        
        grades = {'A': 0, 'B': 0, 'C': 0, 'D': 0, 'F': 0}
        for a in results:
            grade = a.calculate_total_score()['grade']
            grades[grade] = grades.get(grade, 0) + 1
        
        print(f"\n{Fore.CYAN}📈 Security Statistics:")
        print(f"  • Average score: {avg_score:.1f}/25")
        print(f"  • Grade distribution:")
        for grade, count in grades.items():
            if count > 0:
                print(f"      {grade}: {count} sites")
    
    # Export batch results to JSON if requested
    if export_json:
        batch_report = {
            "batch_info": {
                "total_sites": len(urls),
                "successful_scans": len(results),
                "failed_scans": len(urls) - len(results),
                "scan_duration": f"{duration:.1f}s",
                "cache_used": use_cache,
                "scan_time": datetime.now().isoformat()
            },
            "sites": []
        }
        
        for auditor in results:
            site_report = {
                "url": auditor.url,
                "score": auditor.calculate_total_score()['score'],
                "grade": auditor.calculate_total_score()['grade'],
                "headers_found": {h: v for h, v in auditor.headers.items()}
            }
            batch_report["sites"].append(site_report)
        
        batch_file = f"batch-report-{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}.json"
        try:
            with open(batch_file, 'w', encoding='utf-8') as f:
                json.dump(batch_report, f, indent=2, ensure_ascii=False)
            print(f"\n{Fore.GREEN}📁 Batch report saved to: {batch_file}")
        except Exception as e:
            print(f"{Fore.RED}Error saving batch report: {e}")
    
    print(f"\n{Fore.YELLOW}💡 Tip: Use --cache for faster repeated scans")
    return True

def main():
    parser = argparse.ArgumentParser(
        description='Security Headers Auditor v1.2 - Batch Scanning & Caching',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Single site scan:
    python main.py https://example.com
  
  Single site with cache:
    python main.py --cache https://example.com
  
  Batch scan without cache:
    python main.py --batch urls.txt
  
  Batch scan with cache:
    python main.py --batch urls.txt --cache
  
  Export to JSON:
    python main.py --json https://example.com
  
  Clear cache:
    python main.py --clear-cache
        """
    )
    
    parser.add_argument('url', nargs='?', help='Website URL to audit')
    parser.add_argument('--batch', metavar='FILE', help='Batch scan from file with URLs')
    parser.add_argument('--cache', action='store_true', 
                       help='Use cache for faster scanning (saves/loads results)')
    parser.add_argument('--clear-cache', action='store_true', 
                       help='Clear all cached results')
    parser.add_argument('--timeout', type=int, default=10, 
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--user-agent', help='Custom User-Agent')
    parser.add_argument('--json', action='store_true', 
                       help='Export results to JSON file')
    parser.add_argument('--output', help='Custom output JSON filename')
    
    args = parser.parse_args()
    
    # Handle clear-cache command
    if args.clear_cache:
        clear_cache()
        sys.exit(0)
    
    # Handle batch scan
    if args.batch:
        success = batch_scan(
            args.batch, 
            use_cache=args.cache,
            timeout=args.timeout,
            user_agent=args.user_agent,
            export_json=args.json
        )
        sys.exit(0 if success else 1)
    
    # Handle single URL scan
    if not args.url:
        print(f"{Fore.RED}Error: URL is required for single site scan")
        parser.print_help()
        sys.exit(1)
    
    print(f"{Fore.CYAN}🔍 Security analysis for: {Fore.GREEN}{args.url}")
    
    # Try to load from cache if enabled
    cached_results = None
    if args.cache:
        cached_results = load_from_cache(args.url)
    
    auditor = SecurityHeadersAuditor(
        url=args.url,
        timeout=args.timeout,
        user_agent=args.user_agent,
        use_cache=args.cache
    )
    
    if cached_results:
        # Load from cache
        auditor.results = cached_results
        auditor.print_report()
        print(f"\n{Fore.YELLOW}📁 Results loaded from cache")
    else:
        # Perform fresh audit
        if auditor.audit():
            auditor.print_report()
            # Save to cache if enabled
            if args.cache:
                save_to_cache(args.url, auditor.results)
                print(f"\n{Fore.GREEN}📁 Results saved to cache")
        else:
            print(f"{Fore.RED}Failed to fetch data from the website")
            sys.exit(1)
    
    # Export to JSON if requested
    if args.json:
        output_file = auditor.export_to_json(args.output)
        if output_file:
            print(f"{Fore.GREEN}📁 JSON report saved to: {output_file}")

if __name__ == "__main__":
    main()