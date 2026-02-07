#!/usr/bin/env python3

import sys
import requests
import argparse
import json
import os
import time
import re
from datetime import datetime
from urllib.parse import urlparse
from colorama import init, Fore, Back, Style

init(autoreset=True)

CACHE_DIR = "cache"

def ensure_cache_dir():
    if not os.path.exists(CACHE_DIR):
        os.makedirs(CACHE_DIR)

def get_cache_filename(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    parsed = urlparse(url)
    domain = parsed.netloc if parsed.netloc else parsed.path
    if domain.startswith('www.'):
        domain = domain[4:]
    filename = domain.replace('.', '_').replace(':', '_').replace('/', '_')
    filename = filename.rstrip('_')
    return f"{filename}.json"

def save_to_cache(url, data):
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
    except Exception:
        return False

def load_from_cache(url):
    cache_file = os.path.join(CACHE_DIR, get_cache_filename(url))
    
    if not os.path.exists(cache_file):
        return None
    
    try:
        with open(cache_file, 'r', encoding='utf-8') as f:
            cache_data = json.load(f)
        return cache_data["results"]
    except Exception:
        return None

def clear_cache():
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
        self.user_agent = user_agent or "Security-Headers-Auditor/1.3"
        self.headers = {}
        self.results = {}
        self.use_cache = use_cache
        self.raw_cookies = []
        self.detailed_csp = {}
        
    def validate_url(self, url):
        try:
            parsed = urlparse(url)
            return all([parsed.scheme, parsed.netloc])
        except:
            return False
    
    def normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url
    
    def fetch_headers(self):
        try:
            headers = {'User-Agent': self.user_agent}
            
            for attempt in range(3):
                try:
                    response = requests.get(
                        self.url, 
                        timeout=self.timeout, 
                        headers=headers,
                        allow_redirects=True,
                        verify=True
                    )
                    
                    self.headers = response.headers
                    self.raw_cookies = response.cookies
                    
                    if response.status_code == 200:
                        return True
                    else:
                        print(f"{Fore.YELLOW}⚠ Status {response.status_code}")
                        
                except requests.exceptions.Timeout:
                    if attempt == 2:
                        print(f"{Fore.RED}Timeout after {self.timeout}s")
                        return False
                    time.sleep(1)
                    
                except requests.exceptions.SSLError:
                    print(f"{Fore.RED}SSL Error")
                    return False
                    
                except requests.exceptions.ConnectionError:
                    if attempt == 2:
                        print(f"{Fore.RED}Connection failed")
                        return False
                    time.sleep(1)
                    
            return False
            
        except Exception as e:
            print(f"{Fore.RED}Error: {e}")
            return False
    
    def audit(self, from_cache=False):
        if from_cache:
            print(f"{Fore.YELLOW}📁 Loading from cache...")
            return True
            
        print(f"{Fore.CYAN}⏳ Scanning...")
        if not self.fetch_headers():
            return False
            
        self.audit_security_headers()
        return True
    
    def check_header_exists(self, header_name):
        return header_name.lower() in (h.lower() for h in self.headers.keys())
    
    def get_header_value(self, header_name):
        for key, value in self.headers.items():
            if key.lower() == header_name.lower():
                return value
        return None
    
    def audit_security_headers(self):
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
            self.check_expect_ct,
            self.check_cross_origin_policies,
            self.check_cookies_security,
            self.check_report_to,
            self.check_content_type,
        ]
        
        for check in checks:
            check()
    
    def parse_csp_directives(self, csp):
        directives = {}
        if not csp:
            return directives
        
        parts = [part.strip() for part in csp.split(';') if part.strip()]
        
        for part in parts:
            if ' ' in part:
                directive, *values = part.split()
                directives[directive.lower()] = values
            else:
                directives[part.lower()] = []
        
        return directives
    
    def analyze_csp_risks(self, directives):
        risks = []
        recommendations = []
        
        if 'default-src' not in directives:
            risks.append("Missing default-src directive")
            recommendations.append("Add default-src directive with appropriate sources")
        
        unsafe_patterns = {
            'unsafe-inline': "Allows inline scripts/styles",
            'unsafe-eval': "Allows eval() in scripts",
            'unsafe-hashes': "Allows hashed inline scripts",
            'data:': "Allows data: URIs",
            'blob:': "Allows blob: URIs",
            '*': "Wildcard source (too permissive)"
        }
        
        for directive, values in directives.items():
            for value in values:
                lower_value = value.lower()
                if lower_value in unsafe_patterns:
                    risks.append(f"{directive} contains {lower_value}")
                    recommendations.append(f"Remove {lower_value} from {directive}")
        
        if 'script-src' not in directives and 'default-src' in directives:
            if "'self'" in directives.get('default-src', []):
                recommendations.append("Consider adding explicit script-src directive")
        
        if 'object-src' in directives:
            if "'none'" in directives['object-src']:
                recommendations.append("Good: object-src set to 'none'")
            else:
                risks.append("object-src not restricted")
                recommendations.append("Set object-src to 'none' to prevent Flash/Java attacks")
        
        if 'frame-ancestors' not in directives:
            recommendations.append("Consider adding frame-ancestors for clickjacking protection")
        
        return risks, recommendations
    
    def check_content_security_policy(self):
        csp = self.get_header_value('Content-Security-Policy')
        csp_report_only = self.get_header_value('Content-Security-Policy-Report-Only')
        
        if csp:
            directives = self.parse_csp_directives(csp)
            self.detailed_csp = directives
            risks, recommendations = self.analyze_csp_risks(directives)
            
            score = 4
            status = "PRESENT"
            details = ["✓ CSP implemented"]
            
            if not risks:
                score += 1
                details.append("✓ No unsafe directives detected")
            
            if 'object-src' in directives and "'none'" in directives['object-src']:
                score += 1
                details.append("✓ object-src set to 'none'")
            
            if "'unsafe-inline'" not in csp and "'unsafe-eval'" not in csp:
                score += 1
                details.append("✓ No unsafe-inline/eval")
            
            if risks:
                details.extend([f"⚠ {risk}" for risk in risks])
            
            if csp_report_only:
                details.append("ℹ CSP-Report-Only also present (testing mode)")
                
        else:
            score = 0
            status = "MISSING"
            details = ["❌ Missing CSP - high XSS risk"]
            recommendations = ["Implement Content-Security-Policy", "Start with default-src 'self'", "Add script-src 'self'"]
        
        self.results['Content-Security-Policy'] = {
            'score': min(score, 5),
            'status': status,
            'details': details,
            'value': csp,
            'directives': self.detailed_csp if csp else {},
            'recommendations': recommendations if csp else []
        }
    
    def check_x_frame_options(self):
        xfo = self.get_header_value('X-Frame-Options')
        
        if xfo:
            xfo = xfo.upper()
            if xfo in ['DENY', 'SAMEORIGIN']:
                score = 3
                status = "SECURE"
                details = [f"✓ {xfo}"]
            else:
                score = 1
                status = "WEAK"
                details = [f"⚠ {xfo}"]
        else:
            score = 0
            status = "MISSING"
            details = ["❌ Missing - clickjacking risk"]
        
        self.results['X-Frame-Options'] = {
            'score': score,
            'status': status,
            'details': details,
            'value': xfo
        }
    
    def check_x_content_type_options(self):
        xcto = self.get_header_value('X-Content-Type-Options')
        
        if xcto and xcto.lower() == 'nosniff':
            score = 2
            status = "SECURE"
            details = ["✓ nosniff"]
        else:
            score = 0
            status = "MISSING"
            details = ["❌ Missing - MIME-sniffing risk"]
        
        self.results['X-Content-Type-Options'] = {
            'score': score,
            'status': status,
            'details': details,
            'value': xcto
        }
    
    def check_strict_transport_security(self):
        hsts = self.get_header_value('Strict-Transport-Security')
        
        if hsts:
            score = 3
            status = "PRESENT"
            details = []
            
            hsts_lower = hsts.lower()
            
            if 'max-age=' in hsts_lower:
                match = re.search(r'max-age=(\d+)', hsts_lower)
                if match:
                    max_age = int(match.group(1))
                    details.append(f"✓ max-age: {max_age}")
                    if max_age >= 31536000:
                        score += 1
                        details.append("✓ Long duration (≥1 year)")
                    elif max_age < 86400:
                        details.append("⚠ Short duration (<1 day)")
            
            if 'includesubdomains' in hsts_lower:
                score += 1
                details.append("✓ includeSubDomains")
            
            if 'preload' in hsts_lower:
                score += 1
                details.append("✓ preload")
                
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
        rp = self.get_header_value('Referrer-Policy')
        
        strict_policies = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin']
        moderate_policies = ['no-referrer-when-downgrade', 'same-origin']
        
        if rp:
            rp_lower = rp.lower()
            if rp_lower in strict_policies:
                score = 3
                status = "SECURE"
                details = [f"✓ Strict: {rp}"]
            elif rp_lower in moderate_policies:
                score = 2
                status = "MODERATE"
                details = [f"✓ Moderate: {rp}"]
            else:
                score = 1
                status = "WEAK"
                details = [f"⚠ Weak: {rp}"]
        else:
            score = 0
            status = "MISSING"
            details = ["❌ Missing - referrer data leakage risk"]
        
        self.results['Referrer-Policy'] = {
            'score': score,
            'status': status,
            'details': details,
            'value': rp
        }
    
    def check_permissions_policy(self):
        pp = self.get_header_value('Permissions-Policy') or self.get_header_value('Feature-Policy')
        
        if pp:
            score = 3
            status = "PRESENT"
            details = ["✓ Permissions policy configured"]
            
            if 'camera=()' in pp or 'microphone=()' in pp:
                details.append("✓ Sensitive features disabled")
                score += 1
                
        else:
            score = 0
            status = "MISSING"
            details = ["⚠ Missing - limited feature control"]
        
        self.results['Permissions-Policy'] = {
            'score': min(score, 5),
            'status': status,
            'details': details,
            'value': pp
        }
    
    def check_x_xss_protection(self):
        xxss = self.get_header_value('X-XSS-Protection')
        
        if xxss:
            if '1; mode=block' in xxss:
                score = 1
                status = "LEGACY"
                details = ["✓ Deprecated but properly configured"]
            else:
                score = 0
                status = "LEGACY_WEAK"
                details = [f"⚠ Deprecated and weak: {xxss}"]
        else:
            score = 0
            status = "MISSING"
            details = ["ℹ Missing (use CSP instead)"]
        
        self.results['X-XSS-Protection'] = {
            'score': score,
            'status': status,
            'details': details,
            'value': xxss
        }
    
    def check_cache_control(self):
        cc = self.get_header_value('Cache-Control')
        
        if cc:
            score = 2
            status = "PRESENT"
            details = [f"Configured: {cc}"]
            
            sensitive_patterns = ['private', 'no-store', 'no-cache']
            if any(pattern in cc.lower() for pattern in sensitive_patterns):
                score += 1
                details.append("✓ Sensitive content protected")
        else:
            score = 0
            status = "MISSING"
            details = ["⚠ Missing cache control"]
        
        self.results['Cache-Control'] = {
            'score': score,
            'status': status,
            'details': details,
            'value': cc
        }
    
    def check_server_header(self):
        server = self.get_header_value('Server')
        
        if server:
            score = 0
            status = "INFO_LEAK"
            details = [f"Exposed: {server}"]
        else:
            score = 1
            status = "SECURE"
            details = ["✓ Hidden"]
        
        self.results['Server-Info'] = {
            'score': score,
            'status': status,
            'details': details,
            'value': server
        }
    
    def check_expect_ct(self):
        expect_ct = self.get_header_value('Expect-CT')
        
        if expect_ct:
            score = 2
            status = "PRESENT"
            details = ["✓ Certificate Transparency"]
        else:
            score = 0
            status = "MISSING"
            details = ["ℹ Missing (optional)"]
        
        self.results['Expect-CT'] = {
            'score': score,
            'status': status,
            'details': details,
            'value': expect_ct
        }
    
    def check_cross_origin_policies(self):
        coop = self.get_header_value('Cross-Origin-Opener-Policy')
        coep = self.get_header_value('Cross-Origin-Embedder-Policy')
        corp = self.get_header_value('Cross-Origin-Resource-Policy')
        
        details = []
        score = 0
        
        if coop:
            details.append(f"✓ COOP: {coop}")
            score += 1
        else:
            details.append("⚠ Missing COOP")
        
        if coep:
            details.append(f"✓ COEP: {coep}")
            score += 1
        else:
            details.append("ℹ COEP optional")
        
        if corp:
            details.append(f"✓ CORP: {corp}")
            score += 1
        else:
            details.append("ℹ CORP optional")
        
        status = "PARTIAL" if score > 0 else "MISSING"
        
        self.results['Cross-Origin-Policies'] = {
            'score': min(score, 3),
            'status': status,
            'details': details,
            'value': f"COOP: {coop}, COEP: {coep}, CORP: {corp}"
        }
    
    def check_cookies_security(self):
        cookie_headers = []
        for key, value in self.headers.items():
            if key.lower() == 'set-cookie':
                cookie_headers.append(value)
        
        if not cookie_headers and not self.raw_cookies:
            self.results['Cookies'] = {
                'score': 2,
                'status': 'NO_COOKIES',
                'details': ["✓ No cookies set"],
                'value': None
            }
            return
        
        details = []
        secure_count = 0
        httponly_count = 0
        samesite_count = 0
        total_cookies = len(cookie_headers) + len(self.raw_cookies)
        
        for cookie in cookie_headers:
            cookie_lower = cookie.lower()
            
            if 'secure' in cookie_lower:
                secure_count += 1
            
            if 'httponly' in cookie_lower:
                httponly_count += 1
            
            if 'samesite=' in cookie_lower:
                samesite_count += 1
                if 'samesite=strict' in cookie_lower or 'samesite=lax' in cookie_lower:
                    details.append("✓ SameSite configured")
                elif 'samesite=none' in cookie_lower:
                    details.append("⚠ SameSite=None (requires Secure flag)")
        
        for cookie in self.raw_cookies:
            if cookie.secure:
                secure_count += 1
            if hasattr(cookie, '_rest') and 'HttpOnly' in str(cookie._rest):
                httponly_count += 1
        
        if secure_count == total_cookies:
            details.append("✓ All cookies Secure")
        else:
            details.append(f"⚠ {total_cookies - secure_count}/{total_cookies} cookies not Secure")
        
        if httponly_count == total_cookies:
            details.append("✓ All cookies HttpOnly")
        else:
            details.append(f"⚠ {total_cookies - httponly_count}/{total_cookies} cookies not HttpOnly")
        
        score = 0
        if secure_count == total_cookies:
            score += 2
        if httponly_count == total_cookies:
            score += 2
        if samesite_count == total_cookies:
            score += 1
        
        status = "SECURE" if score >= 4 else "WEAK" if score >= 2 else "INSECURE"
        
        self.results['Cookies'] = {
            'score': score,
            'status': status,
            'details': details,
            'value': f"{total_cookies} cookies analyzed",
            'count': total_cookies,
            'secure': secure_count,
            'httponly': httponly_count,
            'samesite': samesite_count
        }
    
    def check_report_to(self):
        report_to = self.get_header_value('Report-To')
        report_uri = self.get_header_value('Report-Uri')
        
        details = []
        score = 0
        
        if report_to:
            details.append("✓ Report-To configured")
            score += 2
        
        if report_uri:
            details.append("✓ Report-URI configured")
            score += 1
        else:
            details.append("ℹ Report-URI missing")
        
        status = "PRESENT" if score > 0 else "MISSING"
        
        self.results['Reporting'] = {
            'score': score,
            'status': status,
            'details': details,
            'value': report_to or report_uri
        }
    
    def check_content_type(self):
        content_type = self.get_header_value('Content-Type')
        
        if content_type:
            score = 1
            status = "PRESENT"
            details = [f"{content_type}"]
            
            if 'charset=' in content_type.lower():
                details.append("✓ Charset specified")
                score += 1
        else:
            score = 0
            status = "MISSING"
            details = ["⚠ Missing Content-Type"]
        
        self.results['Content-Type'] = {
            'score': score,
            'status': status,
            'details': details,
            'value': content_type
        }
    
    def calculate_total_score(self):
        actual_score = sum(item['score'] for item in self.results.values())
        max_possible = 35
        
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
    
    def generate_detailed_recommendations(self):
        recommendations = []
        
        if self.results['Content-Security-Policy']['status'] == 'MISSING':
            recommendations.append({
                'priority': 'HIGH',
                'title': 'Implement Content-Security-Policy',
                'description': 'Missing CSP leaves site vulnerable to XSS attacks',
                'example': "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'"
            })
        
        if self.results['Strict-Transport-Security']['status'] == 'MISSING':
            recommendations.append({
                'priority': 'HIGH',
                'title': 'Add HSTS header',
                'description': 'Force HTTPS connections and prevent SSL stripping',
                'example': "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            })
        
        if self.results['X-Frame-Options']['status'] == 'MISSING':
            recommendations.append({
                'priority': 'HIGH',
                'title': 'Add X-Frame-Options',
                'description': 'Protect against clickjacking attacks',
                'example': "X-Frame-Options: DENY"
            })
        
        if self.results['X-Content-Type-Options']['status'] == 'MISSING':
            recommendations.append({
                'priority': 'MEDIUM',
                'title': 'Add X-Content-Type-Options',
                'description': 'Prevent MIME-sniffing attacks',
                'example': "X-Content-Type-Options: nosniff"
            })
        
        cookies = self.results.get('Cookies', {})
        if cookies.get('status') in ['WEAK', 'INSECURE']:
            recommendations.append({
                'priority': 'MEDIUM',
                'title': 'Secure cookies',
                'description': f"Only {cookies.get('secure', 0)}/{cookies.get('count', 0)} cookies have Secure flag",
                'example': "Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict"
            })
        
        csp_data = self.results.get('Content-Security-Policy', {})
        if csp_data.get('recommendations'):
            for rec in csp_data['recommendations']:
                recommendations.append({
                    'priority': 'LOW',
                    'title': 'Improve CSP',
                    'description': rec,
                    'example': ''
                })
        
        if not recommendations:
            recommendations.append({
                'priority': 'INFO',
                'title': 'Excellent security',
                'description': 'All major security headers are properly configured',
                'example': ''
            })
        
        return recommendations
    
    def print_report(self):
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}SECURITY HEADERS AUDIT v1.3")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.WHITE}URL: {Fore.GREEN}{self.url}")
        print(f"{Fore.WHITE}Time: {Fore.GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.CYAN}{'-'*60}")
        
        for header_name, result in self.results.items():
            status_color = {
                'SECURE': Fore.GREEN,
                'PRESENT': Fore.GREEN,
                'MODERATE': Fore.YELLOW,
                'WEAK': Fore.YELLOW,
                'MISSING': Fore.RED,
                'INFO_LEAK': Fore.YELLOW,
                'LEGACY': Fore.CYAN,
                'LEGACY_WEAK': Fore.YELLOW,
                'PARTIAL': Fore.YELLOW,
                'INSECURE': Fore.RED,
                'NO_COOKIES': Fore.GREEN,
            }.get(result['status'], Fore.WHITE)
            
            print(f"\n{Fore.WHITE}{header_name}: {status_color}{result['status']}")
            for detail in result['details']:
                if detail.startswith('✓'):
                    print(f"  {Fore.GREEN}{detail}")
                elif detail.startswith('⚠'):
                    print(f"  {Fore.YELLOW}{detail}")
                elif detail.startswith('❌'):
                    print(f"  {Fore.RED}{detail}")
                elif detail.startswith('ℹ'):
                    print(f"  {Fore.CYAN}{detail}")
                else:
                    print(f"  {detail}")
        
        total = self.calculate_total_score()
        print(f"\n{Fore.CYAN}{'-'*60}")
        print(f"{Fore.YELLOW}SCORE: {total['color']}{total['score']}/{total['max_possible']} ({total['percentage']:.1f}%)")
        print(f"{Fore.YELLOW}GRADE: {total['color']}{total['grade']}")
        print(f"{Fore.CYAN}{'='*60}")
        
        print(f"\n{Fore.YELLOW}RECOMMENDATIONS:")
        recommendations = self.generate_detailed_recommendations()
        
        priority_order = {'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_recs = sorted(recommendations, key=lambda x: priority_order[x['priority']])
        
        for i, rec in enumerate(sorted_recs, 1):
            priority_color = {
                'HIGH': Fore.RED,
                'MEDIUM': Fore.YELLOW,
                'LOW': Fore.CYAN,
                'INFO': Fore.GREEN
            }.get(rec['priority'], Fore.WHITE)
            
            print(f"\n  {i}. {priority_color}[{rec['priority']}] {rec['title']}")
            print(f"     {rec['description']}")
            if rec['example']:
                print(f"     {Fore.CYAN}Example: {rec['example']}")
    
    def export_to_json(self, output_file=None):
        if not output_file:
            timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
            output_file = f"security-audit-{timestamp}.json"
        
        report_data = {
            "audit_info": {
                "url": self.url,
                "timestamp": datetime.now().isoformat(),
                "version": "1.3"
            },
            "headers_found": dict(self.headers),
            "score": self.calculate_total_score(),
            "results": {},
            "recommendations": self.generate_detailed_recommendations()
        }
        
        for header_name, result in self.results.items():
            report_data["results"][header_name] = {
                "status": result["status"],
                "score": result["score"],
                "value": result["value"],
                "details": result["details"]
            }
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            return output_file
        except Exception:
            return None

def batch_scan(file_path, use_cache=False, timeout=10, user_agent=None, export_json=False):
    if not os.path.exists(file_path):
        print(f"{Fore.RED}Error: File not found")
        return False
    
    try:
        with open(file_path, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
    except Exception:
        print(f"{Fore.RED}Error reading file")
        return False
    
    if not urls:
        print(f"{Fore.YELLOW}No URLs found")
        return False
    
    print(f"{Fore.CYAN}Scanning {len(urls)} sites...")
    
    results = []
    start_time = time.time()
    
    for i, url in enumerate(urls, 1):
        print(f"\n{Fore.CYAN}[{i}/{len(urls)}] {url}")
        
        cached_results = None
        if use_cache:
            cached_results = load_from_cache(url)
        
        if cached_results:
            auditor = SecurityHeadersAuditor(url, timeout, user_agent, use_cache)
            auditor.results = cached_results
            results.append(auditor)
        else:
            auditor = SecurityHeadersAuditor(url, timeout, user_agent, use_cache)
            if auditor.audit():
                results.append(auditor)
                if use_cache:
                    save_to_cache(url, auditor.results)
    
    end_time = time.time()
    duration = end_time - start_time
    
    if results:
        scores = [a.calculate_total_score()['score'] for a in results]
        avg_score = sum(scores) / len(scores) if scores else 0
        
        grades = {'A': 0, 'B': 0, 'C': 0, 'D': 0, 'F': 0}
        for a in results:
            grade = a.calculate_total_score()['grade']
            grades[grade] = grades.get(grade, 0) + 1
        
        print(f"\n{Fore.CYAN}Completed in {duration:.1f}s")
        print(f"Success: {len(results)}/{len(urls)}")
        print(f"Average score: {avg_score:.1f}")
        
        for grade, count in grades.items():
            if count > 0:
                print(f"{grade}: {count}")
    
    if export_json and results:
        batch_report = {
            "batch_info": {
                "total": len(urls),
                "successful": len(results),
                "failed": len(urls) - len(results),
                "duration": f"{duration:.1f}s",
                "timestamp": datetime.now().isoformat()
            },
            "sites": []
        }
        
        for auditor in results:
            site_report = {
                "url": auditor.url,
                "score": auditor.calculate_total_score(),
                "headers_found": dict(auditor.headers)
            }
            batch_report["sites"].append(site_report)
        
        batch_file = f"batch-audit-{datetime.now().strftime('%Y-%m-%d-%H-%M-%S')}.json"
        try:
            with open(batch_file, 'w', encoding='utf-8') as f:
                json.dump(batch_report, f, indent=2, ensure_ascii=False)
            print(f"\n{Fore.GREEN}Batch report: {batch_file}")
        except Exception:
            pass
    
    return True

def main():
    parser = argparse.ArgumentParser(
        description='Security Headers Auditor v1.3',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('url', nargs='?', help='Website URL')
    parser.add_argument('--batch', metavar='FILE', help='Batch scan from file')
    parser.add_argument('--cache', action='store_true', help='Use cache')
    parser.add_argument('--clear-cache', action='store_true', help='Clear cache')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout in seconds')
    parser.add_argument('--user-agent', help='Custom User-Agent')
    parser.add_argument('--json', action='store_true', help='Export to JSON')
    parser.add_argument('--output', help='Output JSON filename')
    
    args = parser.parse_args()
    
    if args.clear_cache:
        clear_cache()
        sys.exit(0)
    
    if args.batch:
        success = batch_scan(
            args.batch, 
            use_cache=args.cache,
            timeout=args.timeout,
            user_agent=args.user_agent,
            export_json=args.json
        )
        sys.exit(0 if success else 1)
    
    if not args.url:
        print(f"{Fore.RED}URL required")
        parser.print_help()
        sys.exit(1)
    
    print(f"{Fore.CYAN}Auditing: {args.url}")
    
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
        auditor.results = cached_results
        auditor.print_report()
    else:
        if auditor.audit():
            auditor.print_report()
            if args.cache:
                save_to_cache(args.url, auditor.results)
        else:
            sys.exit(1)
    
    if args.json:
        output_file = auditor.export_to_json(args.output)
        if output_file:
            print(f"{Fore.GREEN}Report: {output_file}")

if __name__ == "__main__":
    main()