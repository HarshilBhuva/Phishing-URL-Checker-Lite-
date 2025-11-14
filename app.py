from flask import Flask, render_template, request, jsonify
import re
import socket
import ssl
import whois
import requests
from urllib.parse import urlparse
from datetime import datetime
import time

app = Flask(__name__)

# Known suspicious TLDs
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.download']

# Known suspicious keywords in URLs
SUSPICIOUS_KEYWORDS = ['verify', 'secure', 'account', 'update', 'confirm', 'login', 'paypal', 
                      'bank', 'credit', 'card', 'ssn', 'social', 'security', 'urgent', 'action']

# Known legitimate domains (whitelist)
LEGITIMATE_DOMAINS = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com',
                     'twitter.com', 'linkedin.com', 'github.com', 'paypal.com', 'ebay.com']

def check_url_structure(url):
    """Check URL for suspicious structure patterns"""
    issues = []
    score = 0
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        # Check for IP address instead of domain
        try:
            socket.inet_aton(domain.split(':')[0])
            issues.append("URL uses IP address instead of domain name")
            score += 30
        except:
            pass
        
        # Check for suspicious TLDs
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                issues.append(f"Suspicious TLD detected: {tld}")
                score += 15
                break
        
        # Check for multiple subdomains (potential typosquatting)
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            issues.append("Too many subdomains detected")
            score += 10
        
        # Check for suspicious keywords in domain
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in domain and domain not in LEGITIMATE_DOMAINS:
                issues.append(f"Suspicious keyword in domain: {keyword}")
                score += 5
        
        # Check for typosquatting patterns (repeated characters, missing vowels)
        if re.search(r'(.)\1{3,}', domain):
            issues.append("Suspicious character repetition detected")
            score += 10
        
        # Check URL length
        if len(url) > 100:
            issues.append("Unusually long URL")
            score += 5
        
        # Check for homoglyph attacks (basic check for mixed scripts)
        if re.search(r'[^\x00-\x7F]', domain):
            issues.append("Non-ASCII characters in domain (potential homoglyph attack)")
            score += 20
        
        # Check for @ symbol (userinfo in URL)
        if '@' in url:
            issues.append("URL contains @ symbol (potential phishing technique)")
            score += 25
        
        # Check for port number (unusual for web services)
        if ':' in domain and not domain.endswith(':80') and not domain.endswith(':443'):
            port = domain.split(':')[-1]
            if port not in ['80', '443']:
                issues.append(f"Unusual port number: {port}")
                score += 10
        
    except Exception as e:
        issues.append(f"Error parsing URL: {str(e)}")
        score += 5
    
    return issues, score

def check_ssl_certificate(url):
    """Check SSL certificate validity"""
    issues = []
    score = 0
    
    try:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        domain = parsed.netloc.split(':')[0]
        
        # Check if URL uses HTTP instead of HTTPS
        if scheme == 'http':
            issues.append("URL uses HTTP instead of HTTPS (not secure)")
            score += 25
            return issues, score
        elif not scheme or scheme not in ['http', 'https']:
            # No scheme specified, try HTTPS
            pass
        
        # Try to get SSL certificate
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiry
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        issues.append(f"SSL certificate expires soon ({days_until_expiry} days)")
                        score += 10
                    
                    # Check if certificate is self-signed (basic check)
                    issuer = dict(x[0] for x in cert['issuer'])
                    if 'Let\'s Encrypt' not in str(issuer) and 'DigiCert' not in str(issuer) and 'GoDaddy' not in str(issuer):
                        # This is a basic check - not all CAs are listed
                        pass
        except ssl.SSLError:
            issues.append("SSL certificate error or invalid certificate")
            score += 30
        except socket.timeout:
            issues.append("Connection timeout when checking SSL certificate")
            score += 5
        except socket.gaierror:
            # DNS resolution failed
            issues.append("Could not resolve domain name")
            score += 5
        except ConnectionRefusedError:
            issues.append("Connection refused - HTTPS port may not be open")
            score += 10
                    
    except Exception as e:
        # Only add score if it's a significant error
        if "SSL" in str(e) or "certificate" in str(e).lower():
            issues.append(f"SSL certificate verification failed: {str(e)}")
            score += 20
        else:
            # Other errors are less critical
            pass
    
    return issues, score

def check_domain_age(url):
    """Check domain registration age"""
    issues = []
    score = 0
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.split(':')[0]
        
        # Remove port if present
        domain = domain.split(':')[0]
        
        # Query WHOIS
        try:
            domain_info = whois.whois(domain)
        except Exception:
            # WHOIS lookup failed, skip this check
            return issues, score
        
        # Handle different response structures
        creation_date = None
        if hasattr(domain_info, 'creation_date') and domain_info.creation_date:
            if isinstance(domain_info.creation_date, list):
                creation_date = domain_info.creation_date[0]
            else:
                creation_date = domain_info.creation_date
        
        if creation_date:
            # Handle string dates
            if isinstance(creation_date, str):
                try:
                    creation_date = datetime.strptime(creation_date.split()[0], '%Y-%m-%d')
                except:
                    pass
            
            if isinstance(creation_date, datetime):
                age_days = (datetime.now() - creation_date).days
                
                if age_days < 0:
                    # Future date, invalid
                    pass
                elif age_days < 30:
                    issues.append(f"Domain is very new ({age_days} days old)")
                    score += 25
                elif age_days < 90:
                    issues.append(f"Domain is relatively new ({age_days} days old)")
                    score += 10
                elif age_days < 365:
                    issues.append(f"Domain is less than a year old ({age_days} days)")
                    score += 5
        else:
            # Could not get creation date, but don't penalize heavily
            pass
            
    except Exception as e:
        # WHOIS failures are common and shouldn't heavily penalize
        # Only log if in debug mode
        pass
    
    return issues, score

def check_url_reachability(url):
    """Check if URL is reachable and returns valid response"""
    issues = []
    score = 0
    
    try:
        # Add https if no scheme
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        
        if response.status_code == 200:
            # Check for suspicious content
            content = response.text.lower()
            
            # Check for common phishing page indicators
            phishing_indicators = ['enter your password', 'verify your account', 'suspended account',
                                 'click here to verify', 'urgent action required', 'account locked']
            
            for indicator in phishing_indicators:
                if indicator in content:
                    issues.append(f"Suspicious content detected: '{indicator}'")
                    score += 15
                    break
            
            # Check redirects
            if len(response.history) > 3:
                issues.append("Multiple redirects detected (potential phishing technique)")
                score += 10
                
        elif response.status_code >= 400:
            issues.append(f"URL returned error status: {response.status_code}")
            score += 5
            
    except requests.exceptions.SSLError:
        issues.append("SSL verification failed")
        score += 20
    except requests.exceptions.ConnectionError:
        issues.append("Could not connect to URL")
        score += 5
    except requests.exceptions.Timeout:
        issues.append("Request timed out")
        score += 5
    except Exception as e:
        issues.append(f"Error checking URL: {str(e)}")
        score += 5
    
    return issues, score

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check_url():
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        all_issues = []
        total_score = 0
        
        # Run all checks
        structure_issues, structure_score = check_url_structure(url)
        all_issues.extend(structure_issues)
        total_score += structure_score
        
        ssl_issues, ssl_score = check_ssl_certificate(url)
        all_issues.extend(ssl_issues)
        total_score += ssl_score
        
        age_issues, age_score = check_domain_age(url)
        all_issues.extend(age_issues)
        total_score += age_score
        
        reachability_issues, reachability_score = check_url_reachability(url)
        all_issues.extend(reachability_issues)
        total_score += reachability_score
        
        # Determine risk level
        if total_score >= 70:
            risk_level = "HIGH RISK"
            risk_color = "#dc3545"
        elif total_score >= 40:
            risk_level = "MEDIUM RISK"
            risk_color = "#ffc107"
        elif total_score >= 20:
            risk_level = "LOW RISK"
            risk_color = "#ff9800"
        else:
            risk_level = "SAFE"
            risk_color = "#28a745"
        
        return jsonify({
            'url': url,
            'risk_level': risk_level,
            'risk_color': risk_color,
            'risk_score': total_score,
            'issues': all_issues,
            'issue_count': len(all_issues)
        })
        
    except Exception as e:
        return jsonify({'error': f'Error checking URL: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)

