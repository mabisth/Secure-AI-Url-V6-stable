from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, HttpUrl
import os
from motor.motor_asyncio import AsyncIOMotorClient
import re
import urllib.parse
import socket
import ssl
import requests
import hashlib
import json
import io
import csv
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
import asyncio
import whois
from urllib.parse import urlparse
import dns.resolver
import uuid
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN
import joblib
import pickle
import base64
from PIL import Image, ImageDraw, ImageFont
import cv2
import pytesseract
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import tempfile
import threading
import time
from collections import Counter, defaultdict
import geoip2.database
import geoip2.errors

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

# Initialize FastAPI app
app = FastAPI(title="E-Skimming Protection & Malicious URL Detection API", version="3.0.0")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection
MONGO_URL = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
client = AsyncIOMotorClient(MONGO_URL)
db = client.url_security_db

# Initialize scheduler for daily scans
scheduler = AsyncIOScheduler()

# Request/Response models
class URLScanRequest(BaseModel):
    url: str
    scan_type: Optional[str] = "standard"  # standard, e_skimming, payment_gateway

class BulkScanRequest(BaseModel):
    urls: List[str]
    scan_type: Optional[str] = "standard"

class MerchantScanRequest(BaseModel):
    merchant_id: str
    merchant_name: str
    urls: List[str]
    contact_email: str

class ThreatAnalysis(BaseModel):
    risk_score: int
    threat_category: str
    is_malicious: bool
    analysis_details: Dict
    recommendations: List[str]
    scan_timestamp: str
    scan_id: str
    ml_predictions: Dict
    screenshot_analysis: Optional[Dict]
    campaign_info: Optional[Dict]

class ESkimmingAnalysis(BaseModel):
    risk_score: int
    threat_category: str
    is_malicious: bool
    e_skimming_indicators: List[str]
    payment_security_score: int
    transaction_halt_recommended: bool
    compliance_status: str
    analysis_details: Dict
    recommendations: List[str]
    scan_timestamp: str
    scan_id: str
    ml_predictions: Dict
    screenshot_analysis: Optional[Dict]
    campaign_info: Optional[Dict]

class ComplianceReport(BaseModel):
    report_id: str
    merchant_id: str
    scan_date: str
    total_urls_scanned: int
    threats_detected: int
    critical_threats: int
    transaction_halt_required: int
    compliance_status: str
    next_scan_due: str

class BulkScanResult(BaseModel):
    job_id: str
    total_urls: int
    processed_urls: int
    results: List[ThreatAnalysis]
    status: str

class AdvancedESkimmingAnalyzer:
    def __init__(self):
        # E-skimming specific threat patterns (initialize first)
        self.e_skimming_patterns = [
            # Credit card form skimming patterns
            r'document\.forms\[.*\]\.submit\s*\(',
            r'addEventListener\s*\(\s*["\']submit["\']',
            r'onsubmit\s*=\s*["\'].*["\']',
            r'input\[type=["\'](?:text|password)["\']\]\.value',
            r'creditcard|cardnumber|cvv|cvc|expiry',
            r'payment.*form.*submit',
            r'checkout.*form.*data',
            
            # JavaScript injection patterns for payment pages
            r'btoa\s*\(\s*.*card.*\)',
            r'encodeURIComponent\s*\(\s*.*payment.*\)',
            r'XMLHttpRequest.*payment',
            r'fetch\s*\(\s*.*billing.*\)',
            r'\.send\s*\(\s*.*card.*\)',
            
            # Known e-skimming malware signatures
            r'magecart|skimmer|cardstealer',
            r'inter\.(?:php|asp|jsp)\?.*card',
            r'gate\.(?:php|asp|jsp)\?.*payment',
            r'formgrabber|keylogger.*payment',
        ]
        
        # Payment gateway specific indicators
        self.payment_gateway_patterns = [
            r'stripe\.com|paypal\.com|square\.com',
            r'braintree|authorize\.net|worldpay',
            r'checkout\.com|adyen\.com|klarna',
            r'razorpay|payu|ccavenue',
            r'payment.*gateway|merchant.*service',
        ]
        
        # E-skimming malware indicators
        self.e_skimming_malware_indicators = [
            'magecart', 'skimmer', 'cardstealer', 'formgrabber',
            'paymentstealer', 'ccstealer', 'billingstealer',
            'checkoutstealer', 'inter.php', 'gate.php', 'card.php',
            'payment.php', 'billing.php', 'checkout.php'
        ]
        
        # Payment processor whitelist
        self.trusted_payment_processors = [
            'stripe.com', 'paypal.com', 'square.com', 'braintree.com',
            'authorize.net', 'worldpay.com', 'checkout.com', 'adyen.com',
            'klarna.com', 'razorpay.com', 'payu.in', 'ccavenue.com'
        ]
        
        # Enhanced threat patterns (initialize first)
        self.phishing_keywords = [
            'login', 'secure', 'account', 'verify', 'update', 'confirm',
            'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
            'bank', 'credit', 'card', 'suspended', 'limited', 'urgent',
            'signin', 'authentication', 'validation', 'renewal', 'expires',
            # E-skimming specific keywords
            'payment', 'billing', 'checkout', 'purchase', 'order', 'cart'
        ]
        
        self.malware_indicators = [
            '.exe', '.scr', '.bat', '.com', '.pif', '.vbs', '.jar',
            'download', 'install', 'setup', 'crack', 'keygen', 'patch',
            'torrent', 'warez', 'serial', 'activator', 'loader'
        ]
        
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.men', '.xyz', '.top', '.work',
            '.click', '.download', '.bid', '.win', '.accountant', '.science'
        ]
        
        self.trusted_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'twitter.com', 'github.com', 'stackoverflow.com',
            'linkedin.com', 'youtube.com', 'wikipedia.org',
            # Trusted payment processors
            'stripe.com', 'paypal.com', 'square.com', 'braintree.com',
            'authorize.net', 'worldpay.com', 'checkout.com', 'adyen.com'
        ]
        
        # Advanced patterns for ML detection
        self.phishing_patterns = [
            r'(?:login|signin|account).*(?:verify|update|confirm)',
            r'(?:secure|safety).*(?:alert|warning|notice)',
            r'(?:paypal|amazon|microsoft|apple|google).*(?:security|payment)',
            r'(?:suspended|limited|blocked).*account',
            r'click.*(?:here|link|verify|confirm)',
            # E-skimming patterns
            r'(?:payment|billing|checkout).*(?:verify|update|confirm)',
            r'(?:card|credit).*(?:expired|declined|suspended)',
        ]
        
        self.campaign_signatures = {}
        self.screenshot_driver = None
        
        # Initialize ML models (after attributes are set)
        self.phishing_model = None
        self.malware_model = None
        self.tfidf_vectorizer = None
        self.campaign_detector = None
        
        # Load or create ML models
        self._initialize_ml_models()
        
        # Initialize screenshot driver
        self._init_screenshot_driver()

    def _initialize_ml_models(self):
        """Initialize or load ML models"""
        try:
            # Try to load existing models
            self.phishing_model = joblib.load('/app/models/phishing_model.pkl')
            self.malware_model = joblib.load('/app/models/malware_model.pkl')
            self.tfidf_vectorizer = joblib.load('/app/models/tfidf_vectorizer.pkl')
        except:
            # Create new models if they don't exist
            self._train_initial_models()

    def _train_initial_models(self):
        """Train initial ML models with synthetic data"""
        # Generate synthetic training data
        phishing_urls = [
            'http://paypal-security-update.suspicious-site.tk',
            'https://amazon-account-verification.malicious.com',
            'http://microsoft-security-alert.phishing-site.xyz',
            'https://apple-id-locked.fake-domain.ml',
            'http://google-security-warning.evil-site.ga',
            'https://facebook-account-suspended.phish.cf'
        ]
        
        legitimate_urls = [
            'https://www.google.com',
            'https://github.com',
            'https://stackoverflow.com',
            'https://www.microsoft.com',
            'https://www.apple.com',
            'https://www.amazon.com'
        ]
        
        # Extract features for training
        all_urls = phishing_urls + legitimate_urls
        labels = [1] * len(phishing_urls) + [0] * len(legitimate_urls)
        
        # Create feature vectors
        features = []
        for url in all_urls:
            features.append(self._extract_ml_features(url))
        
        # Train models
        self.phishing_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.malware_model = GradientBoostingClassifier(n_estimators=100, random_state=42)
        
        X = np.array(features)
        y = np.array(labels)
        
        self.phishing_model.fit(X, y)
        self.malware_model.fit(X, y)
        
        # Train TF-IDF vectorizer
        self.tfidf_vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.tfidf_vectorizer.fit(all_urls)
        
        # Save models
        os.makedirs('/app/models', exist_ok=True)
        joblib.dump(self.phishing_model, '/app/models/phishing_model.pkl')
        joblib.dump(self.malware_model, '/app/models/malware_model.pkl')
        joblib.dump(self.tfidf_vectorizer, '/app/models/tfidf_vectorizer.pkl')

    def _init_screenshot_driver(self):
        """Initialize Selenium WebDriver for screenshots (disabled for now)"""
        # Disable screenshot functionality for now to avoid Chrome dependency issues
        self.screenshot_driver = None
        print("Screenshot analysis disabled - Chrome dependencies not available")

    def _extract_ml_features(self, url: str) -> List[float]:
        """Extract features for ML models"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        features = [
            len(url),
            len(domain),
            len(path),
            len(domain.split('.')) - 2 if len(domain.split('.')) > 2 else 0,
            len(re.findall(r'[%\-_~]', url)),
            len(re.findall(r'\d', domain)),
            1 if bool(re.match(r'^\d+\.\d+\.\d+\.\d+', domain)) else 0,
            1 if any(domain.endswith(tld) for tld in self.suspicious_tlds) else 0,
            sum(1 for keyword in self.phishing_keywords if keyword in url.lower()),
            sum(1 for indicator in self.malware_indicators if indicator in url.lower()),
            1 if any(shortener in url.lower() for shortener in ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl']) else 0,
            url.count('.'),
            url.count('-'),
            url.count('_'),
            1 if 'https' in url else 0,
        ]
        
        return features

    def analyze_e_skimming_indicators(self, url: str, content: str = "") -> List[str]:
        """Analyze URL and content for e-skimming indicators"""
        indicators = []
        url_lower = url.lower()
        content_lower = content.lower()
        
        # Check for e-skimming malware indicators
        for indicator in self.e_skimming_malware_indicators:
            if indicator in url_lower or indicator in content_lower:
                indicators.append(f"E-skimming malware: {indicator}")
        
        # Check for suspicious payment-related patterns
        for pattern in self.e_skimming_patterns:
            if re.search(pattern, url_lower) or re.search(pattern, content_lower):
                indicators.append(f"Suspicious payment pattern: {pattern[:30]}...")
        
        # Check for payment gateway impersonation
        for gateway_pattern in self.payment_gateway_patterns:
            if re.search(gateway_pattern, url_lower) and not any(trusted in url_lower for trusted in self.trusted_payment_processors):
                indicators.append(f"Payment gateway impersonation: {gateway_pattern}")
        
        # Check for suspicious JavaScript patterns
        js_patterns = [
            r'document\.forms.*submit',
            r'addEventListener.*submit',
            r'XMLHttpRequest.*payment',
            r'fetch.*billing',
        ]
        
        for pattern in js_patterns:
            if re.search(pattern, content_lower):
                indicators.append(f"Suspicious JavaScript: {pattern}")
        
        return indicators

    def analyze_detailed_ssl_certificate(self, domain: str) -> Dict:
        """Enhanced SSL certificate analysis with comprehensive vulnerability detection"""
        ssl_details = {
            'certificate_info': {},
            'security_issues': [],
            'certificate_chain': [],
            'vulnerabilities': [],
            'protocol_support': {},
            'cipher_analysis': {},
            'recommendations': [],
            'grade': 'F',
            'ssl_available': False
        }
        
        try:
            import ssl
            import socket
            from datetime import datetime, timezone
            
            # Test multiple SSL/TLS protocols
            protocols_to_test = {
                'TLSv1.3': ssl.PROTOCOL_TLS,
                'TLSv1.2': ssl.PROTOCOL_TLS,
                'TLSv1.1': ssl.PROTOCOL_TLS,
                'TLSv1.0': ssl.PROTOCOL_TLS
            }
            
            ssl_connection_successful = False
            
            for protocol_name, protocol in protocols_to_test.items():
                try:
                    context = ssl.SSLContext(protocol)
                    if protocol_name in ['TLSv1.3', 'TLSv1.2']:
                        # Allow modern protocols
                        context.minimum_version = ssl.TLSVersion.TLSv1_2
                    else:
                        # For testing older protocols, disable modern restrictions
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        
                    socket.setdefaulttimeout(10)
                    
                    try:
                        with socket.create_connection((domain, 443), timeout=10) as sock:
                            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                                ssl_connection_successful = True
                                ssl_details['ssl_available'] = True
                                ssl_details['protocol_support'][protocol_name] = True
                                
                                cert = ssock.getpeercert()
                                cipher = ssock.cipher()
                                
                                if cert and not ssl_details['certificate_info']:
                                    # Extract detailed certificate information (only once)
                                    ssl_details['certificate_info'] = {
                                        'subject': dict(x[0] for x in cert['subject']),
                                        'issuer': dict(x[0] for x in cert['issuer']),
                                        'version': cert.get('version', 'Unknown'),
                                        'serial_number': cert.get('serialNumber', 'Unknown'),
                                        'not_before': cert.get('notBefore', 'Unknown'),
                                        'not_after': cert.get('notAfter', 'Unknown'),
                                        'signature_algorithm': cert.get('signatureAlgorithm', 'Unknown'),
                                        'subject_alt_names': [x[1] for x in cert.get('subjectAltName', [])],
                                        'key_usage': cert.get('keyUsage', []),
                                        'extended_key_usage': cert.get('extendedKeyUsage', [])
                                    }
                                
                                if cipher:
                                    ssl_details['cipher_analysis'][protocol_name] = {
                                        'protocol': cipher[1],
                                        'cipher_suite': cipher[0],
                                        'key_exchange': cipher[2] if len(cipher) > 2 else 'Unknown'
                                    }
                                
                    except Exception:
                        ssl_details['protocol_support'][protocol_name] = False
                        
                except Exception:
                    ssl_details['protocol_support'][protocol_name] = False
            
            # If no direct connection worked, try with certificate verification disabled
            if not ssl_connection_successful:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((domain, 443), timeout=15) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            ssl_details['ssl_available'] = True
                            ssl_details['security_issues'].append('SSL certificate verification failed - certificate chain incomplete or invalid')
                            
                            cert = ssock.getpeercert()
                            cipher = ssock.cipher()
                            
                            if cert:
                                ssl_details['certificate_info'] = {
                                    'subject': dict(x[0] for x in cert['subject']),
                                    'issuer': dict(x[0] for x in cert['issuer']),
                                    'version': cert.get('version', 'Unknown'),
                                    'serial_number': cert.get('serialNumber', 'Unknown'),
                                    'not_before': cert.get('notBefore', 'Unknown'),
                                    'not_after': cert.get('notAfter', 'Unknown'),
                                    'signature_algorithm': cert.get('signatureAlgorithm', 'Unknown'),
                                    'subject_alt_names': [x[1] for x in cert.get('subjectAltName', [])],
                                }
                            
                            if cipher:
                                ssl_details['cipher_analysis']['fallback'] = {
                                    'protocol': cipher[1],
                                    'cipher_suite': cipher[0],
                                    'key_exchange': cipher[2] if len(cipher) > 2 else 'Unknown'
                                }
                                
                except Exception as e:
                    ssl_details['error'] = f"SSL connection failed: {str(e)}"
            
            # Analyze vulnerabilities and security issues
            if ssl_details['ssl_available']:
                # Check for vulnerable SSL/TLS versions
                vulnerable_protocols = ['TLSv1.0', 'TLSv1.1', 'SSLv2', 'SSLv3']
                for vulnerable in vulnerable_protocols:
                    if ssl_details['protocol_support'].get(vulnerable, False):
                        ssl_details['vulnerabilities'].append(f'Supports vulnerable protocol: {vulnerable}')
                        ssl_details['security_issues'].append(f'Deprecated protocol {vulnerable} is supported')
                
                # Analyze cipher suites for all protocols
                weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'SHA1', 'NULL', 'EXPORT', 'ADH', 'AECDH']
                for protocol, cipher_info in ssl_details['cipher_analysis'].items():
                    cipher_suite = cipher_info.get('cipher_suite', '')
                    for weak in weak_ciphers:
                        if weak in cipher_suite.upper():
                            ssl_details['vulnerabilities'].append(f'Weak cipher in {protocol}: {weak}')
                            ssl_details['security_issues'].append(f'Weak cipher suite detected: {cipher_suite}')
                
                # Check certificate validity if available
                cert_info = ssl_details['certificate_info']
                if cert_info and cert_info.get('not_after') != 'Unknown':
                    try:
                        not_after = datetime.strptime(cert_info['not_after'], '%b %d %H:%M:%S %Y %Z')
                        not_before = datetime.strptime(cert_info['not_before'], '%b %d %H:%M:%S %Y %Z')
                        now = datetime.now(timezone.utc).replace(tzinfo=None)
                        
                        days_until_expiry = (not_after - now).days
                        
                        if days_until_expiry < 0:
                            ssl_details['vulnerabilities'].append('Certificate has expired')
                            ssl_details['security_issues'].append('Certificate has expired')
                        elif days_until_expiry < 30:
                            ssl_details['security_issues'].append(f'Certificate expires in {days_until_expiry} days')
                        
                        # Check certificate validity period length
                        validity_period = (not_after - not_before).days
                        if validity_period > 825:  # CA/Browser Forum baseline
                            ssl_details['security_issues'].append('Certificate validity period exceeds recommended 825 days')
                        
                        # Check if certificate is self-signed
                        subject = cert_info.get('subject', {})
                        issuer = cert_info.get('issuer', {})
                        if subject.get('commonName') == issuer.get('commonName'):
                            ssl_details['security_issues'].append('Self-signed certificate detected')
                            ssl_details['vulnerabilities'].append('Self-signed certificate')
                            
                    except Exception:
                        ssl_details['security_issues'].append('Cannot parse certificate dates')
                
                # Check for wildcard certificates
                subject = cert_info.get('subject', {})
                if subject.get('commonName', '').startswith('*'):
                    ssl_details['certificate_info']['is_wildcard'] = True
                    ssl_details['recommendations'].append('Wildcard certificate in use - ensure proper subdomain security')
                
                # Generate enhanced recommendations
                if ssl_details['protocol_support'].get('TLSv1.0') or ssl_details['protocol_support'].get('TLSv1.1'):
                    ssl_details['recommendations'].append('🔴 Disable TLS 1.0 and 1.1 - use TLS 1.2+ only')
                
                if not ssl_details['protocol_support'].get('TLSv1.3'):
                    ssl_details['recommendations'].append('🟡 Enable TLS 1.3 for improved security and performance')
                
                if len(ssl_details['vulnerabilities']) > 0:
                    ssl_details['recommendations'].append('🔴 Address all identified SSL/TLS vulnerabilities immediately')
                
                if 'certificate chain incomplete' in str(ssl_details.get('error', '')):
                    ssl_details['recommendations'].append('🔴 Fix incomplete certificate chain - install intermediate certificates')
                
                # Enhanced grade calculation
                issues_count = len(ssl_details['security_issues'])
                vulnerabilities_count = len(ssl_details['vulnerabilities'])
                
                if vulnerabilities_count == 0 and issues_count == 0 and ssl_details['protocol_support'].get('TLSv1.3'):
                    ssl_details['grade'] = 'A+'
                elif vulnerabilities_count == 0 and issues_count <= 1:
                    ssl_details['grade'] = 'A'
                elif vulnerabilities_count <= 1 and issues_count <= 2:
                    ssl_details['grade'] = 'B'
                elif vulnerabilities_count <= 2 and issues_count <= 3:
                    ssl_details['grade'] = 'C'
                elif vulnerabilities_count <= 3 and issues_count <= 5:
                    ssl_details['grade'] = 'D'
                else:
                    ssl_details['grade'] = 'F'
            else:
                ssl_details['security_issues'].append('SSL/TLS not available or connection failed')
                ssl_details['vulnerabilities'].append('No SSL/TLS encryption')
                ssl_details['grade'] = 'F'
                ssl_details['recommendations'].append('🔴 Enable SSL/TLS encryption with valid certificate')
                
        except Exception as e:
            ssl_details['error'] = str(e)
            ssl_details['security_issues'].append(f'SSL analysis failed: {str(e)}')
            ssl_details['grade'] = 'F'
            ssl_details['recommendations'].append('🔴 SSL configuration requires investigation')
        
        return ssl_details

    def check_email_security_records(self, domain: str) -> Dict:
        """Check SPF, DMARC, and DKIM records for email security"""
        email_security = {
            'spf_record': None,
            'spf_status': 'Not Found',
            'spf_issues': [],
            'dmarc_record': None,
            'dmarc_status': 'Not Found', 
            'dmarc_policy': None,
            'dkim_status': 'Unknown',
            'dkim_selectors_found': [],
            'email_security_score': 0,
            'recommendations': []
        }
        
        try:
            import dns.resolver
            
            # Configure resolver with reasonable timeouts
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            # Check SPF record
            try:
                spf_answers = resolver.resolve(domain, 'TXT')
                for rdata in spf_answers:
                    txt_record = str(rdata).strip('"')
                    if txt_record.startswith('v=spf1'):
                        email_security['spf_record'] = txt_record
                        email_security['spf_status'] = 'Found'
                        
                        # Analyze SPF record details
                        if 'include:' in txt_record:
                            email_security['spf_issues'].append('Uses include mechanism - verify included domains')
                        
                        # Check SPF terminator mechanism
                        if '~all' in txt_record:
                            email_security['spf_status'] = 'Soft Fail Policy'
                        elif '-all' in txt_record:
                            email_security['spf_status'] = 'Hard Fail Policy (Recommended)'
                        elif '+all' in txt_record:
                            email_security['spf_issues'].append('Dangerous: +all allows any server to send email')
                            email_security['spf_status'] = 'Permissive (Insecure)'
                        elif '?all' in txt_record:
                            email_security['spf_status'] = 'Neutral Policy'
                        
                        # Check for too many DNS lookups (RFC limit is 10)
                        include_count = txt_record.count('include:') + txt_record.count('a:') + txt_record.count('mx:') + txt_record.count('exists:')
                        if include_count > 10:
                            email_security['spf_issues'].append(f'Too many DNS lookups ({include_count}) - exceeds RFC limit of 10')
                        
                        # Check for IPv6 support
                        if 'ip4:' in txt_record and 'ip6:' not in txt_record:
                            email_security['spf_issues'].append('Consider adding IPv6 support with ip6: mechanism')
                        
                        break
            except dns.resolver.NXDOMAIN:
                email_security['spf_status'] = 'Domain Not Found'
            except dns.resolver.NoAnswer:
                email_security['spf_status'] = 'No TXT Records'
            except dns.resolver.Timeout:
                email_security['spf_status'] = 'DNS Query Timeout'
            except Exception as e:
                email_security['spf_status'] = f'DNS Query Error: {str(e)[:30]}'
            
            # Check DMARC record
            try:
                dmarc_domain = f'_dmarc.{domain}'
                dmarc_answers = resolver.resolve(dmarc_domain, 'TXT')
                for rdata in dmarc_answers:
                    txt_record = str(rdata).strip('"')
                    if txt_record.startswith('v=DMARC1'):
                        email_security['dmarc_record'] = txt_record
                        email_security['dmarc_status'] = 'Found'
                        
                        # Extract DMARC policy
                        if 'p=reject' in txt_record.lower():
                            email_security['dmarc_policy'] = 'Reject (Strong)'
                        elif 'p=quarantine' in txt_record.lower():
                            email_security['dmarc_policy'] = 'Quarantine (Moderate)'
                        elif 'p=none' in txt_record.lower():
                            email_security['dmarc_policy'] = 'Monitor Only (Weak)'
                        
                        # Check for subdomain policy
                        if 'sp=' in txt_record:
                            if 'sp=reject' in txt_record.lower():
                                email_security['dmarc_policy'] += ' | Subdomain: Reject'
                            elif 'sp=quarantine' in txt_record.lower():
                                email_security['dmarc_policy'] += ' | Subdomain: Quarantine'
                            elif 'sp=none' in txt_record.lower():
                                email_security['dmarc_policy'] += ' | Subdomain: None'
                        
                        # Check for reporting
                        if 'rua=' not in txt_record and 'ruf=' not in txt_record:
                            email_security['recommendations'].append('Add DMARC reporting addresses (rua/ruf) for visibility')
                        
                        # Check alignment mode
                        if 'aspf=s' in txt_record:
                            email_security['recommendations'].append('SPF alignment mode is strict - ensure SPF record allows your sending sources')
                        if 'adkim=s' in txt_record:
                            email_security['recommendations'].append('DKIM alignment mode is strict - ensure DKIM signatures match From domain')
                        
                        break
            except dns.resolver.NXDOMAIN:
                email_security['dmarc_status'] = 'DMARC Record Not Found'
            except dns.resolver.NoAnswer:
                email_security['dmarc_status'] = 'No DMARC TXT Record'
            except dns.resolver.Timeout:
                email_security['dmarc_status'] = 'DNS Query Timeout'
            except Exception as e:
                email_security['dmarc_status'] = f'DNS Query Error: {str(e)[:30]}'
            
            # Check for DKIM (enhanced check with more selectors)
            try:
                # Extended list of common DKIM selectors
                dkim_selectors = [
                    'default', 'google', 'selector1', 'selector2', 'dkim', 'mail',
                    'k1', 'sig1', 'email', 'smtp', 'mailgun', 'sendgrid', 
                    'amazonses', 'mandrill', 'mailchimp', 'constantcontact',
                    's1', 's2', 'key1', 'key2', 'primary', 'secondary'
                ]
                
                dkim_found = False
                selectors_found = []
                
                for selector in dkim_selectors:
                    try:
                        dkim_domain = f'{selector}._domainkey.{domain}'
                        dkim_answers = resolver.resolve(dkim_domain, 'TXT')
                        if dkim_answers:
                            # Verify it's actually a DKIM record
                            for rdata in dkim_answers:
                                record_text = str(rdata).strip('"')
                                if 'k=' in record_text or 'p=' in record_text or 'v=DKIM1' in record_text:
                                    dkim_found = True
                                    selectors_found.append(selector)
                                    break
                    except:
                        continue
                
                if dkim_found:
                    email_security['dkim_status'] = 'Found'
                    email_security['dkim_selectors_found'] = selectors_found
                else:
                    email_security['dkim_status'] = 'Not Found (Common Selectors Checked)'
                    
            except Exception as e:
                email_security['dkim_status'] = f'DNS Query Error: {str(e)[:30]}'
            
            # Calculate enhanced email security score
            score = 0
            
            # SPF scoring (40 points max)
            if email_security['spf_status'] in ['Hard Fail Policy (Recommended)']:
                score += 40
            elif email_security['spf_status'] in ['Soft Fail Policy']:
                score += 30
            elif email_security['spf_status'] in ['Found', 'Neutral Policy']:
                score += 20
            elif email_security['spf_status'] == 'Permissive (Insecure)':
                score += 10  # Some points for having SPF but it's insecure
            
            # DMARC scoring (40 points max)
            if email_security['dmarc_status'] == 'Found':
                if email_security['dmarc_policy'] and 'Reject' in email_security['dmarc_policy']:
                    score += 40
                elif email_security['dmarc_policy'] and 'Quarantine' in email_security['dmarc_policy']:
                    score += 30
                elif email_security['dmarc_policy'] and 'Monitor Only' in email_security['dmarc_policy']:
                    score += 15
                else:
                    score += 10  # Found but couldn't parse policy
            
            # DKIM scoring (20 points max)
            if email_security['dkim_status'] == 'Found':
                score += 20
            
            email_security['email_security_score'] = min(100, score)
            
            # Generate comprehensive recommendations
            if email_security['spf_status'] == 'Not Found':
                email_security['recommendations'].append('🔴 Critical: Implement SPF record to prevent email spoofing')
            elif email_security['spf_status'] == 'Permissive (Insecure)':
                email_security['recommendations'].append('🟡 Warning: SPF record is too permissive - change +all to -all')
            
            if email_security['dmarc_status'] == 'Not Found':
                email_security['recommendations'].append('🔴 Critical: Implement DMARC policy for email authentication')
            elif email_security['dmarc_policy'] == 'Monitor Only (Weak)':
                email_security['recommendations'].append('🟡 Upgrade: Consider stronger DMARC policy (quarantine or reject)')
            
            if email_security['dkim_status'] in ['Not Found (Common Selectors Checked)', 'Unknown']:
                email_security['recommendations'].append('🟡 Recommended: Implement DKIM signing for email integrity')
            
            # Add SPF-specific recommendations
            if email_security['spf_issues']:
                email_security['recommendations'].extend([f"SPF Issue: {issue}" for issue in email_security['spf_issues']])
                
        except Exception as e:
            email_security['error'] = f'Email security check failed: {str(e)}'
            email_security['recommendations'].append('Unable to check email security records - DNS resolution may be blocked')
        
        return email_security

    def comprehensive_threat_assessment(self, url: str, domain: str, content: str) -> Dict:
        """Comprehensive threat assessment similar to IPQualityScore"""
        threat_assessment = {
            'overall_risk_score': 0,
            'threat_categories': [],
            'malware_detection': {
                'detected': False,
                'signatures': [],
                'confidence': 0
            },
            'phishing_detection': {
                'detected': False,
                'indicators': [],
                'confidence': 0
            },
            'suspicious_activities': [],
            'domain_reputation': {
                'age_score': 0,
                'trust_score': 0,
                'popularity_score': 0
            },
            'content_analysis': {
                'suspicious_keywords': 0,
                'obfuscated_code': False,
                'external_redirects': 0,
                'suspicious_forms': 0
            },
            'network_analysis': {
                'ip_reputation': 'Unknown',
                'hosting_provider': 'Unknown',
                'geolocation': 'Unknown',
                'is_tor_exit': False
            },
            'verdict': 'Clean',
            'confidence_score': 0
        }
        
        url_lower = url.lower()
        content_lower = content.lower()
        
        # Malware detection
        malware_signatures = [
            'eval(', 'base64_decode', 'shell_exec', 'system(', 'exec(',
            'file_get_contents', 'curl_exec', 'fopen(', 'fwrite(',
            'javascript:void', '<script>alert', 'document.cookie',
            'innerHTML', 'onload=', 'onerror=', 'onclick='
        ]
        
        detected_signatures = []
        for signature in malware_signatures:
            if signature in content_lower:
                detected_signatures.append(signature)
        
        if detected_signatures:
            threat_assessment['malware_detection']['detected'] = True
            threat_assessment['malware_detection']['signatures'] = detected_signatures
            threat_assessment['malware_detection']['confidence'] = min(100, len(detected_signatures) * 20)
            threat_assessment['threat_categories'].append('Malware')
        
        # Phishing detection
        phishing_indicators = []
        
        # Check for common phishing patterns
        phishing_patterns = [
            'verify.*account', 'suspended.*account', 'click.*here.*verify',
            'update.*payment', 'confirm.*identity', 'security.*alert',
            'unusual.*activity', 'temporary.*hold', 'expires.*today'
        ]
        
        for pattern in phishing_patterns:
            if re.search(pattern, content_lower):
                phishing_indicators.append(pattern)
        
        # Check URL for phishing indicators
        url_phishing_patterns = [
            'secure', 'verify', 'account', 'login', 'signin',
            'update', 'confirm', 'suspended', 'blocked'
        ]
        
        url_phishing_count = sum(1 for pattern in url_phishing_patterns if pattern in url_lower)
        if url_phishing_count >= 2:
            phishing_indicators.append(f'URL contains {url_phishing_count} phishing keywords')
        
        if phishing_indicators:
            threat_assessment['phishing_detection']['detected'] = True
            threat_assessment['phishing_detection']['indicators'] = phishing_indicators
            threat_assessment['phishing_detection']['confidence'] = min(100, len(phishing_indicators) * 25)
            threat_assessment['threat_categories'].append('Phishing')
        
        # Suspicious activities
        suspicious_activities = []
        
        # Check for redirects
        redirect_patterns = ['location.href', 'window.location', 'meta.*refresh', 'http-equiv.*refresh']
        for pattern in redirect_patterns:
            if re.search(pattern, content_lower):
                suspicious_activities.append(f'Redirect detected: {pattern}')
        
        # Check for obfuscated code
        if re.search(r'[a-z]{50,}', content_lower):  # Long random strings
            threat_assessment['content_analysis']['obfuscated_code'] = True
            suspicious_activities.append('Obfuscated code detected')
        
        # Check for suspicious forms
        form_count = content_lower.count('<form')
        password_fields = content_lower.count('type="password"') + content_lower.count("type='password'")
        
        if form_count > 0 and password_fields > 0:
            threat_assessment['content_analysis']['suspicious_forms'] = form_count
            if form_count > 2:
                suspicious_activities.append(f'Multiple forms with password fields ({form_count})')
        
        threat_assessment['suspicious_activities'] = suspicious_activities
        
        # Domain reputation analysis
        try:
            # Simple age-based scoring
            import whois
            w = whois.whois(domain)
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                
                domain_age_days = (datetime.now() - creation_date).days
                
                if domain_age_days > 365:
                    threat_assessment['domain_reputation']['age_score'] = 100
                elif domain_age_days > 180:
                    threat_assessment['domain_reputation']['age_score'] = 75
                elif domain_age_days > 30:
                    threat_assessment['domain_reputation']['age_score'] = 50
                else:
                    threat_assessment['domain_reputation']['age_score'] = 25
                    suspicious_activities.append(f'Very new domain ({domain_age_days} days old)')
        except:
            threat_assessment['domain_reputation']['age_score'] = 0
        
        # Calculate overall risk score
        risk_score = 0
        
        if threat_assessment['malware_detection']['detected']:
            risk_score += threat_assessment['malware_detection']['confidence']
        
        if threat_assessment['phishing_detection']['detected']:
            risk_score += threat_assessment['phishing_detection']['confidence']
        
        risk_score += len(suspicious_activities) * 10
        
        if threat_assessment['domain_reputation']['age_score'] < 50:
            risk_score += 20
        
        threat_assessment['overall_risk_score'] = min(100, risk_score)
        
        # Determine verdict
        if threat_assessment['overall_risk_score'] >= 80:
            threat_assessment['verdict'] = 'Malicious'
            threat_assessment['confidence_score'] = 95
        elif threat_assessment['overall_risk_score'] >= 60:
            threat_assessment['verdict'] = 'Suspicious'
            threat_assessment['confidence_score'] = 80
        elif threat_assessment['overall_risk_score'] >= 40:
            threat_assessment['verdict'] = 'Potentially Risky'
            threat_assessment['confidence_score'] = 65
        elif threat_assessment['overall_risk_score'] >= 20:
            threat_assessment['verdict'] = 'Low Risk'
            threat_assessment['confidence_score'] = 45
        else:
            threat_assessment['verdict'] = 'Clean'
            threat_assessment['confidence_score'] = 90
        
        return threat_assessment

    def check_url_availability_and_dns_blocking(self, url: str, domain: str) -> Dict:
        """Check URL availability and DNS blocking status across multiple resolvers and threat feeds"""
        availability_check = {
            'url_online': False,
            'response_time_ms': 0,
            'http_status_code': None,
            'last_checked': datetime.now(timezone.utc).isoformat(),
            'dns_resolvers': {},
            'threat_intelligence_feeds': {},
            'total_blocklists': 0,
            'blocked_by_count': 0,
            'availability_score': 0
        }
        
        # Check URL availability
        try:
            import requests
            start_time = time.time()
            response = requests.head(url, timeout=10, allow_redirects=True, headers={
                'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'
            })
            response_time = (time.time() - start_time) * 1000
            
            availability_check['url_online'] = True
            availability_check['response_time_ms'] = int(response_time)
            availability_check['http_status_code'] = response.status_code
            
        except requests.exceptions.ConnectionError:
            availability_check['url_online'] = False
            availability_check['response_time_ms'] = 9999
            availability_check['http_status_code'] = 'Connection Failed'
        except requests.exceptions.Timeout:
            availability_check['url_online'] = False
            availability_check['response_time_ms'] = 9999
            availability_check['http_status_code'] = 'Timeout'
        except Exception as e:
            availability_check['url_online'] = False
            availability_check['response_time_ms'] = 9999
            availability_check['http_status_code'] = f'Error: {str(e)[:50]}'
        
        # DNS Resolvers to check
        dns_resolvers = {
            'Cloudflare': ['1.1.1.1', '1.0.0.1'],
            'Quad9': ['9.9.9.9', '149.112.112.112'],
            'Google DNS': ['8.8.8.8', '8.8.4.4'],
            'AdGuard DNS': ['94.140.14.14', '94.140.15.15'],
            'OpenDNS (Family Shield)': ['208.67.222.123', '208.67.220.123'],
            'CleanBrowsing (Free Tier)': ['185.228.168.9', '185.228.169.9'],
            'dns0.eu': ['193.110.81.0', '185.253.5.0'],
            'CIRA Canadian Shield': ['149.112.121.10', '149.112.122.10']
        }
        
        # Check each DNS resolver
        for resolver_name, dns_servers in dns_resolvers.items():
            resolver_status = {
                'blocked': False,
                'status': 'Unknown',
                'response_time_ms': 0,
                'resolved_ips': []
            }
            
            for dns_server in dns_servers:
                try:
                    import dns.resolver
                    import socket
                    
                    # Create custom resolver
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [dns_server]
                    resolver.timeout = 5
                    resolver.lifetime = 5
                    
                    start_time = time.time()
                    try:
                        answers = resolver.resolve(domain, 'A')
                        response_time = (time.time() - start_time) * 1000
                        
                        resolver_status['status'] = 'Resolved'
                        resolver_status['blocked'] = False
                        resolver_status['response_time_ms'] = int(response_time)
                        resolver_status['resolved_ips'] = [str(rdata) for rdata in answers]
                        break  # Success with this DNS server
                        
                    except dns.resolver.NXDOMAIN:
                        resolver_status['status'] = 'NXDOMAIN (Blocked/Non-existent)'
                        resolver_status['blocked'] = True
                        break
                    except dns.resolver.NoAnswer:
                        resolver_status['status'] = 'No Answer'
                        resolver_status['blocked'] = True
                        break
                    except dns.resolver.Timeout:
                        resolver_status['status'] = 'Timeout'
                        continue  # Try next DNS server
                    except Exception as e:
                        resolver_status['status'] = f'Error: {str(e)[:30]}'
                        continue
                        
                except Exception as e:
                    resolver_status['status'] = f'DNS Error: {str(e)[:30]}'
                    continue
            
            availability_check['dns_resolvers'][resolver_name] = resolver_status
        
        # Threat Intelligence / DNS Blocklist Providers (simulated checks)
        threat_feeds = {
            'SURBL': self._check_surbl_simulation(domain),
            'Spamhaus': self._check_spamhaus_simulation(domain),
            'OpenBL': self._check_openbl_simulation(domain),
            'FireHOL IP Lists': self._check_firehol_simulation(domain),
            'AbuseIPDB': self._check_abuseipdb_simulation(domain),
            'AlienVault OTX': self._check_alienvault_simulation(domain),
            'Emerging Threats (ET Open)': self._check_emerging_threats_simulation(domain)
        }
        
        availability_check['threat_intelligence_feeds'] = threat_feeds
        
        # Calculate blocking statistics
        total_resolvers = len(dns_resolvers)
        blocked_resolvers = sum(1 for resolver_data in availability_check['dns_resolvers'].values() if resolver_data['blocked'])
        
        total_threat_feeds = len(threat_feeds)
        blocked_threat_feeds = sum(1 for feed_data in threat_feeds.values() if feed_data['listed'])
        
        availability_check['total_blocklists'] = total_resolvers + total_threat_feeds
        availability_check['blocked_by_count'] = blocked_resolvers + blocked_threat_feeds
        
        # Calculate availability score (0-100, higher is better)
        if availability_check['url_online']:
            base_score = 70
        else:
            base_score = 0
        
        # Deduct points for blocking
        blocking_penalty = (availability_check['blocked_by_count'] / availability_check['total_blocklists']) * 30
        availability_check['availability_score'] = max(0, int(base_score - blocking_penalty))
        
        return availability_check
    
    def _check_surbl_simulation(self, domain: str) -> Dict:
        """Simulate SURBL check"""
        # In production, this would query SURBL's DNS-based blacklist
        suspicious_patterns = ['phish', 'scam', 'malware', 'spam']
        listed = any(pattern in domain.lower() for pattern in suspicious_patterns)
        return {
            'listed': listed,
            'status': 'Listed' if listed else 'Clean',
            'categories': ['Phishing'] if listed else [],
            'last_seen': datetime.now(timezone.utc).isoformat() if listed else None
        }
    
    def _check_spamhaus_simulation(self, domain: str) -> Dict:
        """Simulate Spamhaus check"""
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
        spam_keywords = ['spam', 'bulk', 'mass']
        listed = (any(domain.endswith(tld) for tld in suspicious_tlds) or 
                 any(keyword in domain.lower() for keyword in spam_keywords))
        return {
            'listed': listed,
            'status': 'Listed' if listed else 'Clean',
            'categories': ['Spam', 'Malware'] if listed else [],
            'last_seen': datetime.now(timezone.utc).isoformat() if listed else None
        }
    
    def _check_openbl_simulation(self, domain: str) -> Dict:
        """Simulate OpenBL check"""
        # OpenBL focuses on open relays and compromised hosts
        suspicious_patterns = ['relay', 'compromised', 'infected']
        listed = any(pattern in domain.lower() for pattern in suspicious_patterns)
        return {
            'listed': listed,
            'status': 'Listed' if listed else 'Clean',
            'categories': ['Open Relay'] if listed else [],
            'last_seen': datetime.now(timezone.utc).isoformat() if listed else None
        }
    
    def _check_firehol_simulation(self, domain: str) -> Dict:
        """Simulate FireHOL IP Lists check"""
        malicious_patterns = ['botnet', 'c2', 'command', 'control']
        listed = any(pattern in domain.lower() for pattern in malicious_patterns)
        return {
            'listed': listed,
            'status': 'Listed' if listed else 'Clean',
            'categories': ['Botnet', 'C&C'] if listed else [],
            'last_seen': datetime.now(timezone.utc).isoformat() if listed else None
        }
    
    def _check_abuseipdb_simulation(self, domain: str) -> Dict:
        """Simulate AbuseIPDB check"""
        abuse_patterns = ['abuse', 'attack', 'exploit', 'hack']
        listed = any(pattern in domain.lower() for pattern in abuse_patterns)
        return {
            'listed': listed,
            'status': 'Listed' if listed else 'Clean',
            'categories': ['Abuse', 'Attack'] if listed else [],
            'confidence': 95 if listed else 0,
            'last_seen': datetime.now(timezone.utc).isoformat() if listed else None
        }
    
    def _check_alienvault_simulation(self, domain: str) -> Dict:
        """Simulate AlienVault OTX check"""
        threat_patterns = ['threat', 'ioc', 'indicator', 'malicious']
        listed = any(pattern in domain.lower() for pattern in threat_patterns)
        return {
            'listed': listed,
            'status': 'Listed' if listed else 'Clean',
            'categories': ['IOC', 'Malicious'] if listed else [],
            'pulse_count': 5 if listed else 0,
            'last_seen': datetime.now(timezone.utc).isoformat() if listed else None
        }
    
    def _check_emerging_threats_simulation(self, domain: str) -> Dict:
        """Simulate Emerging Threats check"""
        et_patterns = ['emerging', 'trojan', 'backdoor', 'exploit']
        listed = any(pattern in domain.lower() for pattern in et_patterns)
        return {
            'listed': listed,
            'status': 'Listed' if listed else 'Clean',
            'categories': ['Emerging Threat', 'Malware'] if listed else [],
            'rule_id': 'ET001' if listed else None,
            'last_seen': datetime.now(timezone.utc).isoformat() if listed else None
        }

    async def check_blacklist_status(self, url: str, domain: str) -> Dict:
        """Check URL against multiple blacklist databases"""
        blacklist_results = {
            'is_blacklisted': False,
            'blacklist_sources': [],
            'reputation_score': 100,  # 0-100, higher is better
            'total_sources_checked': 0,
            'sources_reporting_malicious': 0
        }
        
        sources_checked = 0
        malicious_reports = 0
        
        # Google Safe Browsing (simulated - in production use actual API)
        try:
            # This would be replaced with actual Google Safe Browsing API
            # For now, we'll do heuristic checks
            sources_checked += 1
            if any(indicator in url.lower() for indicator in ['phish', 'malware', 'scam', 'fake']):
                malicious_reports += 1
                blacklist_results['blacklist_sources'].append('Google Safe Browsing (heuristic)')
        except:
            pass
        
        # PhishTank check (simulated)
        try:
            sources_checked += 1
            phishing_indicators = ['login', 'verify', 'account', 'secure', 'update']
            if sum(1 for indicator in phishing_indicators if indicator in url.lower()) >= 2:
                malicious_reports += 1
                blacklist_results['blacklist_sources'].append('PhishTank (heuristic)')
        except:
            pass
        
        # Norton Safe Web (simulated)
        try:
            sources_checked += 1
            if any(tld in domain.lower() for tld in ['.tk', '.ml', '.ga', '.cf']) and 'payment' in url.lower():
                malicious_reports += 1
                blacklist_results['blacklist_sources'].append('Norton Safe Web (heuristic)')
        except:
            pass
        
        # McAfee SiteAdvisor (simulated)
        try:
            sources_checked += 1
            suspicious_patterns = ['download', 'crack', 'keygen', 'serial']
            if any(pattern in url.lower() for pattern in suspicious_patterns):
                malicious_reports += 1
                blacklist_results['blacklist_sources'].append('McAfee SiteAdvisor (heuristic)')
        except:
            pass
        
        # Spamhaus (simulated)
        try:
            sources_checked += 1
            if len(domain.split('.')[0]) > 20 and any(char.isdigit() for char in domain):
                malicious_reports += 1
                blacklist_results['blacklist_sources'].append('Spamhaus (heuristic)')
        except:
            pass
        
        blacklist_results['total_sources_checked'] = sources_checked
        blacklist_results['sources_reporting_malicious'] = malicious_reports
        blacklist_results['is_blacklisted'] = malicious_reports > 0
        
        # Calculate reputation score
        if sources_checked > 0:
            reputation_percentage = (sources_checked - malicious_reports) / sources_checked
            blacklist_results['reputation_score'] = int(reputation_percentage * 100)
        
        return blacklist_results

    def check_security_headers(self, url: str) -> Dict:
        """Check security headers (Sucuri-like feature)"""
        security_headers = {
            'headers_present': [],
            'headers_missing': [],
            'security_score': 0,
            'recommendations': []
        }
        
        important_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy', 
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy'
        ]
        
        try:
            response = requests.head(url, timeout=10, allow_redirects=True)
            headers = response.headers
            
            for header in important_headers:
                if header in headers:
                    security_headers['headers_present'].append(header)
                else:
                    security_headers['headers_missing'].append(header)
            
            # Calculate security score
            score = (len(security_headers['headers_present']) / len(important_headers)) * 100
            security_headers['security_score'] = int(score)
            
            # Generate recommendations
            if 'Strict-Transport-Security' not in headers:
                security_headers['recommendations'].append('Enable HSTS (HTTP Strict Transport Security)')
            if 'Content-Security-Policy' not in headers:
                security_headers['recommendations'].append('Implement Content Security Policy')
            if 'X-Frame-Options' not in headers:
                security_headers['recommendations'].append('Add X-Frame-Options header to prevent clickjacking')
            
        except Exception as e:
            security_headers['error'] = str(e)
            security_headers['security_score'] = 0
        
        return security_headers

    def check_outdated_software(self, url: str, content: str = "") -> Dict:
        """Check for outdated software indicators (Sucuri-like feature)"""
        software_check = {
            'detected_software': [],
            'outdated_components': [],
            'vulnerability_risk': 'Low',
            'recommendations': []
        }
        
        # Common CMS and software signatures
        cms_signatures = {
            'WordPress': [r'wp-content', r'wp-includes', r'/wp-admin/', r'wordpress'],
            'Drupal': [r'sites/all/', r'sites/default/', r'drupal'],
            'Joomla': [r'administrator/', r'components/', r'joomla'],
            'Magento': [r'skin/frontend/', r'app/design/', r'magento'],
            'Shopify': [r'shopify', r'myshopify.com'],
            'WooCommerce': [r'woocommerce', r'wc-'],
            'jQuery': [r'jquery', r'jQuery'],
        }
        
        content_lower = content.lower()
        url_lower = url.lower()
        
        # Detect software
        for software, patterns in cms_signatures.items():
            for pattern in patterns:
                if re.search(pattern, content_lower) or re.search(pattern, url_lower):
                    software_check['detected_software'].append(software)
                    break
        
        # Check for version information and potential vulnerabilities
        version_patterns = [
            r'version\s*[\'"]?(\d+\.\d+(?:\.\d+)?)',
            r'ver\s*[\'"]?(\d+\.\d+(?:\.\d+)?)',
            r'v(\d+\.\d+(?:\.\d+)?)',
        ]
        
        for pattern in version_patterns:
            matches = re.findall(pattern, content_lower)
            for match in matches:
                # Simple heuristic: versions starting with 0.x or 1.x might be outdated
                if match.startswith(('0.', '1.', '2.')):
                    software_check['outdated_components'].append(f"Version {match} detected")
        
        # Assess risk level
        if len(software_check['outdated_components']) > 2:
            software_check['vulnerability_risk'] = 'High'
            software_check['recommendations'].append('Update all outdated software components immediately')
        elif len(software_check['outdated_components']) > 0:
            software_check['vulnerability_risk'] = 'Medium' 
            software_check['recommendations'].append('Consider updating detected outdated components')
        
        # Add general recommendations
        if 'WordPress' in software_check['detected_software']:
            software_check['recommendations'].append('Ensure WordPress core, themes, and plugins are up to date')
        
        return software_check

    def calculate_payment_security_score(self, url: str, ml_predictions: Dict, domain_features: Dict) -> int:
        """Calculate payment security score (0-100, higher is more secure)"""
        score = 100  # Start with perfect security
        
        # Deduct points for e-skimming probability
        e_skimming_prob = ml_predictions.get('e_skimming_probability', 0)
        score -= int(e_skimming_prob * 80)  # Up to 80 points deduction
        
        # Deduct points for phishing/malware
        phishing_prob = ml_predictions.get('phishing_probability', 0)
        malware_prob = ml_predictions.get('malware_probability', 0)
        score -= int((phishing_prob + malware_prob) * 30)  # Up to 60 points deduction
        
        # Add points for trusted payment processors
        if any(processor in url.lower() for processor in self.trusted_payment_processors):
            score = min(100, score + 20)
        
        # Deduct points for missing security features
        if not domain_features.get('has_ssl', False):
            score -= 30
        
        # Deduct points for suspicious TLD
        if any(url.lower().endswith(tld) for tld in self.suspicious_tlds):
            score -= 25
        
        return max(0, min(100, score))

    def determine_transaction_halt_recommendation(self, risk_score: int, e_skimming_indicators: List[str], payment_security_score: int) -> bool:
        """Determine if transactions should be halted based on regulatory requirements"""
        # Halt transactions if:
        # 1. High risk score (>70)
        # 2. E-skimming indicators detected
        # 3. Low payment security score (<50)
        # 4. Critical e-skimming malware detected
        
        if risk_score > 70:
            return True
        
        if len(e_skimming_indicators) > 0:
            return True
        
        if payment_security_score < 50:
            return True
        
        # Check for critical e-skimming patterns
        critical_patterns = ['magecart', 'skimmer', 'cardstealer', 'formgrabber']
        if any(pattern in ' '.join(e_skimming_indicators).lower() for pattern in critical_patterns):
            return True
        
        return False

    def determine_compliance_status(self, risk_score: int, transaction_halt_required: bool, e_skimming_indicators: List[str]) -> str:
        """Determine compliance status for regulatory reporting"""
        if transaction_halt_required:
            return "NON_COMPLIANT_CRITICAL"
        elif risk_score > 50 or len(e_skimming_indicators) > 0:
            return "NON_COMPLIANT_MODERATE"
        elif risk_score > 30:
            return "COMPLIANT_WITH_WARNINGS"
        else:
            return "FULLY_COMPLIANT"

    def _get_ml_predictions(self, url: str) -> Dict:
        """Get predictions from ML models including e-skimming detection"""
        features = np.array([self._extract_ml_features(url)])
        
        try:
            phishing_prob = self.phishing_model.predict_proba(features)[0][1]
            malware_prob = self.malware_model.predict_proba(features)[0][1]
            
            # TF-IDF analysis
            tfidf_features = self.tfidf_vectorizer.transform([url])
            tfidf_score = tfidf_features.sum()
            
            # E-skimming probability calculation (heuristic-based)
            e_skimming_prob = 0.0
            url_lower = url.lower()
            
            # Check for payment-related keywords
            payment_keywords = ['payment', 'checkout', 'billing', 'cart', 'order', 'purchase']
            payment_score = sum(1 for keyword in payment_keywords if keyword in url_lower) / len(payment_keywords)
            
            # Check for suspicious patterns
            suspicious_patterns = ['inter.php', 'gate.php', 'card.php', 'payment.php']
            pattern_score = sum(1 for pattern in suspicious_patterns if pattern in url_lower)
            
            # Combine scores for e-skimming probability
            e_skimming_prob = min(1.0, (payment_score * 0.6) + (pattern_score * 0.4) + (malware_prob * 0.3))
            
            return {
                'phishing_probability': float(phishing_prob),
                'malware_probability': float(malware_prob),
                'e_skimming_probability': float(e_skimming_prob),
                'content_similarity_score': float(tfidf_score),
                'ensemble_score': float((phishing_prob + malware_prob + e_skimming_prob) / 3)
            }
        except Exception as e:
            return {
                'phishing_probability': 0.5,
                'malware_probability': 0.5,
                'e_skimming_probability': 0.3,
                'content_similarity_score': 0.0,
                'ensemble_score': 0.4,
                'error': str(e)
            }

    async def _take_screenshot(self, url: str) -> Optional[Dict]:
        """Take screenshot and analyze it"""
        if not self.screenshot_driver:
            return None
            
        try:
            # Take screenshot
            self.screenshot_driver.get(url)
            time.sleep(3)  # Wait for page load
            
            # Save screenshot
            screenshot_path = f"/tmp/screenshot_{uuid.uuid4().hex}.png"
            self.screenshot_driver.save_screenshot(screenshot_path)
            
            # Analyze screenshot
            analysis = self._analyze_screenshot(screenshot_path)
            
            # Clean up
            os.remove(screenshot_path)
            
            return analysis
            
        except Exception as e:
            return {'error': str(e), 'text_extracted': '', 'suspicious_elements': []}

    def _analyze_screenshot(self, screenshot_path: str) -> Dict:
        """Analyze screenshot using OCR and image processing"""
        try:
            # Load image
            image = cv2.imread(screenshot_path)
            
            # Extract text using OCR
            extracted_text = pytesseract.image_to_string(image)
            
            # Look for suspicious elements
            suspicious_elements = []
            
            # Check for common phishing indicators in text
            for keyword in self.phishing_keywords:
                if keyword.lower() in extracted_text.lower():
                    suspicious_elements.append(f"Suspicious text: {keyword}")
            
            # Check for form elements (basic detection)
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            edges = cv2.Canny(gray, 50, 150)
            contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            
            # Detect potential form fields (rectangular shapes)
            form_fields = 0
            for contour in contours:
                x, y, w, h = cv2.boundingRect(contour)
                aspect_ratio = w / float(h)
                if 2 < aspect_ratio < 10 and w > 100 and h > 20:
                    form_fields += 1
            
            if form_fields > 3:
                suspicious_elements.append(f"Multiple form fields detected: {form_fields}")
            
            return {
                'text_extracted': extracted_text[:500],  # First 500 chars
                'suspicious_elements': suspicious_elements,
                'form_fields_detected': form_fields,
                'text_length': len(extracted_text)
            }
            
        except Exception as e:
            return {'error': str(e), 'text_extracted': '', 'suspicious_elements': []}

    def _detect_campaign(self, url: str, analysis_details: Dict) -> Optional[Dict]:
        """Detect if URL belongs to a known campaign"""
        try:
            # Extract campaign signatures
            domain = urlparse(url).netloc
            path_structure = re.sub(r'[0-9]+', 'X', urlparse(url).path)
            
            # Create signature
            signature = {
                'domain_pattern': re.sub(r'[0-9]+', 'X', domain),
                'path_pattern': path_structure,
                'threat_indicators': analysis_details.get('threat_indicators', []),
                'risk_level': analysis_details.get('risk_score', 0)
            }
            
            # Simple campaign detection (in production, this would be more sophisticated)
            signature_key = f"{signature['domain_pattern']}:{signature['path_pattern']}"
            
            if signature_key in self.campaign_signatures:
                self.campaign_signatures[signature_key]['count'] += 1
                self.campaign_signatures[signature_key]['urls'].append(url)
                return {
                    'campaign_id': hashlib.md5(signature_key.encode()).hexdigest()[:8],
                    'campaign_size': self.campaign_signatures[signature_key]['count'],
                    'similar_urls': self.campaign_signatures[signature_key]['urls'][-5:],
                    'first_seen': self.campaign_signatures[signature_key]['first_seen']
                }
            else:
                self.campaign_signatures[signature_key] = {
                    'count': 1,
                    'urls': [url],
                    'first_seen': datetime.now(timezone.utc).isoformat(),
                    'signature': signature
                }
                return None
                
        except Exception as e:
            return None

    def analyze_lexical_features(self, url: str) -> Dict:
        """Enhanced lexical analysis"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        # Basic features
        features = {
            'url_length': len(url),
            'domain_length': len(domain),
            'path_length': len(path),
            'subdomain_count': len(domain.split('.')) - 2 if len(domain.split('.')) > 2 else 0,
            'suspicious_chars': len(re.findall(r'[%\-_~]', url)),
            'digits_in_domain': len(re.findall(r'\d', domain)),
            'has_ip_address': bool(re.match(r'^\d+\.\d+\.\d+\.\d+', domain)),
            'has_suspicious_tld': any(domain.endswith(tld) for tld in self.suspicious_tlds)
        }
        
        # Enhanced features
        features.update({
            'vowel_consonant_ratio': self._calculate_vowel_ratio(domain),
            'entropy': self._calculate_entropy(url),
            'special_char_count': len(re.findall(r'[^a-zA-Z0-9./:]', url)),
            'consecutive_consonants': self._max_consecutive_consonants(domain),
            'domain_tokens': len(re.findall(r'[a-zA-Z]+', domain)),
        })
        
        return features

    def _calculate_vowel_ratio(self, text: str) -> float:
        """Calculate vowel to consonant ratio"""
        vowels = len(re.findall(r'[aeiouAEIOU]', text))
        consonants = len(re.findall(r'[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]', text))
        return vowels / max(consonants, 1)

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        char_counts = Counter(text)
        text_length = len(text)
        entropy = -sum((count / text_length) * np.log2(count / text_length) for count in char_counts.values())
        return entropy

    def _max_consecutive_consonants(self, text: str) -> int:
        """Find maximum consecutive consonants"""
        consonants = re.findall(r'[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]+', text)
        return max(len(c) for c in consonants) if consonants else 0

    def analyze_content_features(self, url: str) -> Dict:
        """Enhanced content analysis"""
        features = {
            'phishing_keywords': 0,
            'malware_indicators': 0,
            'url_shortener': False,
            'homograph_attack': False
        }
        
        url_lower = url.lower()
        
        # Enhanced keyword detection
        features['phishing_keywords'] = sum(1 for keyword in self.phishing_keywords if keyword in url_lower)
        features['malware_indicators'] = sum(1 for indicator in self.malware_indicators if indicator in url_lower)
        
        # URL shortener detection
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'short.ly', 'ow.ly', 'buff.ly']
        features['url_shortener'] = any(shortener in url_lower for shortener in shorteners)
        
        # Enhanced homograph detection
        suspicious_chars = ['а', 'о', 'р', 'с', 'е', 'х', 'і', 'ӏ', 'ј']  # Cyrillic lookalikes
        features['homograph_attack'] = any(char in url for char in suspicious_chars)
        
        # Pattern matching
        features['pattern_matches'] = sum(1 for pattern in self.phishing_patterns if re.search(pattern, url_lower))
        
        return features

    def analyze_domain_reputation(self, domain: str) -> Dict:
        """Enhanced domain reputation analysis with proper SSL detection"""
        features = {
            'is_trusted_domain': False,
            'domain_age_days': 0,
            'has_ssl': False,
            'ssl_issuer': None,
            'ssl_expires': None,
            'dns_resolution_time': 0,
            'mx_records_exist': False,
            'geographic_location': None,
            'registrar_info': None
        }
        
        # Check if trusted domain
        features['is_trusted_domain'] = any(trusted in domain for trusted in self.trusted_domains)
        
        # Enhanced SSL check with multiple approaches
        ssl_detected = False
        ssl_issuer = None
        ssl_expires = None
        
        # Method 1: Direct SSL connection
        try:
            import ssl
            import socket
            from datetime import datetime
            
            context = ssl.create_default_context()
            # Set a longer timeout for SSL check
            socket.setdefaulttimeout(10)
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    ssl_detected = True
                    cert = ssock.getpeercert()
                    if cert:
                        # Get issuer information
                        issuer_info = cert.get('issuer', [])
                        for item in issuer_info:
                            if item[0] == 'organizationName':
                                ssl_issuer = item[1]
                                break
                        
                        # Get expiration date
                        not_after = cert.get('notAfter')
                        if not_after:
                            try:
                                exp_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                ssl_expires = exp_date.isoformat()
                            except:
                                pass
        except Exception as e:
            # Method 2: Try HTTPS request
            try:
                import requests
                response = requests.get(f"https://{domain}", timeout=5, verify=True)
                if response.status_code < 500:  # Any response means SSL is working
                    ssl_detected = True
                    ssl_issuer = "Verified via HTTPS"
            except requests.exceptions.SSLError:
                ssl_detected = False
            except requests.exceptions.ConnectionError:
                # Method 3: Check if domain responds to HTTPS at all
                try:
                    import urllib3
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                    response = requests.get(f"https://{domain}", timeout=5, verify=False)
                    ssl_detected = True
                    ssl_issuer = "SSL Present (Certificate may be invalid)"
                except:
                    ssl_detected = False
            except:
                ssl_detected = False
        
        features['has_ssl'] = ssl_detected
        features['ssl_issuer'] = ssl_issuer or 'Unknown'
        features['ssl_expires'] = ssl_expires

        # DNS checks
        try:
            import dns.resolver
            dns.resolver.resolve(domain, 'MX')
            features['mx_records_exist'] = True
        except:
            features['mx_records_exist'] = False

        # DNS resolution time
        try:
            start_time = datetime.now()
            socket.gethostbyname(domain)
            features['dns_resolution_time'] = (datetime.now() - start_time).total_seconds() * 1000
        except:
            features['dns_resolution_time'] = 9999

        # WHOIS lookup (simplified)
        try:
            import whois
            w = whois.whois(domain)
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                features['domain_age_days'] = (datetime.now() - creation_date).days
            features['registrar_info'] = str(w.registrar) if w.registrar else None
        except:
            pass

        return features

    def calculate_risk_score(self, lexical_features: Dict, content_features: Dict, domain_features: Dict, ml_predictions: Dict) -> int:
        """Enhanced risk score calculation with ML integration"""
        score = 0
        
        # Lexical scoring (enhanced)
        if lexical_features['url_length'] > 150:
            score += 20
        elif lexical_features['url_length'] > 75:
            score += 10
        
        # Entropy-based scoring
        if lexical_features.get('entropy', 0) > 4:
            score += 15
        
        # Subdomain scoring
        if lexical_features['subdomain_count'] > 4:
            score += 25
        elif lexical_features['subdomain_count'] > 2:
            score += 15
        
        # Critical indicators
        if lexical_features['has_ip_address']:
            score += 30
        if lexical_features['has_suspicious_tld']:
            score += 25
        if lexical_features['suspicious_chars'] > 8:
            score += 20
        
        # Content scoring (enhanced)
        score += min(content_features['phishing_keywords'] * 12, 50)
        score += min(content_features['malware_indicators'] * 15, 40)
        score += min(content_features.get('pattern_matches', 0) * 18, 35)
        
        if content_features['url_shortener']:
            score += 20
        if content_features['homograph_attack']:
            score += 35
        
        # Domain reputation scoring
        if domain_features['is_trusted_domain']:
            score = max(0, score - 60)
        if not domain_features['has_ssl']:
            score += 25
        if not domain_features['mx_records_exist']:
            score += 15
        if domain_features['dns_resolution_time'] > 10000:
            score += 20
        if domain_features.get('domain_age_days', 0) < 30:
            score += 30
        
        # ML model integration
        ml_score = ml_predictions.get('ensemble_score', 0.5) * 100
        score = int((score * 0.7) + (ml_score * 0.3))  # Weighted combination
        
        return min(100, max(0, score))

    def categorize_threat(self, score: int, content_features: Dict, ml_predictions: Dict, e_skimming_indicators: List[str] = None) -> str:
        """Enhanced threat categorization with e-skimming detection"""
        if e_skimming_indicators is None:
            e_skimming_indicators = []
            
        phishing_prob = ml_predictions.get('phishing_probability', 0)
        malware_prob = ml_predictions.get('malware_probability', 0)
        
        # Check for e-skimming threats first
        if len(e_skimming_indicators) > 0:
            critical_patterns = ['magecart', 'skimmer', 'cardstealer', 'formgrabber']
            if any(pattern in ' '.join(e_skimming_indicators).lower() for pattern in critical_patterns):
                return "E-Skimming Threat"
            elif len(e_skimming_indicators) > 2:
                return "Payment Security Risk"
        
        if phishing_prob > 0.7 or content_features['phishing_keywords'] > 3:
            return "Phishing"
        elif malware_prob > 0.7 or content_features['malware_indicators'] > 2:
            return "Malware"
        elif score > 80:
            return "Critical Risk"
        elif score > 60:
            return "High Risk"
        elif score > 40:
            return "Moderate Risk"
        elif score > 20:
            return "Low Risk"
        else:
            return "Safe"

    async def analyze_url(self, url: str, include_screenshot: bool = True, scan_type: str = "standard") -> ThreatAnalysis:
        """Enhanced URL analysis with e-skimming detection and Sucuri-like features"""
        scan_id = str(uuid.uuid4())
        
        # Parse URL
        try:
            parsed = urlparse(url)
            if not parsed.scheme:
                url = f"https://{url}"
                parsed = urlparse(url)
            domain = parsed.netloc
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid URL format: {str(e)}")
        
        # Get page content for analysis
        content = ""
        try:
            response = requests.get(url, timeout=15, headers={
                'User-Agent': 'E-Skimming Security Scanner/3.0 (Compliance Check)'
            })
            content = response.text[:10000]  # First 10000 characters
        except:
            content = ""
        
        # Enhanced analysis with detailed checks
        lexical_features = self.analyze_lexical_features(url)
        content_features = self.analyze_content_features(url)
        domain_features = self.analyze_domain_reputation(domain)
        ml_predictions = self._get_ml_predictions(url)
        
        # E-skimming specific analysis
        e_skimming_indicators = self.analyze_e_skimming_indicators(url, content)
        
        # Standard security features (always included)
        blacklist_status = await self.check_blacklist_status(url, domain)
        security_headers = self.check_security_headers(url)
        software_check = self.check_outdated_software(url, content)
        
        # Detailed analysis (for detailed report)
        detailed_ssl_analysis = self.analyze_detailed_ssl_certificate(domain)
        email_security = self.check_email_security_records(domain)
        threat_assessment = self.comprehensive_threat_assessment(url, domain, content)
        
        # DNS & Availability checking
        dns_availability = self.check_url_availability_and_dns_blocking(url, domain)
        
        # Screenshot analysis (optional for performance)
        screenshot_analysis = None
        if include_screenshot:
            screenshot_analysis = await self._take_screenshot(url)
        
        # Calculate enhanced risk score
        risk_score = self.calculate_risk_score(lexical_features, content_features, domain_features, ml_predictions)
        
        # Adjust risk score based on Sucuri-like checks
        if blacklist_status['is_blacklisted']:
            risk_score = min(100, risk_score + 30)
        if security_headers['security_score'] < 50:
            risk_score = min(100, risk_score + 15)
        if software_check['vulnerability_risk'] == 'High':
            risk_score = min(100, risk_score + 20)
        
        # Calculate payment security score
        payment_security_score = self.calculate_payment_security_score(url, ml_predictions, domain_features)
        
        # Regulatory compliance checks
        transaction_halt_required = self.determine_transaction_halt_recommendation(
            risk_score, e_skimming_indicators, payment_security_score
        )
        compliance_status = self.determine_compliance_status(
            risk_score, transaction_halt_required, e_skimming_indicators
        )
        
        # Categorize threat with enhanced awareness
        threat_category = self.categorize_threat(risk_score, content_features, ml_predictions, e_skimming_indicators)
        
        # Create enhanced analysis details
        analysis_details = {
            'lexical_analysis': lexical_features,
            'content_analysis': content_features,
            'domain_analysis': domain_features,
            'e_skimming_analysis': {
                'indicators_found': e_skimming_indicators,
                'payment_security_score': payment_security_score,
                'trusted_processor': any(processor in url.lower() for processor in self.trusted_payment_processors)
            },
            'blacklist_analysis': blacklist_status,
            'security_headers': security_headers,
            'software_analysis': software_check,
            'detailed_report': {
                'ssl_detailed_analysis': detailed_ssl_analysis,
                'email_security_records': email_security,
                'comprehensive_threat_assessment': threat_assessment,
                'dns_availability_check': dns_availability
            },
            'threat_indicators': self.get_threat_indicators(content_features, lexical_features, domain_features, ml_predictions, e_skimming_indicators)
        }
        
        # Campaign detection
        campaign_info = self._detect_campaign(url, analysis_details)
        
        # Generate enhanced recommendations
        recommendations = self.generate_recommendations(risk_score, content_features, lexical_features, domain_features, ml_predictions, e_skimming_indicators, transaction_halt_required)
        
        # Add Sucuri-like recommendations
        if blacklist_status['is_blacklisted']:
            recommendations.insert(0, f"⚠️ BLACKLISTED: Reported by {len(blacklist_status['blacklist_sources'])} security sources")
        
        if security_headers['security_score'] < 70:
            recommendations.extend([f"🔒 Security Headers: {rec}" for rec in security_headers['recommendations'][:2]])
        
        if software_check['vulnerability_risk'] in ['High', 'Medium']:
            recommendations.extend([f"🔄 Software Updates: {rec}" for rec in software_check['recommendations'][:2]])
        
        # Store in database with all enhanced data
        scan_result = {
            'scan_id': scan_id,
            'url': url,
            'scan_type': scan_type,
            'risk_score': risk_score,
            'threat_category': threat_category,
            'is_malicious': risk_score > 60,
            'e_skimming_indicators': e_skimming_indicators,
            'payment_security_score': payment_security_score,
            'transaction_halt_recommended': transaction_halt_required,
            'compliance_status': compliance_status,
            'analysis_details': analysis_details,
            'recommendations': recommendations,
            'ml_predictions': ml_predictions,
            'screenshot_analysis': screenshot_analysis,
            'campaign_info': campaign_info,
            'scan_timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        await db.scan_results.insert_one(scan_result)
        
        return ThreatAnalysis(
            risk_score=risk_score,
            threat_category=threat_category,
            is_malicious=risk_score > 60,
            analysis_details=analysis_details,
            recommendations=recommendations,
            scan_timestamp=scan_result['scan_timestamp'],
            scan_id=scan_id,
            ml_predictions=ml_predictions,
            screenshot_analysis=screenshot_analysis,
            campaign_info=campaign_info
        )

    async def bulk_analyze_urls(self, urls: List[str], job_id: str, scan_type: str = "standard") -> None:
        """Bulk URL analysis with e-skimming detection"""
        total_urls = len(urls)
        results = []
        
        # Create job record
        job_record = {
            'job_id': job_id,
            'total_urls': total_urls,
            'processed_urls': 0,
            'scan_type': scan_type,
            'status': 'processing',
            'results': [],
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        await db.bulk_scan_jobs.insert_one(job_record)
        
        # Process URLs
        for i, url in enumerate(urls):
            try:
                result = await self.analyze_url(url, include_screenshot=False, scan_type=scan_type)
                
                # Convert result to dict if it's a Pydantic model
                if hasattr(result, 'dict'):
                    result_dict = result.dict()
                elif hasattr(result, 'model_dump'):
                    result_dict = result.model_dump()
                else:
                    result_dict = dict(result)
                
                results.append(result_dict)
                
                # Update progress more frequently
                if (i + 1) % 5 == 0 or i == len(urls) - 1:  # Update every 5 URLs or on last URL
                    await db.bulk_scan_jobs.update_one(
                        {'job_id': job_id},
                        {'$set': {'processed_urls': i + 1, 'results': results}}
                    )
                
            except Exception as e:
                # Handle individual URL failures
                error_result = {
                    'url': url,
                    'error': str(e),
                    'risk_score': 0,
                    'is_malicious': False,
                    'threat_categories': [],
                    'scan_timestamp': datetime.now(timezone.utc).isoformat(),
                    'scan_type': scan_type
                }
                results.append(error_result)
                
                # Log the error for debugging
                print(f"Error processing URL {url}: {str(e)}")
        
        # Mark job as complete
        await db.bulk_scan_jobs.update_one(
            {'job_id': job_id},
            {'$set': {'status': 'completed', 'results': results, 'processed_urls': total_urls}}
        )

    def generate_recommendations(self, risk_score: int, content_features: Dict, lexical_features: Dict, domain_features: Dict, ml_predictions: Dict, e_skimming_indicators: List[str] = None, transaction_halt_required: bool = False) -> List[str]:
        """Enhanced recommendations with ML insights and e-skimming awareness"""
        if e_skimming_indicators is None:
            e_skimming_indicators = []
            
        recommendations = []
        
        # E-skimming specific recommendations
        if transaction_halt_required:
            recommendations.append("🚨 REGULATORY ALERT: Transaction processing should be halted immediately")
            recommendations.append("Contact payment processor and regulatory authorities")
        
        if len(e_skimming_indicators) > 0:
            recommendations.append("⚠️ E-SKIMMING DETECTED: Payment forms may be compromised")
            recommendations.append("Avoid entering payment information on this site")
        
        # Risk-based recommendations
        if risk_score > 85:
            recommendations.append("🚨 CRITICAL: Block this URL immediately")
            recommendations.append("Report to security team and threat intelligence feeds")
        elif risk_score > 70:
            recommendations.append("🚨 HIGH RISK: Do not visit this URL")
            recommendations.append("Block this URL in your firewall/security software")
        elif risk_score > 50:
            recommendations.append("⚠️ CAUTION: Proceed with extreme caution")
            recommendations.append("Use isolated browsing environment if access is necessary")
        elif risk_score > 30:
            recommendations.append("⚡ MODERATE RISK: Be cautious when visiting")
            recommendations.append("Verify the URL authenticity before entering sensitive information")
        else:
            recommendations.append("✅ LOW RISK: Appears to be safe")
            recommendations.append("Standard security precautions recommended")
        
        # ML-based recommendations
        if ml_predictions.get('phishing_probability', 0) > 0.8:
            recommendations.append("ML Model detected high phishing probability")
        if ml_predictions.get('malware_probability', 0) > 0.8:
            recommendations.append("ML Model detected high malware probability")
        
        # Specific threat recommendations
        if content_features['phishing_keywords'] > 3:
            recommendations.append("Contains multiple phishing-related keywords")
        if lexical_features['has_ip_address']:
            recommendations.append("Uses IP address instead of domain name - highly suspicious")
        if not domain_features['has_ssl']:
            recommendations.append("No SSL certificate - data transmission not secure")
        if content_features['url_shortener']:
            recommendations.append("URL shortener detected - destination unclear, verify before clicking")
        if domain_features.get('domain_age_days', 999) < 30:
            recommendations.append("Very new domain (less than 30 days) - exercise extreme caution")
        
        return recommendations

    def get_threat_indicators(self, content_features: Dict, lexical_features: Dict, domain_features: Dict, ml_predictions: Dict, e_skimming_indicators: List[str] = None) -> List[str]:
        """Enhanced threat indicators with ML insights and e-skimming detection"""
        if e_skimming_indicators is None:
            e_skimming_indicators = []
            
        indicators = []
        
        # E-skimming specific indicators
        if len(e_skimming_indicators) > 0:
            indicators.extend([f"E-Skimming: {indicator}" for indicator in e_skimming_indicators[:3]])  # Limit to first 3
        
        # Traditional indicators
        if lexical_features['has_ip_address']:
            indicators.append("IP Address Usage")
        if lexical_features['has_suspicious_tld']:
            indicators.append("Suspicious Top-Level Domain")
        if content_features['phishing_keywords'] > 0:
            indicators.append(f"Phishing Keywords ({content_features['phishing_keywords']})")
        if content_features['malware_indicators'] > 0:
            indicators.append(f"Malware Indicators ({content_features['malware_indicators']})")
        if content_features['url_shortener']:
            indicators.append("URL Shortener")
        if content_features['homograph_attack']:
            indicators.append("Homograph Attack")
        if lexical_features['subdomain_count'] > 3:
            indicators.append("Excessive Subdomains")
        if not domain_features['has_ssl']:
            indicators.append("No SSL Certificate")
        
        # ML-based indicators
        if ml_predictions.get('phishing_probability', 0) > 0.7:
            indicators.append("High ML Phishing Score")
        if ml_predictions.get('malware_probability', 0) > 0.7:
            indicators.append("High ML Malware Score")
        if ml_predictions.get('ensemble_score', 0) > 0.8:
            indicators.append("High ML Ensemble Score")
        
        # Advanced indicators
        if lexical_features.get('entropy', 0) > 4.5:
            indicators.append("High URL Entropy")
        if lexical_features.get('consecutive_consonants', 0) > 6:
            indicators.append("Unusual Character Patterns")
        if content_features.get('pattern_matches', 0) > 2:
            indicators.append("Multiple Threat Patterns")
        
        return indicators

# Initialize analyzer
analyzer = AdvancedESkimmingAnalyzer()

# Bulk scan jobs storage
bulk_scan_jobs = {}

@app.get("/")
async def root():
    return {
        "message": "E-Skimming Protection & Malicious URL Detection API", 
        "version": "3.0.0", 
        "status": "active", 
        "features": [
            "E-Skimming Detection", 
            "Payment Gateway Security", 
            "Regulatory Compliance", 
            "Daily Merchant Scanning",
            "Transaction Halt Recommendations",
            "ML Analysis", 
            "Bulk Scanning",
            "Campaign Detection"
        ],
        "compliance": "Retail Payment Services and Card Schemes Regulation"
    }

@app.post("/api/scan/merchant")
async def scan_merchant_urls(request: MerchantScanRequest):
    """Scan merchant URLs for e-skimming compliance"""
    job_id = str(uuid.uuid4())
    
    # Store merchant information
    merchant_record = {
        'merchant_id': request.merchant_id,
        'merchant_name': request.merchant_name,
        'contact_email': request.contact_email,
        'scan_job_id': job_id,
        'created_at': datetime.now(timezone.utc).isoformat()
    }
    await db.merchants.insert_one(merchant_record)
    
    # Start background task for merchant scanning
    asyncio.create_task(analyzer.bulk_analyze_urls(request.urls, job_id))
    
    return {
        "job_id": job_id,
        "merchant_id": request.merchant_id,
        "status": "started",
        "total_urls": len(request.urls),
        "scan_type": "e_skimming",
        "compliance_check": True
    }

@app.post("/api/scan", response_model=ThreatAnalysis)
async def scan_url(request: URLScanRequest):
    """Enhanced URL scanning with e-skimming detection and Sucuri-like features"""
    try:
        result = await analyzer.analyze_url(request.url, include_screenshot=True, scan_type=request.scan_type)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/scan/bulk")
async def bulk_scan_urls(request: BulkScanRequest):
    """Start bulk URL scanning job"""
    job_id = str(uuid.uuid4())
    
    # Start background task with scan_type
    asyncio.create_task(analyzer.bulk_analyze_urls(request.urls, job_id, request.scan_type))
    
    return {"job_id": job_id, "status": "started", "total_urls": len(request.urls)}

@app.get("/api/scan/bulk/{job_id}")
async def get_bulk_scan_status(job_id: str):
    """Get bulk scan job status"""
    job = await db.bulk_scan_jobs.find_one({"job_id": job_id})
    if not job:
        raise HTTPException(status_code=404, detail="Bulk scan job not found")
    
    job.pop('_id', None)
    return job

@app.post("/api/scan/bulk/upload")
async def upload_bulk_scan_file(file: UploadFile = File(...), scan_type: str = "standard"):
    """Upload CSV file for bulk scanning"""
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files are supported")
    
    try:
        contents = await file.read()
        csv_file = io.StringIO(contents.decode('utf-8'))
        reader = csv.reader(csv_file)
        
        urls = []
        for row in reader:
            if row and row[0].strip():  # Skip empty rows
                urls.append(row[0].strip())
        
        if not urls:
            raise HTTPException(status_code=400, detail="No valid URLs found in CSV file")
        
        # Start bulk scan with scan_type
        job_id = str(uuid.uuid4())
        asyncio.create_task(analyzer.bulk_analyze_urls(urls, job_id, scan_type))
        
        return {"job_id": job_id, "status": "started", "total_urls": len(urls)}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File processing failed: {str(e)}")

@app.get("/api/scan/bulk/{job_id}/export")
async def export_bulk_scan_results(job_id: str, format: str = "csv"):
    """Export bulk scan results"""
    job = await db.bulk_scan_jobs.find_one({"job_id": job_id})
    if not job:
        raise HTTPException(status_code=404, detail="Bulk scan job not found")
    
    if job['status'] != 'completed':
        raise HTTPException(status_code=400, detail="Job not yet completed")
    
    results = job['results']
    
    if format.lower() == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['URL', 'Risk Score', 'Threat Category', 'Is Malicious', 'Scan Time', 'Recommendations'])
        
        # Write data
        for result in results:
            if 'error' in result:
                writer.writerow([result['url'], 'ERROR', result['error'], '', result['scan_timestamp'], ''])
            else:
                recommendations = '; '.join(result.get('recommendations', []))
                writer.writerow([
                    result.get('url', ''),
                    result.get('risk_score', ''),
                    result.get('threat_category', ''),
                    result.get('is_malicious', ''),
                    result.get('scan_timestamp', ''),
                    recommendations
                ])
        
        output.seek(0)
        return StreamingResponse(
            io.BytesIO(output.getvalue().encode()),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=bulk_scan_results_{job_id}.csv"}
        )
    
    elif format.lower() == 'json':
        return StreamingResponse(
            io.BytesIO(json.dumps(results, indent=2).encode()),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=bulk_scan_results_{job_id}.json"}
        )
    
    else:
        raise HTTPException(status_code=400, detail="Unsupported format. Use 'csv' or 'json'")

@app.get("/api/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    """Get scan result by ID"""
    result = await db.scan_results.find_one({"scan_id": scan_id})
    if not result:
        raise HTTPException(status_code=404, detail="Scan result not found")
    
    result.pop('_id', None)
    return result

@app.get("/api/stats")
async def get_stats():
    """Enhanced statistics with ML insights"""
    total_scans = await db.scan_results.count_documents({})
    malicious_count = await db.scan_results.count_documents({"is_malicious": True})
    
    # Get recent scans
    recent_scans = []
    async for scan in db.scan_results.find().sort("scan_timestamp", -1).limit(10):
        scan.pop('_id', None)
        recent_scans.append(scan)
    
    # Threat category distribution
    threat_categories = {}
    async for scan in db.scan_results.find({}, {"threat_category": 1}):
        category = scan.get('threat_category', 'Unknown')
        threat_categories[category] = threat_categories.get(category, 0) + 1
    
    # Time-series data (last 7 days)
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=7)
    
    daily_stats = []
    for i in range(7):
        day_start = start_date + timedelta(days=i)
        day_end = day_start + timedelta(days=1)
        
        day_scans = await db.scan_results.count_documents({
            "scan_timestamp": {
                "$gte": day_start.isoformat(),
                "$lt": day_end.isoformat()
            }
        })
        
        day_malicious = await db.scan_results.count_documents({
            "scan_timestamp": {
                "$gte": day_start.isoformat(),
                "$lt": day_end.isoformat()
            },
            "is_malicious": True
        })
        
        daily_stats.append({
            "date": day_start.strftime("%Y-%m-%d"),
            "total_scans": day_scans,
            "malicious_count": day_malicious,
            "detection_rate": round((day_malicious / max(day_scans, 1)) * 100, 2)
        })
    
    # Campaign statistics
    campaign_count = len(analyzer.campaign_signatures)
    
    return {
        "total_scans": total_scans,
        "malicious_urls_detected": malicious_count,
        "safe_urls": total_scans - malicious_count,
        "detection_rate": round((malicious_count / total_scans * 100), 2) if total_scans > 0 else 0,
        "recent_scans": recent_scans,
        "threat_categories": threat_categories,
        "daily_stats": daily_stats,
        "campaign_count": campaign_count,
        "bulk_jobs_completed": await db.bulk_scan_jobs.count_documents({"status": "completed"})
    }

@app.get("/api/analytics/trends")
async def get_trends():
    """Get threat trends over time"""
    end_date = datetime.now(timezone.utc)
    start_date = end_date - timedelta(days=30)
    
    # Get daily threat trends
    trends = []
    for i in range(30):
        day_start = start_date + timedelta(days=i)
        day_end = day_start + timedelta(days=1)
        
        pipeline = [
            {
                "$match": {
                    "scan_timestamp": {
                        "$gte": day_start.isoformat(),
                        "$lt": day_end.isoformat()
                    }
                }
            },
            {
                "$group": {
                    "_id": "$threat_category",
                    "count": {"$sum": 1}
                }
            }
        ]
        
        day_trends = {}
        async for doc in db.scan_results.aggregate(pipeline):
            day_trends[doc["_id"]] = doc["count"]
        
        trends.append({
            "date": day_start.strftime("%Y-%m-%d"),
            "trends": day_trends
        })
    
    return {"trends": trends}

@app.get("/api/campaigns")
async def get_campaigns():
    """Get detected campaigns"""
    campaigns = []
    for signature_key, campaign_data in analyzer.campaign_signatures.items():
        if campaign_data['count'] > 1:  # Only return campaigns with multiple URLs
            campaigns.append({
                'campaign_id': hashlib.md5(signature_key.encode()).hexdigest()[:8],
                'signature_pattern': signature_key,
                'url_count': campaign_data['count'],
                'first_seen': campaign_data['first_seen'],
                'sample_urls': campaign_data['urls'][-3:],  # Last 3 URLs
                'risk_level': campaign_data['signature']['risk_level']
            })
    
    # Sort by URL count (most prolific campaigns first)
    campaigns.sort(key=lambda x: x['url_count'], reverse=True)
    
    return {"campaigns": campaigns[:20]}  # Return top 20 campaigns

@app.get("/api/compliance/dashboard")
async def get_compliance_dashboard():
    """Get compliance dashboard data for regulatory reporting"""
    today = datetime.now(timezone.utc).date()
    
    # Today's scan statistics
    today_start = datetime.combine(today, datetime.min.time()).replace(tzinfo=timezone.utc)
    today_end = today_start + timedelta(days=1)
    
    today_scans = await db.scan_results.count_documents({
        "scan_timestamp": {
            "$gte": today_start.isoformat(),
            "$lt": today_end.isoformat()
        }
    })
    
    today_threats = await db.scan_results.count_documents({
        "scan_timestamp": {
            "$gte": today_start.isoformat(),
            "$lt": today_end.isoformat()
        },
        "is_malicious": True
    })
    
    today_e_skimming = await db.scan_results.count_documents({
        "scan_timestamp": {
            "$gte": today_start.isoformat(),
            "$lt": today_end.isoformat()
        },
        "threat_category": "E-Skimming Threat"
    })
    
    today_transaction_halts = await db.scan_results.count_documents({
        "scan_timestamp": {
            "$gte": today_start.isoformat(),
            "$lt": today_end.isoformat()
        },
        "transaction_halt_recommended": True
    })
    
    # Compliance status distribution
    compliance_stats = {}
    async for doc in db.scan_results.aggregate([
        {"$group": {"_id": "$compliance_status", "count": {"$sum": 1}}}
    ]):
        compliance_stats[doc["_id"]] = doc["count"]
    
    # Active merchants
    active_merchants = await db.merchants.count_documents({})
    
    return {
        "today_scans": today_scans,
        "today_threats_detected": today_threats,
        "today_e_skimming_detected": today_e_skimming,
        "today_transaction_halts": today_transaction_halts,
        "compliance_distribution": compliance_stats,
        "active_merchants": active_merchants,
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "regulatory_compliance": "Retail Payment Services and Card Schemes Regulation"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)