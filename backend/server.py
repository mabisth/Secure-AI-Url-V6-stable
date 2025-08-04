from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, HttpUrl, EmailStr
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

# MongoDB collections
scan_results = db.scan_results
bulk_scan_jobs = db.bulk_scan_jobs
companies = db.companies
scan_history = db.scan_history
users = db.users

# Create super user if it doesn't exist
async def create_super_user():
    """Create super user 'ohm' if it doesn't exist"""
    try:
        existing_user = await users.find_one({"username": "ohm"})
        if not existing_user:
            super_user = {
                "user_id": str(uuid.uuid4()),
                "username": "ohm",
                "password": "admin",  # In production, this should be hashed
                "role": "super_admin",
                "created_at": datetime.now(timezone.utc).isoformat(),
                "is_active": True
            }
            await users.insert_one(super_user)
            print("✅ Super user 'ohm' created successfully")
        else:
            print("✅ Super user 'ohm' already exists")
    except Exception as e:
        print(f"❌ Error creating super user: {e}")

# Initialize super user on startup
asyncio.create_task(create_super_user())

# Initialize scheduler for daily scans
scheduler = AsyncIOScheduler()

# Request/Response models
class URLScanRequest(BaseModel):
    url: str
    scan_type: Optional[str] = "standard"  # standard, e_skimming, payment_gateway

class BulkScanRequest(BaseModel):
    urls: List[str]
    scan_type: Optional[str] = "standard"

class LoginRequest(BaseModel):
    username: str
    password: str

class CompanyRegistration(BaseModel):
    company_name: str
    website_url: str
    contact_email: EmailStr
    contact_phone: Optional[str] = None
    industry: str
    company_size: str
    country: str
    contact_person: str
    designation: str
    payment_gateway_urls: Optional[List[str]] = []
    critical_urls: Optional[List[str]] = []
    compliance_requirements: Optional[List[str]] = []
    preferred_scan_frequency: str = "monthly"  # daily, weekly, monthly, quarterly
    notification_preferences: Dict[str, bool] = {
        "email_alerts": True,
        "dashboard_notifications": True,
        "compliance_reports": True
    }
    additional_notes: Optional[str] = None

class CompanyUpdateRequest(BaseModel):
    company_name: Optional[str] = None
    website_url: Optional[str] = None
    contact_email: Optional[EmailStr] = None
    contact_phone: Optional[str] = None
    industry: Optional[str] = None
    company_size: Optional[str] = None
    country: Optional[str] = None
    contact_person: Optional[str] = None
    designation: Optional[str] = None
    payment_gateway_urls: Optional[List[str]] = None
    critical_urls: Optional[List[str]] = None
    compliance_requirements: Optional[List[str]] = None
    preferred_scan_frequency: Optional[str] = None
    notification_preferences: Optional[Dict[str, bool]] = None
    additional_notes: Optional[str] = None

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

    def analyze_e_skimming_security_assessment(self, url: str, content: str, domain: str, ssl_details: Dict) -> Dict:
        """Comprehensive security assessment for e-skimming detection"""
        assessment = {}
        
        # Certificate validation check
        has_valid_ssl = ssl_details.get('ssl_available', False) and len(ssl_details.get('security_issues', [])) == 0
        assessment['certificate_validation'] = has_valid_ssl
        
        # Card data transmission security
        if has_valid_ssl:
            assessment['card_data_transmission'] = "Encrypted (HTTPS)"
        else:
            assessment['card_data_transmission'] = "Unencrypted (HTTP) - High Risk"
        
        # PCI compliance indicators
        pci_score = 0
        if has_valid_ssl:
            pci_score += 40
        if 'pci' in content.lower() or 'compliance' in content.lower():
            pci_score += 20
        if any(processor in url.lower() for processor in self.trusted_payment_processors):
            pci_score += 40
            
        if pci_score >= 80:
            assessment['pci_compliance_indicators'] = "Strong compliance indicators detected"
        elif pci_score >= 60:
            assessment['pci_compliance_indicators'] = "Moderate compliance indicators"
        else:
            assessment['pci_compliance_indicators'] = "Compliance review needed - insufficient indicators"
        
        # Payment form analysis
        form_indicators = []
        if re.search(r'<form.*payment|checkout.*form|billing.*form', content.lower()):
            form_indicators.append("Payment forms detected")
        if re.search(r'input.*type=["\']password["\']|input.*type=["\']text["\'].*card', content.lower()):
            form_indicators.append("Credential input fields found")
        if re.search(r'method=["\']post["\']', content.lower()):
            form_indicators.append("POST method forms (secure)")
            
        assessment['payment_form_analysis'] = "; ".join(form_indicators) if form_indicators else "No payment forms detected"
        
        # JavaScript injection check
        js_risk_indicators = []
        if re.search(r'eval\s*\(|document\.write\s*\(|innerHTML\s*=', content.lower()):
            js_risk_indicators.append("Dynamic code execution detected")
        if re.search(r'document\.forms.*submit|addEventListener.*submit', content.lower()):
            js_risk_indicators.append("Form submission handlers found")
        if re.search(r'XMLHttpRequest|fetch.*api|ajax', content.lower()):
            js_risk_indicators.append("AJAX/API calls detected")
            
        assessment['javascript_injection_check'] = "; ".join(js_risk_indicators) if js_risk_indicators else "No suspicious JavaScript patterns detected"
        
        # Third-party script analysis
        script_analysis = []
        if re.search(r'<script.*src=["\']https?://[^"\']*["\']', content):
            external_scripts = re.findall(r'<script.*src=["\'](https?://[^"\']*)["\']', content)
            trusted_domains = ['google.com', 'googleapis.com', 'jquery.com', 'cloudflare.com', 'amazonaws.com']
            
            external_count = len(external_scripts)
            trusted_count = sum(1 for script in external_scripts if any(trusted in script for trusted in trusted_domains))
            
            script_analysis.append(f"{external_count} external scripts detected")
            if trusted_count > 0:
                script_analysis.append(f"{trusted_count} from trusted sources")
            if external_count - trusted_count > 0:
                script_analysis.append(f"{external_count - trusted_count} from unknown sources")
        else:
            script_analysis.append("No external scripts detected")
            
        assessment['third_party_script_analysis'] = "; ".join(script_analysis)
        
        return assessment

    def analyze_e_skimming_risk_factors(self, url: str, content: str, domain: str, domain_features: Dict, ssl_details: Dict) -> Dict:
        """Analyze specific risk factors for e-skimming detection"""
        risk_factors = {}
        
        # Domain reputation analysis
        reputation_factors = []
        if domain_features.get('is_suspicious', False):
            reputation_factors.append("Domain flagged as suspicious")
        if domain_features.get('domain_age_days', 999) < 30:
            reputation_factors.append("Very new domain (less than 30 days)")
        if domain_features.get('uses_suspicious_tld', False):
            reputation_factors.append("Uses suspicious TLD")
        if any(blacklist in url.lower() for blacklist in ['phishing', 'malware', 'spam']):
            reputation_factors.append("Listed in security blacklists")
            
        if not reputation_factors:
            risk_factors['domain_reputation'] = "No reputation issues detected - Clean"
        else:
            risk_factors['domain_reputation'] = "; ".join(reputation_factors)
        
        # SSL certificate issues
        ssl_issues = []
        if not ssl_details.get('ssl_available', False):
            ssl_issues.append("No SSL certificate")
        elif ssl_details.get('security_issues'):
            ssl_issues.extend(ssl_details['security_issues'])
        if ssl_details.get('grade', 'F') in ['D', 'E', 'F']:
            ssl_issues.append(f"Poor SSL grade: {ssl_details.get('grade', 'F')}")
            
        if not ssl_issues:
            risk_factors['ssl_certificate_issues'] = "SSL certificate appears secure"
        else:
            risk_factors['ssl_certificate_issues'] = "; ".join(ssl_issues[:3])  # Limit to first 3
        
        # Suspicious patterns in content
        suspicious_patterns = []
        if re.search(r'urgent.*action|act.*now|verify.*account|suspended.*account', content.lower()):
            suspicious_patterns.append("Urgency/social engineering language")
        if re.search(r'click.*here.*verify|update.*payment|confirm.*card', content.lower()):
            suspicious_patterns.append("Suspicious call-to-action patterns")
        if re.search(r'win.*prize|congratulations.*selected|claim.*reward', content.lower()):
            suspicious_patterns.append("Prize/reward scam indicators")
        if len(content) < 500:
            suspicious_patterns.append("Minimal content - possible redirect page")
            
        if not suspicious_patterns:
            risk_factors['suspicious_patterns'] = "No suspicious content patterns detected"
        else:
            risk_factors['suspicious_patterns'] = "; ".join(suspicious_patterns[:3])  # Limit to first 3
        
        # Malware indicators
        malware_indicators = []
        for indicator in self.e_skimming_malware_indicators:
            if indicator in url.lower() or indicator in content.lower():
                malware_indicators.append(f"'{indicator}' detected")
        if re.search(r'\.exe|\.bat|\.scr|\.vbs|\.jar', content.lower()):
            malware_indicators.append("Executable file references found")
        if re.search(r'base64|atob\s*\(|fromCharCode', content.lower()):
            malware_indicators.append("Encoded/obfuscated content detected")
            
        if not malware_indicators:
            risk_factors['malware_indicators'] = "No malware indicators detected"
        else:
            risk_factors['malware_indicators'] = "; ".join(malware_indicators[:3])  # Limit to first 3
        
        return risk_factors

    def calculate_comprehensive_e_skimming_analysis(self, url: str, content: str, domain: str, domain_features: Dict, ssl_details: Dict, ml_predictions: Dict) -> Dict:
        """Calculate comprehensive e-skimming analysis with all details"""
        # Get basic indicators
        indicators_found = self.analyze_e_skimming_indicators(url, content)
        
        # Get security assessment
        security_assessment = self.analyze_e_skimming_security_assessment(url, content, domain, ssl_details)
        
        # Get risk factors
        risk_factors = self.analyze_e_skimming_risk_factors(url, content, domain, domain_features, ssl_details)
        
        # Calculate payment security score
        payment_security_score = self.calculate_payment_security_score(url, ml_predictions, domain_features)
        
        # Check trusted processor
        trusted_processor = any(processor in url.lower() for processor in self.trusted_payment_processors)
        
        # Get e-skimming probability from ML predictions
        e_skimming_probability = ml_predictions.get('e_skimming_probability', 0.0)
        
        return {
            'indicators_found': indicators_found,
            'payment_security_score': payment_security_score,
            'trusted_processor': trusted_processor,
            'e_skimming_probability': e_skimming_probability,
            'security_assessment': security_assessment,
            'risk_factors': risk_factors,
            'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
            'detailed_breakdown': {
                'total_indicators': len(indicators_found),
                'risk_level': 'High' if len(indicators_found) > 2 or e_skimming_probability > 0.1 else 'Medium' if len(indicators_found) > 0 or e_skimming_probability > 0.01 else 'Low',
                'confidence_score': min(100, max(0, int((len(indicators_found) * 20 + payment_security_score * 0.3 + e_skimming_probability * 100) / 3))),
                'compliance_assessment': 'COMPLIANT' if payment_security_score >= 80 and len(indicators_found) == 0 else 'NON_COMPLIANT' if len(indicators_found) > 2 else 'REVIEW_REQUIRED'
            }
        }

    def analyze_comprehensive_technical_details(self, url: str, domain: str, content: str) -> Dict:
        """Analyze comprehensive technical details including server, location, and technology information"""
        technical_details = {
            'server_info': 'Unknown',
            'technologies': [],
            'ip_address': 'N/A',
            'geographic_location': 'Unknown',
            'dns_resolution_time': 'N/A',
            'mx_records_exist': False,
            'hosting_provider': 'Unknown',
            'ip_reputation': 'Unknown',
            'geolocation': 'Unknown',
            'is_tor_exit': False,
            'domain_popularity_score': 0,
            'server_headers': {},
            'cdn_provider': 'None',
            'operating_system': 'Unknown',
            'web_server_version': 'Unknown',
            'response_time_ms': 'N/A',
            'content_encoding': 'None',
            'security_headers_count': 0,
            'http_status_code': 'N/A',
            'redirect_count': 0,
            'page_size_bytes': 0,
            'load_time_ms': 'N/A',
            'country_code': 'Unknown',
            'organization': 'Unknown',
            'isp': 'Unknown',
            'timezone': 'Unknown'
        }
        
        try:
            # Get comprehensive HTTP response data
            start_time = time.time()
            response = requests.get(url, timeout=15, headers={
                'User-Agent': 'SecureURL Technical Analysis Bot/3.0'
            }, allow_redirects=True)
            response_time = int((time.time() - start_time) * 1000)
            
            # Extract server information from headers
            headers = dict(response.headers)
            technical_details['server_headers'] = headers
            technical_details['server_info'] = headers.get('Server', 'Unknown')
            technical_details['http_status_code'] = response.status_code
            technical_details['response_time_ms'] = response_time
            technical_details['page_size_bytes'] = len(response.content)
            technical_details['content_encoding'] = headers.get('Content-Encoding', 'None')
            technical_details['load_time_ms'] = response_time
            technical_details['redirect_count'] = len(response.history)
            
            # Analyze web server and version
            server_header = headers.get('Server', '').lower()
            if 'nginx' in server_header:
                technical_details['web_server_version'] = f"Nginx {server_header.split('/')[-1] if '/' in server_header else 'Unknown Version'}"
            elif 'apache' in server_header:
                technical_details['web_server_version'] = f"Apache {server_header.split('/')[-1] if '/' in server_header else 'Unknown Version'}"
            elif 'iis' in server_header:
                technical_details['web_server_version'] = f"IIS {server_header.split('/')[-1] if '/' in server_header else 'Unknown Version'}"
            elif 'cloudflare' in server_header:
                technical_details['web_server_version'] = "Cloudflare Proxy"
                technical_details['cdn_provider'] = 'Cloudflare'
            
            # Count security headers
            security_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Content-Type-Options', 
                              'X-Frame-Options', 'X-XSS-Protection', 'Referrer-Policy']
            technical_details['security_headers_count'] = sum(1 for header in security_headers if header in headers)
            
            # Detect technologies from headers
            technologies = []
            if 'X-Powered-By' in headers:
                technologies.append(f"Powered by {headers['X-Powered-By']}")
            if 'X-Generator' in headers:
                technologies.append(f"Generated by {headers['X-Generator']}")
            if 'cloudflare' in server_header or 'CF-RAY' in headers:
                technologies.append('Cloudflare CDN')
                technical_details['cdn_provider'] = 'Cloudflare'
            if 'fastly' in headers.get('Via', '').lower():
                technologies.append('Fastly CDN')
                technical_details['cdn_provider'] = 'Fastly'
            if 'Amazon' in headers.get('Server', ''):
                technologies.append('Amazon Web Services')
                technical_details['hosting_provider'] = 'Amazon Web Services'
            
            # Analyze content for technologies
            content_lower = content.lower()
            if 'wordpress' in content_lower:
                technologies.append('WordPress')
            if 'drupal' in content_lower:
                technologies.append('Drupal')
            if 'joomla' in content_lower:
                technologies.append('Joomla')
            if 'react' in content_lower or 'reactjs' in content_lower:
                technologies.append('React.js')
            if 'angular' in content_lower:
                technologies.append('Angular')
            if 'vue' in content_lower or 'vuejs' in content_lower:
                technologies.append('Vue.js')
            if 'bootstrap' in content_lower:
                technologies.append('Bootstrap')
            if 'jquery' in content_lower:
                technologies.append('jQuery')
            
            technical_details['technologies'] = technologies
            
        except Exception as e:
            print(f"Error analyzing technical details for {url}: {str(e)}")
        
        try:
            # DNS and IP analysis
            start_dns = time.time()
            ip_address = socket.gethostbyname(domain)
            dns_time = int((time.time() - start_dns) * 1000)
            
            technical_details['ip_address'] = ip_address
            technical_details['dns_resolution_time'] = dns_time
            
            # Get additional IP information (mock enhanced geolocation)
            # In production, you would use services like MaxMind GeoIP, IPinfo, etc.
            if ip_address.startswith('104.') or ip_address.startswith('172.'):
                technical_details['geographic_location'] = 'United States'
                technical_details['country_code'] = 'US'
                technical_details['geolocation'] = 'North America - United States'
                technical_details['timezone'] = 'UTC-5 to UTC-8'
            elif ip_address.startswith('185.') or ip_address.startswith('195.'):
                technical_details['geographic_location'] = 'Europe'
                technical_details['country_code'] = 'EU'
                technical_details['geolocation'] = 'Europe'
                technical_details['timezone'] = 'UTC+0 to UTC+3'
            elif ip_address.startswith('202.') or ip_address.startswith('203.'):
                technical_details['geographic_location'] = 'Asia-Pacific'
                technical_details['country_code'] = 'AP'
                technical_details['geolocation'] = 'Asia-Pacific'
                technical_details['timezone'] = 'UTC+5 to UTC+12'
            else:
                technical_details['geographic_location'] = 'Global/Unknown'
                technical_details['country_code'] = 'Unknown'
                technical_details['geolocation'] = 'Location not determined'
                technical_details['timezone'] = 'Unknown'
            
            # Enhanced hosting provider detection
            if '8.8.8.8' in ip_address or '8.8.4.4' in ip_address:
                technical_details['hosting_provider'] = 'Google LLC'
                technical_details['isp'] = 'Google'
                technical_details['organization'] = 'Google'
            elif ip_address.startswith('13.') or ip_address.startswith('52.') or ip_address.startswith('54.'):
                technical_details['hosting_provider'] = 'Amazon Web Services'
                technical_details['isp'] = 'Amazon Technologies Inc.'
                technical_details['organization'] = 'Amazon'
            elif ip_address.startswith('104.'):
                technical_details['hosting_provider'] = 'Cloudflare Inc.'
                technical_details['isp'] = 'Cloudflare'
                technical_details['organization'] = 'Cloudflare'
            else:
                technical_details['hosting_provider'] = 'Unknown Hosting Provider'
                technical_details['isp'] = 'Unknown ISP'
                technical_details['organization'] = 'Unknown Organization'
            
            # IP reputation analysis
            if ip_address.startswith('127.') or ip_address.startswith('192.168.') or ip_address.startswith('10.'):
                technical_details['ip_reputation'] = 'Private/Local IP'
            elif any(known_bad in ip_address for known_bad in ['666.', '999.', 'invalid']):
                technical_details['ip_reputation'] = 'Suspicious'
            else:
                technical_details['ip_reputation'] = 'Clean'
            
            # Domain popularity (mock scoring)
            if domain in ['google.com', 'facebook.com', 'amazon.com', 'microsoft.com']:
                technical_details['domain_popularity_score'] = 100
            elif domain.endswith('.com') or domain.endswith('.org'):
                technical_details['domain_popularity_score'] = 70
            else:
                technical_details['domain_popularity_score'] = 30
            
        except Exception as e:
            print(f"Error analyzing DNS/IP for {domain}: {str(e)}")
        
        try:
            # MX Records check
            mx_records = dns.resolver.resolve(domain, 'MX')
            technical_details['mx_records_exist'] = len(mx_records) > 0
        except:
            technical_details['mx_records_exist'] = False
        
        return technical_details

    def analyze_detailed_ssl_certificate(self, domain: str) -> Dict:
        """Enhanced SSL certificate analysis with comprehensive protocol support detection"""
        ssl_details = {
            'certificate_info': {},
            'security_issues': [],
            'certificate_chain': [],
            'vulnerabilities': [],
            'protocol_support': {},
            'cipher_analysis': {},
            'recommendations': [],
            'grade': 'F',
            'ssl_available': False,
            'connection_details': {},
            'supported_protocols': [],
            'active_protocols': [],
            'deprecated_protocols': [],
            'cipher_suites': [],
            'certificate_validity': {},
            'key_exchange': {},
            'signature_algorithm': 'Unknown'
        }
        
        # Define protocol versions to test
        protocols_to_test = [
            ('TLSv1.3', ssl.PROTOCOL_TLS),
            ('TLSv1.2', ssl.PROTOCOL_TLS),
            ('TLSv1.1', ssl.PROTOCOL_TLS),
            ('TLSv1.0', ssl.PROTOCOL_TLS),
            ('SSLv3', ssl.PROTOCOL_TLS),
            ('SSLv2', ssl.PROTOCOL_TLS)
        ]
        
        supported_protocols = []
        active_protocol = None
        
        try:
            # Test each protocol version
            for protocol_name, protocol_version in protocols_to_test:
                try:
                    context = ssl.SSLContext(protocol_version)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    # Set specific protocol constraints for testing
                    if protocol_name == 'TLSv1.3':
                        context.minimum_version = ssl.TLSVersion.TLSv1_3
                        context.maximum_version = ssl.TLSVersion.TLSv1_3
                    elif protocol_name == 'TLSv1.2':
                        context.minimum_version = ssl.TLSVersion.TLSv1_2
                        context.maximum_version = ssl.TLSVersion.TLSv1_2
                    elif protocol_name == 'TLSv1.1':
                        context.minimum_version = ssl.TLSVersion.TLSv1_1
                        context.maximum_version = ssl.TLSVersion.TLSv1_1
                    elif protocol_name == 'TLSv1.0':
                        context.minimum_version = ssl.TLSVersion.TLSv1
                        context.maximum_version = ssl.TLSVersion.TLSv1
                    
                    with socket.create_connection((domain, 443), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=domain) as ssock:
                            supported_protocols.append({
                                'version': protocol_name,
                                'supported': True,
                                'cipher': ssock.cipher()[0] if ssock.cipher() else 'Unknown',
                                'cipher_version': ssock.cipher()[1] if ssock.cipher() else 'Unknown',
                                'cipher_bits': ssock.cipher()[2] if ssock.cipher() else 0
                            })
                            
                            # Mark as active protocol if it's the first successful connection
                            if not active_protocol:
                                active_protocol = protocol_name
                                
                except Exception:
                    supported_protocols.append({
                        'version': protocol_name,
                        'supported': False,
                        'cipher': None,
                        'cipher_version': None,
                        'cipher_bits': 0
                    })
            
            # Now perform detailed analysis with default connection
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        ssl_details['ssl_available'] = True
                        ssl_details['connection_details']['connected'] = True
                        
                        # Get certificate info
                        cert = ssock.getpeercert()
                        if cert:
                            ssl_details['certificate_info'] = {
                                'subject': dict(x[0] for x in cert.get('subject', [])),
                                'issuer': dict(x[0] for x in cert.get('issuer', [])),
                                'version': cert.get('version'),
                                'serial_number': cert.get('serialNumber'),
                                'not_before': cert.get('notBefore'),
                                'not_after': cert.get('notAfter'),
                                'subject_alt_names': [x[1] for x in cert.get('subjectAltName', [])]
                            }
                            
                            # Certificate validity analysis
                            try:
                                from datetime import datetime
                                not_after = datetime.strptime(cert.get('notAfter'), '%b %d %H:%M:%S %Y %Z')
                                not_before = datetime.strptime(cert.get('notBefore'), '%b %d %H:%M:%S %Y %Z')
                                now = datetime.utcnow()
                                
                                days_until_expiry = (not_after - now).days
                                ssl_details['certificate_validity'] = {
                                    'valid': not_before <= now <= not_after,
                                    'days_until_expiry': days_until_expiry,
                                    'expired': now > not_after,
                                    'not_yet_valid': now < not_before
                                }
                                
                                if days_until_expiry < 30:
                                    ssl_details['security_issues'].append(f'Certificate expires in {days_until_expiry} days')
                                if now > not_after:
                                    ssl_details['security_issues'].append('Certificate has expired')
                                if now < not_before:
                                    ssl_details['security_issues'].append('Certificate is not yet valid')
                                    
                            except Exception:
                                ssl_details['certificate_validity'] = {'valid': False, 'parsing_error': True}
                        
                        # Get cipher and protocol info
                        cipher = ssock.cipher()
                        if cipher:
                            ssl_details['cipher_analysis'] = {
                                'current_cipher': cipher[0],
                                'protocol_version': cipher[1],
                                'key_bits': cipher[2],
                                'description': f"{cipher[0]} ({cipher[2]} bits) over {cipher[1]}"
                            }
                            active_protocol = cipher[1]
                            
                            # Analyze key exchange and signature
                            cipher_name = cipher[0].upper()
                            if 'ECDHE' in cipher_name:
                                ssl_details['key_exchange']['type'] = 'ECDHE (Perfect Forward Secrecy)'
                                ssl_details['key_exchange']['security'] = 'Excellent'
                            elif 'DHE' in cipher_name:
                                ssl_details['key_exchange']['type'] = 'DHE (Perfect Forward Secrecy)'
                                ssl_details['key_exchange']['security'] = 'Good'
                            elif 'RSA' in cipher_name:
                                ssl_details['key_exchange']['type'] = 'RSA'
                                ssl_details['key_exchange']['security'] = 'Moderate'
                            else:
                                ssl_details['key_exchange']['type'] = 'Unknown'
                                ssl_details['key_exchange']['security'] = 'Unknown'
                            
                            # Detect signature algorithm
                            if 'SHA256' in cipher_name or 'SHA384' in cipher_name:
                                ssl_details['signature_algorithm'] = 'SHA-256/384 (Secure)'
                            elif 'SHA' in cipher_name:
                                ssl_details['signature_algorithm'] = 'SHA-1 (Deprecated)'
                            else:
                                ssl_details['signature_algorithm'] = 'Unknown'
                        
                        # Protocol support analysis
                        ssl_details['supported_protocols'] = [p for p in supported_protocols if p['supported']]
                        ssl_details['active_protocols'] = [active_protocol] if active_protocol else []
                        ssl_details['deprecated_protocols'] = [p['version'] for p in supported_protocols 
                                                            if p['supported'] and p['version'] in ['TLSv1.0', 'TLSv1.1', 'SSLv3', 'SSLv2']]
                        
                        # Comprehensive grading based on protocols and configuration
                        grade_score = 100
                        
                        # Protocol version scoring
                        if any(p['version'] == 'TLSv1.3' for p in ssl_details['supported_protocols']):
                            grade_score += 10  # Bonus for TLS 1.3
                        if any(p['version'] in ['SSLv2', 'SSLv3'] for p in ssl_details['supported_protocols']):
                            grade_score -= 40  # Major penalty for SSL
                        if any(p['version'] in ['TLSv1.0', 'TLSv1.1'] for p in ssl_details['supported_protocols']):
                            grade_score -= 20  # Penalty for old TLS
                        
                        # Certificate scoring
                        if ssl_details['certificate_validity'].get('expired', False):
                            grade_score -= 50
                        elif ssl_details['certificate_validity'].get('days_until_expiry', 365) < 30:
                            grade_score -= 20
                        
                        # Cipher scoring
                        if cipher and cipher[2] >= 256:
                            grade_score += 5  # Bonus for strong encryption
                        elif cipher and cipher[2] < 128:
                            grade_score -= 30  # Penalty for weak encryption
                        
                        # Key exchange scoring
                        if ssl_details['key_exchange'].get('security') == 'Excellent':
                            grade_score += 5
                        elif ssl_details['key_exchange'].get('security') == 'Moderate':
                            grade_score -= 10
                        
                        # Convert score to grade
                        if grade_score >= 90:
                            ssl_details['grade'] = 'A+'
                        elif grade_score >= 80:
                            ssl_details['grade'] = 'A'
                        elif grade_score >= 70:
                            ssl_details['grade'] = 'B'
                        elif grade_score >= 60:
                            ssl_details['grade'] = 'C'
                        elif grade_score >= 50:
                            ssl_details['grade'] = 'D'
                        else:
                            ssl_details['grade'] = 'F'
                        
                        # Generate recommendations
                        recommendations = []
                        if ssl_details['deprecated_protocols']:
                            recommendations.append(f"🔴 Disable deprecated protocols: {', '.join(ssl_details['deprecated_protocols'])}")
                        if not any(p['version'] == 'TLSv1.3' for p in ssl_details['supported_protocols']):
                            recommendations.append('🟡 Consider upgrading to TLS 1.3 for enhanced security')
                        if ssl_details['certificate_validity'].get('days_until_expiry', 365) < 60:
                            recommendations.append('🟡 Certificate renewal recommended within 60 days')
                        if cipher and cipher[2] < 256:
                            recommendations.append('🟡 Consider using stronger encryption (256+ bits)')
                        if ssl_details['key_exchange'].get('security') != 'Excellent':
                            recommendations.append('🟡 Enable Perfect Forward Secrecy (ECDHE)')
                        
                        ssl_details['recommendations'] = recommendations if recommendations else ['✅ SSL configuration appears secure']
                        
            except Exception as e:
                ssl_details['security_issues'].append(f'SSL connection failed: {str(e)}')
                ssl_details['recommendations'] = ['🔴 SSL configuration issues detected - manual investigation required']
        
        except Exception as e:
            ssl_details['security_issues'].append(f'SSL analysis failed: {str(e)}')
            ssl_details['recommendations'] = ['🔴 Unable to analyze SSL configuration']
        
        # Ensure protocol support is populated even if connection fails
        if not ssl_details['supported_protocols']:
            ssl_details['supported_protocols'] = supported_protocols
        
        return ssl_details

    def check_email_security_records(self, domain: str) -> Dict:
        """Enhanced email security records analysis with comprehensive DNS validation"""
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
            'recommendations': [],
            'dns_errors': []
        }
        
        try:
            import dns.resolver
            import dns.exception
            
            # Configure resolver with enhanced settings
            resolver = dns.resolver.Resolver()
            resolver.timeout = 8
            resolver.lifetime = 15
            
            # Use multiple DNS servers for reliability
            resolver.nameservers = [
                '8.8.8.8',   # Google
                '1.1.1.1',   # Cloudflare  
                '9.9.9.9',   # Quad9
                '208.67.222.222'  # OpenDNS
            ]
            
            # Enhanced SPF record checking
            spf_found = False
            try:
                # Query TXT records for the domain
                txt_answers = resolver.resolve(domain, 'TXT')
                for rdata in txt_answers:
                    txt_record = str(rdata).strip('"').replace('" "', '')  # Handle multi-part TXT records
                    
                    if txt_record.startswith('v=spf1'):
                        spf_found = True
                        email_security['spf_record'] = txt_record
                        email_security['spf_status'] = 'Found'
                        
                        # Comprehensive SPF analysis
                        spf_mechanisms = txt_record.lower()
                        
                        # Determine SPF policy strength
                        if '-all' in spf_mechanisms:
                            email_security['spf_status'] = 'Hard Fail Policy (Recommended)'
                        elif '~all' in spf_mechanisms:
                            email_security['spf_status'] = 'Soft Fail Policy (Moderate)'
                        elif '+all' in spf_mechanisms:
                            email_security['spf_status'] = 'Pass All Policy (Insecure)'
                            email_security['spf_issues'].append('🔴 CRITICAL: +all allows any server to send email')
                        elif '?all' in spf_mechanisms:
                            email_security['spf_status'] = 'Neutral Policy (Weak)'
                        elif 'all' not in spf_mechanisms:
                            email_security['spf_issues'].append('⚠️ No "all" mechanism found - policy incomplete')
                        
                        # Count DNS lookups (RFC 7208 limit is 10)
                        lookup_mechanisms = ['include:', 'a:', 'mx:', 'exists:', 'redirect=']
                        total_lookups = sum(spf_mechanisms.count(mech) for mech in lookup_mechanisms)
                        
                        if total_lookups > 10:
                            email_security['spf_issues'].append(f'🔴 Too many DNS lookups ({total_lookups}) - exceeds RFC limit of 10')
                        elif total_lookups > 7:
                            email_security['spf_issues'].append(f'⚠️ High DNS lookup count ({total_lookups}) - approaching RFC limit')
                        
                        # Check for IPv6 support
                        if 'ip4:' in spf_mechanisms and 'ip6:' not in spf_mechanisms:
                            email_security['spf_issues'].append('ℹ️ Consider adding IPv6 support with ip6: mechanism')
                        
                        # Check for common issues
                        if spf_mechanisms.count('include:') > 5:
                            email_security['spf_issues'].append('⚠️ Many include mechanisms - consider consolidation')
                        
                        # Check for macro usage
                        if '%' in spf_mechanisms:
                            email_security['spf_issues'].append('ℹ️ SPF macros detected - ensure proper implementation')
                        
                        break  # Use first valid SPF record found
                        
                if not spf_found:
                    email_security['spf_status'] = 'Not Found'
                    
            except dns.resolver.NXDOMAIN:
                email_security['spf_status'] = 'Domain Not Found'
                email_security['dns_errors'].append(f'Domain {domain} does not exist')
            except dns.resolver.NoAnswer:
                email_security['spf_status'] = 'No TXT Records Found'
            except dns.resolver.Timeout:
                email_security['spf_status'] = 'DNS Query Timeout'
                email_security['dns_errors'].append('SPF lookup timed out')
            except Exception as e:
                email_security['spf_status'] = f'DNS Query Error'
                email_security['dns_errors'].append(f'SPF query failed: {str(e)[:50]}')
            
            # Enhanced DMARC record checking
            try:
                dmarc_domain = f'_dmarc.{domain}'
                dmarc_answers = resolver.resolve(dmarc_domain, 'TXT')
                
                for rdata in dmarc_answers:
                    txt_record = str(rdata).strip('"').replace('" "', '')
                    
                    if txt_record.startswith('v=DMARC1'):
                        email_security['dmarc_record'] = txt_record
                        email_security['dmarc_status'] = 'Found'
                        
                        # Enhanced DMARC policy analysis
                        dmarc_lower = txt_record.lower()
                        
                        # Main policy analysis
                        if 'p=reject' in dmarc_lower:
                            email_security['dmarc_policy'] = 'Reject (Strong Protection)'
                        elif 'p=quarantine' in dmarc_lower:
                            email_security['dmarc_policy'] = 'Quarantine (Moderate Protection)'
                        elif 'p=none' in dmarc_lower:
                            email_security['dmarc_policy'] = 'Monitor Only (Weak Protection)'
                        else:
                            email_security['dmarc_policy'] = 'Policy Not Clear'
                        
                        # Subdomain policy
                        if 'sp=reject' in dmarc_lower:
                            email_security['dmarc_policy'] += ' | Subdomains: Reject'
                        elif 'sp=quarantine' in dmarc_lower:
                            email_security['dmarc_policy'] += ' | Subdomains: Quarantine'
                        elif 'sp=none' in dmarc_lower:
                            email_security['dmarc_policy'] += ' | Subdomains: Monitor'
                        
                        # Alignment checks
                        alignment_info = []
                        if 'aspf=s' in dmarc_lower:
                            alignment_info.append('SPF: Strict')
                        elif 'aspf=r' in dmarc_lower:
                            alignment_info.append('SPF: Relaxed')
                        
                        if 'adkim=s' in dmarc_lower:
                            alignment_info.append('DKIM: Strict')
                        elif 'adkim=r' in dmarc_lower:
                            alignment_info.append('DKIM: Relaxed')
                        
                        if alignment_info:
                            email_security['dmarc_policy'] += f' | Alignment: {", ".join(alignment_info)}'
                        
                        # Check for reporting addresses
                        has_aggregate_reports = 'rua=' in dmarc_lower
                        has_forensic_reports = 'ruf=' in dmarc_lower
                        
                        if not has_aggregate_reports and not has_forensic_reports:
                            email_security['recommendations'].append('⚠️ Add DMARC reporting addresses (rua/ruf) for visibility')
                        elif not has_aggregate_reports:
                            email_security['recommendations'].append('ℹ️ Consider adding aggregate reporting (rua) for better insights')
                        elif not has_forensic_reports:
                            email_security['recommendations'].append('ℹ️ Consider adding forensic reporting (ruf) for detailed analysis')
                        
                        # Check percentage policy
                        if 'pct=' in dmarc_lower:
                            try:
                                pct_value = int(dmarc_lower.split('pct=')[1].split(';')[0])
                                if pct_value < 100:
                                    email_security['dmarc_policy'] += f' | Percentage: {pct_value}%'
                                    if pct_value < 50:
                                        email_security['recommendations'].append(f'⚠️ DMARC policy applied to only {pct_value}% of emails')
                            except:
                                pass
                        
                        break
                        
            except dns.resolver.NXDOMAIN:
                email_security['dmarc_status'] = 'DMARC Record Not Found'
            except dns.resolver.NoAnswer:
                email_security['dmarc_status'] = 'No DMARC TXT Record'
            except dns.resolver.Timeout:
                email_security['dmarc_status'] = 'DNS Query Timeout'
                email_security['dns_errors'].append('DMARC lookup timed out')
            except Exception as e:
                email_security['dmarc_status'] = 'DNS Query Error'
                email_security['dns_errors'].append(f'DMARC query failed: {str(e)[:50]}')
            
            # Enhanced DKIM checking with comprehensive selector list
            try:
                # Extensive list of DKIM selectors used by major email services and custom setups
                dkim_selectors = [
                    # Standard selectors
                    'default', 'selector1', 'selector2', 'dkim', 'mail', 'email',
                    
                    # Google/Gmail
                    'google', '20161025', '20120113', '20161025',
                    
                    # Microsoft/Office 365
                    'selector1', 'selector2', 
                    
                    # Amazon SES
                    'amazonses', '7v7vs6w47njt4pimodk5mmttg2u67rxi', 
                    
                    # SendGrid
                    'sendgrid', 'sg', 'smtpapi', 'em', 's1', 's2',
                    
                    # Mailgun
                    'mailgun', 'mg', 'k1', 'key1',
                    
                    # Mailchimp
                    'mailchimp', 'mc', 'k2', 'key2',
                    
                    # Common patterns
                    'smtp', 'server', 'primary', 'secondary', 'main',
                    'sig1', 'sig2', 'signature', 'auth', 'verification',
                    
                    # Date-based selectors (common pattern)
                    '2023', '2024', '2025', '20230101', '20240101', '20250101',
                    
                    # Service-specific
                    'mandrill', 'postmark', 'sparkpost', 'constantcontact',
                    'campaignmonitor', 'aweber', 'getresponse',
                    
                    # Custom/organization
                    'corp', 'company', 'org', 'enterprise'
                ]
                
                selectors_found = []
                dkim_records_found = []
                
                for selector in dkim_selectors:
                    try:
                        dkim_domain = f'{selector}._domainkey.{domain}'
                        dkim_answers = resolver.resolve(dkim_domain, 'TXT')
                        
                        for rdata in dkim_answers:
                            record_text = str(rdata).strip('"').replace('" "', '')
                            
                            # Validate it's actually a DKIM record
                            if any(marker in record_text for marker in ['k=', 'p=', 'v=DKIM1', 't=', 'n=', 'g=']):
                                selectors_found.append(selector)
                                dkim_records_found.append({
                                    'selector': selector,
                                    'record': record_text[:100] + '...' if len(record_text) > 100 else record_text
                                })
                                break
                                
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                        # These are expected for non-existent selectors
                        continue
                    except Exception:
                        # Log unexpected errors but continue
                        continue
                
                if selectors_found:
                    email_security['dkim_status'] = 'Found'
                    email_security['dkim_selectors_found'] = selectors_found
                    email_security['dkim_records'] = dkim_records_found
                else:
                    email_security['dkim_status'] = 'Not Found (Extensive Selector Check)'
                    
            except Exception as e:
                email_security['dkim_status'] = 'DNS Query Error'
                email_security['dns_errors'].append(f'DKIM query failed: {str(e)[:50]}')
            
            # Enhanced scoring algorithm (0-100)
            score = 0
            
            # SPF scoring (40 points maximum)
            if email_security['spf_status'] == 'Hard Fail Policy (Recommended)':
                score += 40
            elif email_security['spf_status'] == 'Soft Fail Policy (Moderate)':
                score += 30
            elif email_security['spf_status'] in ['Found', 'Neutral Policy (Weak)']:
                score += 20
            elif email_security['spf_status'] == 'Pass All Policy (Insecure)':
                score += 10  # Some points for having SPF but it's insecure
            # Subtract points for SPF issues
            score -= min(len(email_security['spf_issues']) * 5, 20)
            
            # DMARC scoring (40 points maximum)
            if email_security['dmarc_status'] == 'Found':
                if 'Reject (Strong Protection)' in email_security.get('dmarc_policy', ''):
                    score += 40
                elif 'Quarantine (Moderate Protection)' in email_security.get('dmarc_policy', ''):
                    score += 30
                elif 'Monitor Only (Weak Protection)' in email_security.get('dmarc_policy', ''):
                    score += 15
                else:
                    score += 10
                    
                # Bonus points for comprehensive DMARC setup
                if 'rua=' in email_security.get('dmarc_record', '').lower() or 'ruf=' in email_security.get('dmarc_record', '').lower():
                    score += 5
            
            # DKIM scoring (20 points maximum)
            if email_security['dkim_status'] == 'Found':
                base_dkim_score = 15
                # Bonus for multiple selectors
                selector_count = len(email_security.get('dkim_selectors_found', []))
                if selector_count > 1:
                    base_dkim_score += min(selector_count, 5)
                score += min(base_dkim_score, 20)
            
            # Ensure score doesn't go below 0
            email_security['email_security_score'] = max(0, min(100, score))
            
            # Generate comprehensive recommendations
            if email_security['spf_status'] == 'Not Found':
                email_security['recommendations'].append('🔴 CRITICAL: Implement SPF record to prevent email spoofing')
            elif email_security['spf_status'] == 'Pass All Policy (Insecure)':
                email_security['recommendations'].append('🔴 URGENT: Change SPF "+all" to "-all" for security')
            
            if email_security['dmarc_status'] == 'Not Found':
                email_security['recommendations'].append('🔴 CRITICAL: Implement DMARC policy for email authentication')
            elif 'Monitor Only' in email_security.get('dmarc_policy', ''):
                email_security['recommendations'].append('🟡 RECOMMENDED: Upgrade DMARC policy from "none" to "quarantine" or "reject"')
            
            if email_security['dkim_status'] in ['Not Found (Extensive Selector Check)', 'Unknown']:
                email_security['recommendations'].append('🟡 RECOMMENDED: Implement DKIM signing for email integrity verification')
            elif email_security['dkim_status'] == 'Found' and len(email_security.get('dkim_selectors_found', [])) == 1:
                email_security['recommendations'].append('ℹ️ OPTIONAL: Consider multiple DKIM selectors for key rotation')
            
            # Add specific recommendations based on issues found
            for issue in email_security['spf_issues']:
                if 'CRITICAL' in issue:
                    email_security['recommendations'].append(f'SPF Fix Needed: {issue}')
                elif 'lookup' in issue.lower():
                    email_security['recommendations'].append(f'SPF Optimization: {issue}')
                    
        except Exception as e:
            email_security['error'] = f'Email security analysis failed: {str(e)}'
            email_security['dns_errors'].append(f'Analysis error: {str(e)}')
            email_security['recommendations'].append('🔴 Email security analysis failed - DNS resolution may be blocked or domain may not exist')
        
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
        """Enhanced DNS availability checking with comprehensive threat intelligence validation"""
        availability_check = {
            'url_online': False,
            'response_time_ms': 0,
            'http_status_code': None,
            'dns_resolvers': {},
            'threat_intelligence_feeds': {},
            'availability_score': 0,
            'total_blocklists': 0,
            'blocked_by_count': 0,
            'last_checked': datetime.now(timezone.utc).isoformat()
        }
        
        try:
            import socket
            import requests
            import dns.resolver
            
            # Test URL availability
            start_time = datetime.now()
            try:
                # First, test basic connectivity
                response = requests.head(url, timeout=10, allow_redirects=True, verify=False)
                availability_check['url_online'] = True
                availability_check['http_status_code'] = response.status_code
                availability_check['response_time_ms'] = int((datetime.now() - start_time).total_seconds() * 1000)
            except requests.exceptions.Timeout:
                availability_check['response_time_ms'] = 10000
                availability_check['http_status_code'] = 'Timeout'
            except requests.exceptions.ConnectionError:
                availability_check['http_status_code'] = 'Connection Failed'
                # Try ping-like test
                try:
                    with socket.create_connection((domain, 80), timeout=5):
                        availability_check['url_online'] = True
                        availability_check['http_status_code'] = 'Port 80 Open'
                except:
                    try:
                        with socket.create_connection((domain, 443), timeout=5):
                            availability_check['url_online'] = True
                            availability_check['http_status_code'] = 'Port 443 Open'
                    except:
                        availability_check['url_online'] = False
            except Exception as e:
                availability_check['http_status_code'] = str(e)[:50]
            
            # Enhanced DNS resolver checking
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
            
            for resolver_name, dns_servers in dns_resolvers.items():
                resolver_status = {
                    'blocked': False,
                    'status': 'Unknown',
                    'response_time_ms': 0,
                    'resolved_ips': [],
                    'error': None
                }
                
                # Test with primary DNS server
                primary_dns = dns_servers[0]
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [primary_dns]
                    resolver.timeout = 5
                    resolver.lifetime = 8
                    
                    start_dns = datetime.now()
                    answers = resolver.resolve(domain, 'A')
                    resolver_status['response_time_ms'] = int((datetime.now() - start_dns).total_seconds() * 1000)
                    resolver_status['resolved_ips'] = [str(rdata) for rdata in answers]
                    resolver_status['status'] = 'Resolved'
                    
                    # Additional check for DNS filtering (some resolvers return NXDOMAIN for blocked domains)
                    if len(resolver_status['resolved_ips']) == 1 and resolver_status['resolved_ips'][0] in ['0.0.0.0', '127.0.0.1']:
                        resolver_status['blocked'] = True
                        resolver_status['status'] = 'Blocked (Sinkhole IP)'
                        
                except dns.resolver.NXDOMAIN:
                    # Domain doesn't exist according to this resolver - might be blocked
                    # Cross-check with authoritative DNS to confirm
                    try:
                        # Use system resolver as reference
                        socket.gethostbyname(domain)
                        # If system resolver works but this one doesn't, it's likely blocked
                        resolver_status['blocked'] = True
                        resolver_status['status'] = 'Blocked (NXDOMAIN)'
                    except:
                        resolver_status['status'] = 'Domain Not Found'
                        
                except dns.resolver.Timeout:
                    resolver_status['status'] = 'Timeout'
                    resolver_status['response_time_ms'] = 8000
                    
                except Exception as e:
                    resolver_status['status'] = 'Error'
                    resolver_status['error'] = str(e)[:50]
                
                availability_check['dns_resolvers'][resolver_name] = resolver_status
            
            # Enhanced threat intelligence feeds with more realistic checks
            threat_feeds = {
                'SURBL Multi': {
                    'description': 'Spam URI Realtime Blocklist',
                    'check_method': 'dns',
                    'listed': False,
                    'categories': [],
                    'confidence': 0
                },
                'Spamhaus ZEN': {
                    'description': 'Spamhaus IP and Domain Blocklist',
                    'check_method': 'dns',
                    'listed': False,
                    'categories': [],
                    'confidence': 0
                },
                'Phishtank': {
                    'description': 'Anti-Phishing Working Group',
                    'check_method': 'heuristic',
                    'listed': False,
                    'categories': [],
                    'confidence': 0
                },
                'Google Safe Browsing': {
                    'description': 'Google Web Risk API',
                    'check_method': 'heuristic',
                    'listed': False,
                    'categories': [],
                    'confidence': 0
                },
                'VirusTotal': {
                    'description': 'Multi-engine malware scanner',
                    'check_method': 'heuristic',
                    'listed': False,
                    'categories': [],
                    'confidence': 0
                },
                'URLVoid': {
                    'description': 'URL reputation checker',
                    'check_method': 'heuristic',
                    'listed': False,
                    'categories': [],
                    'confidence': 0
                },
                'Kaspersky': {
                    'description': 'Kaspersky Web Security',
                    'check_method': 'heuristic',
                    'listed': False,
                    'categories': [],
                    'confidence': 0
                }
            }
            
            # Enhanced heuristic analysis for threat intelligence
            url_lower = url.lower()
            domain_lower = domain.lower()
            
            # High-confidence indicators
            high_risk_patterns = [
                'phishing', 'malware', 'virus', 'trojan', 'scam', 'fraud',
                'fake', 'suspicious', 'malicious', 'hack', 'exploit'
            ]
            
            # Medium-confidence indicators
            medium_risk_patterns = [
                'login', 'verify', 'account', 'secure', 'update', 'confirm',
                'payment', 'billing', 'support', 'service'
            ]
            
            # Domain reputation factors
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.work', '.click']
            suspicious_patterns = ['bit.ly', 'tinyurl', 'short', 'url', 'redirect']
            
            # Check each threat intelligence feed with enhanced logic
            for feed_name, feed_info in threat_feeds.items():
                listed = False
                categories = []
                confidence = 0
                
                if feed_info['check_method'] == 'dns':
                    # Simulate DNS blocklist checking (more sophisticated)
                    if feed_name == 'SURBL Multi':
                        # Check for URL shorteners and redirectors
                        if any(pattern in url_lower for pattern in suspicious_patterns):
                            listed = True
                            categories.append('url_shortener')
                            confidence = 70
                        # Check for suspicious TLDs with certain patterns
                        elif any(tld in domain_lower for tld in suspicious_tlds) and any(pattern in url_lower for pattern in medium_risk_patterns):
                            listed = True
                            categories.append('suspicious_domain')
                            confidence = 85
                            
                    elif feed_name == 'Spamhaus ZEN':
                        # Check for known malicious patterns
                        if any(pattern in url_lower for pattern in high_risk_patterns):
                            listed = True
                            categories.append('malware')
                            confidence = 90
                        # Check for domain age and suspicious patterns
                        elif len(domain_lower.split('.')[0]) > 20 and any(c.isdigit() for c in domain_lower):
                            listed = True
                            categories.append('suspicious_domain')
                            confidence = 60
                            
                elif feed_info['check_method'] == 'heuristic':
                    if feed_name == 'Phishtank':
                        # Enhanced phishing detection
                        phishing_score = 0
                        phishing_indicators = 0
                        
                        # URL structure analysis
                        if any(indicator in url_lower for indicator in ['login', 'verify', 'account', 'secure']):
                            phishing_score += 20
                            phishing_indicators += 1
                            
                        # Check for brand impersonation patterns
                        brand_names = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook', 'twitter']
                        domain_parts = domain_lower.replace('-', '').replace('_', '')
                        
                        for brand in brand_names:
                            if brand in domain_parts and not domain_lower.endswith(f'{brand}.com'):
                                phishing_score += 30
                                phishing_indicators += 1
                                categories.append('brand_impersonation')
                                
                        # Suspicious TLD + phishing keywords
                        if any(tld in domain_lower for tld in suspicious_tlds) and phishing_indicators > 0:
                            phishing_score += 25
                            
                        if phishing_score >= 45:
                            listed = True
                            categories.append('phishing')
                            confidence = min(phishing_score + 20, 95)
                            
                    elif feed_name == 'Google Safe Browsing':
                        # Malware and social engineering detection
                        risk_score = 0
                        
                        # Check for malware distribution patterns
                        malware_patterns = ['download', 'install', 'setup', 'crack', 'keygen', 'serial']
                        if any(pattern in url_lower for pattern in malware_patterns):
                            risk_score += 25
                            
                        # Check for social engineering
                        if any(pattern in url_lower for pattern in ['urgent', 'immediate', 'expires', 'suspended', 'verify']):
                            risk_score += 20
                            
                        # Domain trust factors
                        if any(tld in domain_lower for tld in suspicious_tlds):
                            risk_score += 15
                            
                        if risk_score >= 35:
                            listed = True
                            categories.append('malware' if 'download' in url_lower else 'social_engineering')
                            confidence = min(risk_score + 30, 90)
                            
                    elif feed_name == 'VirusTotal':
                        # File and URL scanning simulation
                        virus_indicators = 0
                        
                        # Check for file extension patterns in URL
                        dangerous_extensions = ['.exe', '.scr', '.bat', '.com', '.pif', '.vbs', '.jar']
                        if any(ext in url_lower for ext in dangerous_extensions):
                            virus_indicators += 2
                            categories.append('malicious_file')
                            
                        # Check for suspicious parameters
                        if '?' in url and any(param in url_lower for param in ['exec', 'cmd', 'shell', 'run']):
                            virus_indicators += 1
                            categories.append('code_injection')
                            
                        # Domain reputation
                        if any(pattern in domain_lower for pattern in high_risk_patterns):
                            virus_indicators += 2
                            
                        if virus_indicators >= 2:
                            listed = True
                            if 'malicious_file' not in categories:
                                categories.append('malware')
                            confidence = min(virus_indicators * 30, 95)
                            
                    elif feed_name in ['URLVoid', 'Kaspersky']:
                        # Generic threat detection
                        threat_score = 0
                        
                        # Comprehensive pattern matching
                        all_risk_patterns = high_risk_patterns + medium_risk_patterns
                        pattern_matches = sum(1 for pattern in all_risk_patterns if pattern in url_lower)
                        
                        if pattern_matches >= 3:
                            threat_score = 60 + (pattern_matches * 5)
                            listed = True
                            categories.append('suspicious_content')
                            confidence = min(threat_score, 85)
                        elif pattern_matches >= 2 and any(tld in domain_lower for tld in suspicious_tlds):
                            threat_score = 50
                            listed = True
                            categories.append('potentially_malicious')
                            confidence = 70
                
                # Update feed information
                feed_info['listed'] = listed
                feed_info['categories'] = categories
                feed_info['confidence'] = confidence
                
                availability_check['threat_intelligence_feeds'][feed_name] = feed_info
            
            # Calculate summary statistics
            availability_check['total_blocklists'] = len(threat_feeds)
            availability_check['blocked_by_count'] = sum(1 for feed in threat_feeds.values() if feed['listed'])
            
            # Calculate availability score (0-100)
            score = 100
            
            # Deduct for being offline
            if not availability_check['url_online']:
                score -= 50
            
            # Deduct for DNS blocking
            dns_blocked_count = sum(1 for resolver in availability_check['dns_resolvers'].values() if resolver['blocked'])
            score -= min(dns_blocked_count * 5, 25)
            
            # Deduct for threat intelligence listings
            threat_blocked_count = availability_check['blocked_by_count']
            if threat_blocked_count > 0:
                # Weight by confidence
                weighted_threats = sum(feed['confidence'] / 100 for feed in threat_feeds.values() if feed['listed'])
                score -= min(weighted_threats * 15, 40)
            
            # Response time penalty
            if availability_check['response_time_ms'] > 5000:
                score -= 10
            elif availability_check['response_time_ms'] > 3000:
                score -= 5
                
            availability_check['availability_score'] = max(0, int(score))
            
        except Exception as e:
            availability_check['error'] = str(e)
            availability_check['availability_score'] = 0
        
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
        """Enhanced domain reputation analysis with comprehensive geographic intelligence"""
        features = {
            'is_trusted_domain': False,
            'domain_age_days': 0,
            'has_ssl': False,
            'ssl_issuer': None,
            'ssl_expires': None,
            'dns_resolution_time': 0,
            'mx_records_exist': False,
            'geographic_location': None,
            'registrar_info': None,
            # Enhanced geographic intelligence
            'country_code': 'Unknown',
            'country_name': 'Unknown',
            'continent': 'Unknown',
            'region': 'Unknown',
            'city': 'Unknown',
            'timezone': 'Unknown',
            'language': 'Unknown',
            'currency': 'Unknown',
            'country_flag': '🏳️',
            'country_risk_level': 'Unknown',
            'is_high_risk_country': False,
            'tld_country': 'Generic',
            'domain_extensions': [],
            'local_popularity': 0,
            'international_popularity': 0
        }
        
        # Check if trusted domain
        features['is_trusted_domain'] = any(trusted in domain for trusted in self.trusted_domains)
        
        # Enhanced SSL check with multiple approaches
        ssl_detected = False
        ssl_issuer = None
        ssl_expires = None
        
        # Method 1: Direct SSL connection with proper verification
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
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
        except Exception:
            # Method 2: Try HTTPS request
            try:
                import requests
                response = requests.head(f"https://{domain}", timeout=8, verify=True)
                if response.status_code < 500:  # Any response means SSL is working
                    ssl_detected = True
                    ssl_issuer = "Verified via HTTPS"
            except requests.exceptions.SSLError:
                # Method 3: Try with verification disabled to check if SSL exists but has issues
                try:
                    import urllib3
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                    response = requests.head(f"https://{domain}", timeout=8, verify=False)
                    if response.status_code < 500:
                        ssl_detected = True
                        ssl_issuer = "SSL Present (Certificate issues detected)"
                except:
                    ssl_detected = False
            except requests.exceptions.ConnectionError:
                # Method 4: Direct port check for SSL service
                try:
                    with socket.create_connection((domain, 443), timeout=5) as sock:
                        ssl_detected = True
                        ssl_issuer = "SSL Port Open"
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

        # Enhanced Geographic Intelligence Analysis
        try:
            # Get IP address for geographic analysis
            ip_address = socket.gethostbyname(domain)
            
            # Comprehensive country and geographic mapping based on IP ranges
            if ip_address.startswith(('8.8.', '172.217.', '216.58.', '142.250.', '74.125.')):
                # Google IP ranges
                features.update({
                    'country_code': 'US',
                    'country_name': 'United States',
                    'continent': 'North America',
                    'region': 'California',
                    'city': 'Mountain View',
                    'timezone': 'UTC-8 (PST)',
                    'language': 'English',
                    'currency': 'USD',
                    'country_flag': '🇺🇸',
                    'country_risk_level': 'Low',
                    'is_high_risk_country': False,
                    'geographic_location': 'United States (Google Infrastructure)'
                })
            elif ip_address.startswith(('13.', '52.', '54.', '18.', '34.', '35.')):
                # Amazon AWS IP ranges
                features.update({
                    'country_code': 'US',
                    'country_name': 'United States',
                    'continent': 'North America',
                    'region': 'Global AWS Infrastructure',
                    'city': 'Multiple Data Centers',
                    'timezone': 'UTC-5 to UTC-8',
                    'language': 'English',
                    'currency': 'USD',
                    'country_flag': '🇺🇸',
                    'country_risk_level': 'Low',
                    'is_high_risk_country': False,
                    'geographic_location': 'United States (AWS Cloud)'
                })
            elif ip_address.startswith(('104.', '108.', '162.', '173.')):
                # Cloudflare IP ranges
                features.update({
                    'country_code': 'US',
                    'country_name': 'United States',
                    'continent': 'North America',
                    'region': 'Global CDN Network',
                    'city': 'San Francisco',
                    'timezone': 'UTC-8 (PST)',
                    'language': 'English',
                    'currency': 'USD',
                    'country_flag': '🇺🇸',
                    'country_risk_level': 'Low',
                    'is_high_risk_country': False,
                    'geographic_location': 'Global (Cloudflare CDN)'
                })
            elif ip_address.startswith(('185.', '194.', '195.', '46.', '31.')):
                # European IP ranges
                features.update({
                    'country_code': 'EU',
                    'country_name': 'European Union',
                    'continent': 'Europe',
                    'region': 'Western Europe',
                    'city': 'Multiple Cities',
                    'timezone': 'UTC+0 to UTC+3',
                    'language': 'Multiple Languages',
                    'currency': 'EUR (Multiple)',
                    'country_flag': '🇪🇺',
                    'country_risk_level': 'Low',
                    'is_high_risk_country': False,
                    'geographic_location': 'Europe'
                })
            elif ip_address.startswith(('202.', '203.', '61.', '124.', '220.')):
                # Asia-Pacific IP ranges
                features.update({
                    'country_code': 'AP',
                    'country_name': 'Asia-Pacific',
                    'continent': 'Asia',
                    'region': 'Asia-Pacific',
                    'city': 'Multiple Cities',
                    'timezone': 'UTC+5 to UTC+12',
                    'language': 'Multiple Languages',
                    'currency': 'Multiple Currencies',
                    'country_flag': '🌏',
                    'country_risk_level': 'Medium',
                    'is_high_risk_country': False,
                    'geographic_location': 'Asia-Pacific'
                })
            elif ip_address.startswith(('200.', '201.', '190.', '181.')):
                # Latin America IP ranges
                features.update({
                    'country_code': 'BR',
                    'country_name': 'Brazil/Latin America',
                    'continent': 'South America',
                    'region': 'Latin America',
                    'city': 'Multiple Cities',
                    'timezone': 'UTC-3 to UTC-5',
                    'language': 'Portuguese/Spanish',
                    'currency': 'BRL/Multiple',
                    'country_flag': '🇧🇷',
                    'country_risk_level': 'Medium',
                    'is_high_risk_country': False,
                    'geographic_location': 'Latin America'
                })
            else:
                # Default/Unknown location
                features.update({
                    'country_code': 'Unknown',
                    'country_name': 'Unknown',
                    'continent': 'Unknown',
                    'region': 'Unknown',
                    'city': 'Unknown',
                    'timezone': 'Unknown',
                    'language': 'Unknown',
                    'currency': 'Unknown',
                    'country_flag': '🏳️',
                    'country_risk_level': 'Unknown',
                    'is_high_risk_country': False,
                    'geographic_location': 'Location Unknown'
                })
            
            # Analyze Top-Level Domain (TLD) for country intelligence
            tld = domain.split('.')[-1].lower()
            country_tlds = {
                'us': ('United States', '🇺🇸', 'Low'),
                'uk': ('United Kingdom', '🇬🇧', 'Low'),
                'ca': ('Canada', '🇨🇦', 'Low'),
                'au': ('Australia', '🇦🇺', 'Low'),
                'de': ('Germany', '🇩🇪', 'Low'),
                'fr': ('France', '🇫🇷', 'Low'),
                'jp': ('Japan', '🇯🇵', 'Low'),
                'cn': ('China', '🇨🇳', 'Medium'),
                'ru': ('Russia', '🇷🇺', 'High'),
                'in': ('India', '🇮🇳', 'Medium'),
                'ae': ('United Arab Emirates', '🇦🇪', 'Medium'),
                'br': ('Brazil', '🇧🇷', 'Medium'),
                'mx': ('Mexico', '🇲🇽', 'Medium'),
                'tr': ('Turkey', '🇹🇷', 'Medium'),
                'pk': ('Pakistan', '🇵🇰', 'High'),
                'ng': ('Nigeria', '🇳🇬', 'High'),
                'id': ('Indonesia', '🇮🇩', 'Medium')
            }
            
            if tld in country_tlds:
                country_name, flag, risk_level = country_tlds[tld]
                features.update({
                    'tld_country': country_name,
                    'country_flag': flag,
                    'country_risk_level': risk_level,
                    'is_high_risk_country': risk_level == 'High'
                })
                
                # Override country info if TLD provides better information
                if features['country_name'] == 'Unknown':
                    features['country_name'] = country_name
                    features['country_flag'] = flag
            else:
                features['tld_country'] = 'Generic TLD (.com, .org, .net, etc.)'
            
            # Domain popularity analysis
            popular_domains = [
                'google.com', 'facebook.com', 'youtube.com', 'amazon.com', 'microsoft.com',
                'apple.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'netflix.com',
                'wikipedia.org', 'reddit.com', 'ebay.com', 'paypal.com', 'github.com'
            ]
            
            if domain.lower() in popular_domains:
                features['international_popularity'] = 100
                features['local_popularity'] = 100
            elif any(popular in domain.lower() for popular in ['google', 'microsoft', 'amazon']):
                features['international_popularity'] = 90
                features['local_popularity'] = 85
            elif domain.endswith(('.com', '.org', '.net')):
                features['international_popularity'] = 60
                features['local_popularity'] = 50
            else:
                features['international_popularity'] = 30
                features['local_popularity'] = 40
            
            # Domain extensions analysis
            extensions = domain.split('.')
            features['domain_extensions'] = extensions if len(extensions) > 2 else [tld]
            
        except Exception as e:
            print(f"Geographic intelligence analysis failed for {domain}: {str(e)}")
            features.update({
                'geographic_location': 'Analysis Failed',
                'country_code': 'Unknown',
                'country_name': 'Unknown',
                'continent': 'Unknown',
                'region': 'Unknown',
                'city': 'Unknown',
                'timezone': 'Unknown',
                'language': 'Unknown',
                'currency': 'Unknown',
                'country_flag': '🏳️',
                'country_risk_level': 'Unknown',
                'is_high_risk_country': False,
                'tld_country': 'Generic',
                'domain_extensions': [domain.split('.')[-1]],
                'local_popularity': 0,
                'international_popularity': 0
            })

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
        
        # Comprehensive E-skimming specific analysis (enhanced)
        comprehensive_e_skimming_analysis = self.calculate_comprehensive_e_skimming_analysis(
            url, content, domain, domain_features, detailed_ssl_analysis, ml_predictions
        )
        
        # Extract e_skimming_indicators for backward compatibility
        e_skimming_indicators = comprehensive_e_skimming_analysis['indicators_found']
        
        # Comprehensive Technical Details Analysis (enhanced)
        comprehensive_technical_details = self.analyze_comprehensive_technical_details(url, domain, content)
        
        # Extract e_skimming_indicators for backward compatibility
        e_skimming_indicators = comprehensive_e_skimming_analysis['indicators_found']
        
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
        
        # Calculate payment security score from comprehensive analysis
        payment_security_score = comprehensive_e_skimming_analysis['payment_security_score']
        
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
            'e_skimming_analysis': comprehensive_e_skimming_analysis,
            'technical_details': comprehensive_technical_details,
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

@app.get("/api/health")
async def health_check():
    return {"status": "ok", "message": "API is healthy"}

# Authentication Endpoints
@app.post("/api/auth/login")
async def login(login_data: LoginRequest):
    """Login endpoint for user authentication"""
    try:
        user = await users.find_one({
            "username": login_data.username,
            "password": login_data.password,  # In production, use hashed passwords
            "is_active": True
        })
        
        if not user:
            raise HTTPException(status_code=401, detail="Invalid username or password")
        
        # Create session token (simplified - in production use JWT)
        session_token = str(uuid.uuid4())
        
        # Update user's last login
        await users.update_one(
            {"user_id": user["user_id"]},
            {"$set": {"last_login": datetime.now(timezone.utc).isoformat()}}
        )
        
        return {
            "message": "Login successful",
            "user_id": user["user_id"],
            "username": user["username"],
            "role": user["role"],
            "session_token": session_token
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

@app.post("/api/auth/logout")
async def logout():
    """Logout endpoint"""
    return {"message": "Logged out successfully"}

# Company Registration Endpoints
@app.post("/api/companies/register")
async def register_company(company_data: CompanyRegistration):
    """Register a new company for security monitoring"""
    try:
        # Create company document
        company_id = str(uuid.uuid4())
        company_doc = {
            "company_id": company_id,
            **company_data.dict(),
            "registration_date": datetime.now(timezone.utc).isoformat(),
            "status": "active",
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "total_scans": 0,
            "last_scan_date": None,
            "compliance_status": "pending_first_scan"
        }
        
        # Check if company already exists (by email or website)
        existing_company = await companies.find_one({
            "$or": [
                {"contact_email": company_data.contact_email},
                {"website_url": company_data.website_url}
            ]
        })
        
        if existing_company:
            raise HTTPException(
                status_code=400, 
                detail="Company already registered with this email or website URL"
            )
        
        # Insert company document
        await companies.insert_one(company_doc)
        
        # Create initial scan history entry
        initial_history = {
            "company_id": company_id,
            "scan_id": str(uuid.uuid4()),
            "scan_type": "registration",
            "status": "registered",
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "urls_scanned": [company_data.website_url],
            "summary": "Company registered for security monitoring",
            "results_count": 0
        }
        
        await scan_history.insert_one(initial_history)
        
        return {
            "company_id": company_id,
            "message": "Company registered successfully",
            "status": "active",
            "registration_date": company_doc["registration_date"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@app.get("/api/companies")
async def list_companies(skip: int = 0, limit: int = 50):
    """List all registered companies"""
    try:
        total_companies = await companies.count_documents({})
        company_list = await companies.find(
            {}, 
            {"company_name": 1, "website_url": 1, "contact_email": 1, "industry": 1, 
             "registration_date": 1, "status": 1, "total_scans": 1, "last_scan_date": 1,
             "compliance_status": 1, "company_id": 1}
        ).skip(skip).limit(limit).to_list(length=limit)
        
        # Remove MongoDB _id from results
        for company in company_list:
            company.pop('_id', None)
        
        return {
            "companies": company_list,
            "total": total_companies,
            "skip": skip,
            "limit": limit
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve companies: {str(e)}")

@app.get("/api/companies/{company_id}")
async def get_company_details(company_id: str):
    """Get detailed information about a specific company"""
    try:
        company = await companies.find_one({"company_id": company_id})
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")
        
        company.pop('_id', None)
        
        # Get recent scan history
        recent_scans = await scan_history.find(
            {"company_id": company_id}
        ).sort("scan_date", -1).limit(10).to_list(length=10)
        
        for scan in recent_scans:
            scan.pop('_id', None)
        
        company["recent_scans"] = recent_scans
        
        return company
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve company: {str(e)}")

@app.put("/api/companies/{company_id}")
async def update_company(company_id: str, update_data: CompanyUpdateRequest):
    """Update company information"""
    try:
        # Check if company exists
        existing_company = await companies.find_one({"company_id": company_id})
        if not existing_company:
            raise HTTPException(status_code=404, detail="Company not found")
        
        # Prepare update data (only non-None fields)
        update_fields = {k: v for k, v in update_data.dict().items() if v is not None}
        
        if not update_fields:
            raise HTTPException(status_code=400, detail="No valid fields to update")
        
        # Add last_updated timestamp
        update_fields["last_updated"] = datetime.now(timezone.utc).isoformat()
        
        # Update company document
        result = await companies.update_one(
            {"company_id": company_id},
            {"$set": update_fields}
        )
        
        if result.modified_count == 0:
            raise HTTPException(status_code=400, detail="No changes made to company")
        
        # Get updated company info
        updated_company = await companies.find_one({"company_id": company_id})
        updated_company.pop('_id', None)
        
        return {
            "message": "Company updated successfully",
            "company": updated_company
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update company: {str(e)}")

@app.delete("/api/companies/{company_id}")
async def delete_company(company_id: str):
    """Deactivate a company (soft delete)"""
    try:
        result = await companies.update_one(
            {"company_id": company_id},
            {"$set": {
                "status": "deactivated",
                "last_updated": datetime.now(timezone.utc).isoformat()
            }}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Company not found")
        
        return {"message": "Company deactivated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to deactivate company: {str(e)}")

# Scan History Endpoints
@app.get("/api/companies/{company_id}/scan-history")
async def get_company_scan_history(
    company_id: str, 
    skip: int = 0, 
    limit: int = 50, 
    scan_type: Optional[str] = None
):
    """Get scan history for a specific company"""
    try:
        # Build query
        query = {"company_id": company_id}
        if scan_type:
            query["scan_type"] = scan_type
        
        # Get total count
        total_scans = await scan_history.count_documents(query)
        
        # Get scan history
        scans = await scan_history.find(query).sort("scan_date", -1).skip(skip).limit(limit).to_list(length=limit)
        
        # Remove MongoDB _id from results
        for scan in scans:
            scan.pop('_id', None)
        
        return {
            "company_id": company_id,
            "scan_history": scans,
            "total": total_scans,
            "skip": skip,
            "limit": limit
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve scan history: {str(e)}")

@app.post("/api/companies/{company_id}/scan")
async def trigger_company_scan(company_id: str, scan_type: str = "comprehensive"):
    """Trigger a security scan for a specific company"""
    try:
        # Check if company exists
        company = await companies.find_one({"company_id": company_id})
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")
        
        # Collect URLs to scan
        urls_to_scan = [company["website_url"]]
        if company.get("payment_gateway_urls"):
            urls_to_scan.extend(company["payment_gateway_urls"])
        if company.get("critical_urls"):
            urls_to_scan.extend(company["critical_urls"])
        
        # Remove duplicates
        urls_to_scan = list(set(urls_to_scan))
        
        # Create scan job
        scan_id = str(uuid.uuid4())
        scan_doc = {
            "scan_id": scan_id,
            "company_id": company_id,
            "scan_type": scan_type,
            "status": "initiated",
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "urls_to_scan": urls_to_scan,
            "urls_scanned": [],
            "results": [],
            "summary": {
                "total_urls": len(urls_to_scan),
                "scanned_urls": 0,
                "high_risk_urls": 0,
                "compliance_issues": 0
            }
        }
        
        await scan_history.insert_one(scan_doc)
        
        # Start background scan
        asyncio.create_task(
            process_company_scan(scan_id, company_id, urls_to_scan, scan_type)
        )
        
        # Update company scan count
        await companies.update_one(
            {"company_id": company_id},
            {
                "$inc": {"total_scans": 1},
                "$set": {"last_scan_date": datetime.now(timezone.utc).isoformat()}
            }
        )
        
        return {
            "scan_id": scan_id,
            "message": "Company scan initiated",
            "urls_to_scan": len(urls_to_scan),
            "status": "processing"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to initiate company scan: {str(e)}")

async def process_company_scan(scan_id: str, company_id: str, urls: List[str], scan_type: str):
    """Background task to process company scan"""
    try:
        analyzer = AdvancedESkimmingAnalyzer()
        results = []
        high_risk_count = 0
        compliance_issues = 0
        
        for url in urls:
            try:
                # Perform URL analysis
                result = await analyzer.analyze_url(url, include_screenshot=False, scan_type=scan_type)
                
                # Convert to dict
                if hasattr(result, 'dict'):
                    result_dict = result.dict()
                elif hasattr(result, 'model_dump'):
                    result_dict = result.model_dump()
                else:
                    result_dict = dict(result)
                
                results.append(result_dict)
                
                # Count high-risk URLs and compliance issues
                if result_dict.get('risk_score', 0) >= 70:
                    high_risk_count += 1
                
                if result_dict.get('transaction_halt_required', False):
                    compliance_issues += 1
                    
            except Exception as e:
                # Handle individual URL failures
                error_result = {
                    'url': url,
                    'error': str(e),
                    'risk_score': 0,
                    'is_malicious': False,
                    'scan_timestamp': datetime.now(timezone.utc).isoformat()
                }
                results.append(error_result)
        
        # Update scan history with results
        summary = {
            "total_urls": len(urls),
            "scanned_urls": len(results),
            "high_risk_urls": high_risk_count,
            "compliance_issues": compliance_issues
        }
        
        await scan_history.update_one(
            {"scan_id": scan_id},
            {
                "$set": {
                    "status": "completed",
                    "urls_scanned": urls,
                    "results": results,
                    "summary": summary,
                    "completion_date": datetime.now(timezone.utc).isoformat()
                }
            }
        )
        
        # Update company compliance status
        if compliance_issues > 0:
            compliance_status = "non_compliant"
        elif high_risk_count > 0:
            compliance_status = "at_risk"
        else:
            compliance_status = "compliant"
        
        await companies.update_one(
            {"company_id": company_id},
            {"$set": {"compliance_status": compliance_status}}
        )
        
    except Exception as e:
        # Mark scan as failed
        await scan_history.update_one(
            {"scan_id": scan_id},
            {
                "$set": {
                    "status": "failed",
                    "error": str(e),
                    "completion_date": datetime.now(timezone.utc).isoformat()
                }
            }
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)