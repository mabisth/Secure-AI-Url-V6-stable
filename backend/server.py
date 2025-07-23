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

class AdvancedURLAnalyzer:
    def __init__(self):
        # Enhanced threat patterns (initialize first)
        self.phishing_keywords = [
            'login', 'secure', 'account', 'verify', 'update', 'confirm',
            'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
            'bank', 'credit', 'card', 'suspended', 'limited', 'urgent',
            'signin', 'authentication', 'validation', 'renewal', 'expires'
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
            'linkedin.com', 'youtube.com', 'wikipedia.org'
        ]
        
        # Advanced patterns for ML detection
        self.phishing_patterns = [
            r'(?:login|signin|account).*(?:verify|update|confirm)',
            r'(?:secure|safety).*(?:alert|warning|notice)',
            r'(?:paypal|amazon|microsoft|apple|google).*(?:security|payment)',
            r'(?:suspended|limited|blocked).*account',
            r'click.*(?:here|link|verify|confirm)',
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

    def _get_ml_predictions(self, url: str) -> Dict:
        """Get predictions from ML models"""
        features = np.array([self._extract_ml_features(url)])
        
        try:
            phishing_prob = self.phishing_model.predict_proba(features)[0][1]
            malware_prob = self.malware_model.predict_proba(features)[0][1]
            
            # TF-IDF analysis
            tfidf_features = self.tfidf_vectorizer.transform([url])
            tfidf_score = tfidf_features.sum()
            
            return {
                'phishing_probability': float(phishing_prob),
                'malware_probability': float(malware_prob),
                'content_similarity_score': float(tfidf_score),
                'ensemble_score': float((phishing_prob + malware_prob) / 2)
            }
        except Exception as e:
            return {
                'phishing_probability': 0.5,
                'malware_probability': 0.5,
                'content_similarity_score': 0.0,
                'ensemble_score': 0.5,
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
        """Enhanced domain reputation analysis"""
        features = {
            'is_trusted_domain': False,
            'domain_age_days': 0,
            'has_ssl': False,
            'dns_resolution_time': 0,
            'mx_records_exist': False,
            'geographic_location': None,
            'registrar_info': None
        }
        
        # Check if trusted domain
        features['is_trusted_domain'] = any(trusted in domain for trusted in self.trusted_domains)
        
        # SSL check
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    features['has_ssl'] = True
                    cert = ssock.getpeercert()
                    features['ssl_issuer'] = cert.get('issuer', [{}])[0].get('organizationName', 'Unknown')
        except:
            features['has_ssl'] = False

        # DNS checks
        try:
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

    def categorize_threat(self, score: int, content_features: Dict, ml_predictions: Dict) -> str:
        """Enhanced threat categorization"""
        phishing_prob = ml_predictions.get('phishing_probability', 0)
        malware_prob = ml_predictions.get('malware_probability', 0)
        
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

    async def analyze_url(self, url: str, include_screenshot: bool = True) -> ThreatAnalysis:
        """Enhanced URL analysis with ML and screenshot analysis"""
        scan_id = str(uuid.uuid4())
        
        # Parse URL
        try:
            parsed = urlparse(url)
            if not parsed.scheme:
                url = f"http://{url}"
                parsed = urlparse(url)
            domain = parsed.netloc
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid URL format: {str(e)}")
        
        # Run enhanced analysis
        lexical_features = self.analyze_lexical_features(url)
        content_features = self.analyze_content_features(url)
        domain_features = self.analyze_domain_reputation(domain)
        ml_predictions = self._get_ml_predictions(url)
        
        # Screenshot analysis (optional for performance)
        screenshot_analysis = None
        if include_screenshot:
            screenshot_analysis = await self._take_screenshot(url)
        
        # Calculate enhanced risk score
        risk_score = self.calculate_risk_score(lexical_features, content_features, domain_features, ml_predictions)
        
        # Categorize threat
        threat_category = self.categorize_threat(risk_score, content_features, ml_predictions)
        
        # Campaign detection
        analysis_details = {
            'lexical_analysis': lexical_features,
            'content_analysis': content_features,
            'domain_analysis': domain_features,
            'threat_indicators': self.get_threat_indicators(content_features, lexical_features, domain_features, ml_predictions)
        }
        
        campaign_info = self._detect_campaign(url, analysis_details)
        
        # Generate recommendations
        recommendations = self.generate_recommendations(risk_score, content_features, lexical_features, domain_features, ml_predictions)
        
        # Store in database
        scan_result = {
            'scan_id': scan_id,
            'url': url,
            'risk_score': risk_score,
            'threat_category': threat_category,
            'is_malicious': risk_score > 60,
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

    async def bulk_analyze_urls(self, urls: List[str], job_id: str) -> None:
        """Bulk URL analysis with progress tracking"""
        total_urls = len(urls)
        results = []
        
        # Create job record
        job_record = {
            'job_id': job_id,
            'total_urls': total_urls,
            'processed_urls': 0,
            'status': 'processing',
            'results': [],
            'created_at': datetime.now(timezone.utc).isoformat()
        }
        await db.bulk_scan_jobs.insert_one(job_record)
        
        # Process URLs
        for i, url in enumerate(urls):
            try:
                result = await self.analyze_url(url, include_screenshot=False)  # Skip screenshots for bulk processing
                results.append(result.dict())
                
                # Update progress
                await db.bulk_scan_jobs.update_one(
                    {'job_id': job_id},
                    {'$set': {'processed_urls': i + 1, 'results': results}}
                )
                
            except Exception as e:
                # Handle individual URL failures
                results.append({
                    'url': url,
                    'error': str(e),
                    'risk_score': 0,
                    'scan_timestamp': datetime.now(timezone.utc).isoformat()
                })
        
        # Mark job as complete
        await db.bulk_scan_jobs.update_one(
            {'job_id': job_id},
            {'$set': {'status': 'completed', 'results': results}}
        )

    def generate_recommendations(self, risk_score: int, content_features: Dict, lexical_features: Dict, domain_features: Dict, ml_predictions: Dict) -> List[str]:
        """Enhanced recommendations with ML insights"""
        recommendations = []
        
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

    def get_threat_indicators(self, content_features: Dict, lexical_features: Dict, domain_features: Dict, ml_predictions: Dict) -> List[str]:
        """Enhanced threat indicators with ML insights"""
        indicators = []
        
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
analyzer = AdvancedURLAnalyzer()

# Bulk scan jobs storage
bulk_scan_jobs = {}

@app.get("/")
async def root():
    return {"message": "Advanced Malicious URL Detection API", "version": "2.0.0", "status": "active", "features": ["ML Analysis", "Screenshot OCR", "Bulk Scanning", "Campaign Detection"]}

@app.post("/api/scan", response_model=ThreatAnalysis)
async def scan_url(request: URLScanRequest):
    """Enhanced URL scanning with ML analysis"""
    try:
        result = await analyzer.analyze_url(request.url, include_screenshot=True)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/api/scan/bulk")
async def bulk_scan_urls(request: BulkScanRequest):
    """Start bulk URL scanning job"""
    job_id = str(uuid.uuid4())
    
    # Start background task
    asyncio.create_task(analyzer.bulk_analyze_urls(request.urls, job_id))
    
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
async def upload_bulk_scan_file(file: UploadFile = File(...)):
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
        
        # Start bulk scan
        job_id = str(uuid.uuid4())
        asyncio.create_task(analyzer.bulk_analyze_urls(urls, job_id))
        
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)