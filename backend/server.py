from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
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
from datetime import datetime, timezone
from typing import Dict, List, Optional
import asyncio
import whois
from urllib.parse import urlparse
import dns.resolver
import uuid

# Initialize FastAPI app
app = FastAPI(title="Malicious URL Detection API", version="1.0.0")

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

# Request/Response models
class URLScanRequest(BaseModel):
    url: str

class ThreatAnalysis(BaseModel):
    risk_score: int
    threat_category: str
    is_malicious: bool
    analysis_details: Dict
    recommendations: List[str]
    scan_timestamp: str
    scan_id: str

class URLAnalyzer:
    def __init__(self):
        # Malicious keywords and patterns
        self.phishing_keywords = [
            'login', 'secure', 'account', 'verify', 'update', 'confirm',
            'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook',
            'bank', 'credit', 'card', 'suspended', 'limited', 'urgent'
        ]
        
        self.malware_indicators = [
            '.exe', '.scr', '.bat', '.com', '.pif', '.vbs', '.jar',
            'download', 'install', 'setup', 'crack', 'keygen', 'patch'
        ]
        
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.men', '.xyz', '.top', '.work',
            '.click', '.download', '.bid', '.win', '.accountant'
        ]
        
        self.trusted_domains = [
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'twitter.com', 'github.com', 'stackoverflow.com'
        ]

    def analyze_lexical_features(self, url: str) -> Dict:
        """Analyze lexical features of the URL"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
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
        
        return features

    def analyze_content_features(self, url: str) -> Dict:
        """Analyze content and behavioral features"""
        features = {
            'phishing_keywords': 0,
            'malware_indicators': 0,
            'url_shortener': False,
            'homograph_attack': False
        }
        
        url_lower = url.lower()
        
        # Count phishing keywords
        features['phishing_keywords'] = sum(1 for keyword in self.phishing_keywords if keyword in url_lower)
        
        # Count malware indicators
        features['malware_indicators'] = sum(1 for indicator in self.malware_indicators if indicator in url_lower)
        
        # Check for URL shorteners
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'short.ly']
        features['url_shortener'] = any(shortener in url_lower for shortener in shorteners)
        
        # Basic homograph detection
        suspicious_chars = ['а', 'о', 'р', 'с', 'е', 'х']  # Cyrillic lookalikes
        features['homograph_attack'] = any(char in url for char in suspicious_chars)
        
        return features

    def analyze_domain_reputation(self, domain: str) -> Dict:
        """Analyze domain reputation and DNS features"""
        features = {
            'is_trusted_domain': False,
            'domain_age_days': 0,
            'has_ssl': False,
            'dns_resolution_time': 0,
            'mx_records_exist': False
        }
        
        # Check if trusted domain
        features['is_trusted_domain'] = any(trusted in domain for trusted in self.trusted_domains)
        
        try:
            # Check SSL certificate
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    features['has_ssl'] = True
        except:
            features['has_ssl'] = False
        
        try:
            # Check MX records
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
        
        return features

    def calculate_risk_score(self, lexical_features: Dict, content_features: Dict, domain_features: Dict) -> int:
        """Calculate overall risk score (0-100)"""
        score = 0
        
        # Lexical scoring
        if lexical_features['url_length'] > 100:
            score += 15
        elif lexical_features['url_length'] > 50:
            score += 8
        
        if lexical_features['subdomain_count'] > 3:
            score += 20
        elif lexical_features['subdomain_count'] > 1:
            score += 10
        
        if lexical_features['has_ip_address']:
            score += 25
        
        if lexical_features['has_suspicious_tld']:
            score += 20
        
        if lexical_features['suspicious_chars'] > 5:
            score += 15
        
        # Content scoring
        score += min(content_features['phishing_keywords'] * 8, 40)
        score += min(content_features['malware_indicators'] * 10, 30)
        
        if content_features['url_shortener']:
            score += 15
        
        if content_features['homograph_attack']:
            score += 30
        
        # Domain reputation scoring
        if domain_features['is_trusted_domain']:
            score = max(0, score - 50)
        
        if not domain_features['has_ssl']:
            score += 20
        
        if not domain_features['mx_records_exist']:
            score += 10
        
        if domain_features['dns_resolution_time'] > 5000:
            score += 15
        
        return min(100, max(0, score))

    def categorize_threat(self, score: int, content_features: Dict, lexical_features: Dict) -> str:
        """Categorize the type of threat"""
        if content_features['phishing_keywords'] > 2:
            return "Phishing"
        elif content_features['malware_indicators'] > 1:
            return "Malware"
        elif score > 70:
            return "High Risk"
        elif score > 40:
            return "Suspicious"
        else:
            return "Low Risk"

    async def analyze_url(self, url: str) -> ThreatAnalysis:
        """Main analysis function"""
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
        
        # Run analysis
        lexical_features = self.analyze_lexical_features(url)
        content_features = self.analyze_content_features(url)
        domain_features = self.analyze_domain_reputation(domain)
        
        # Calculate risk score
        risk_score = self.calculate_risk_score(lexical_features, content_features, domain_features)
        
        # Categorize threat
        threat_category = self.categorize_threat(risk_score, content_features, lexical_features)
        
        # Generate recommendations
        recommendations = self.generate_recommendations(risk_score, content_features, lexical_features, domain_features)
        
        # Create analysis details
        analysis_details = {
            'lexical_analysis': lexical_features,
            'content_analysis': content_features,
            'domain_analysis': domain_features,
            'threat_indicators': self.get_threat_indicators(content_features, lexical_features, domain_features)
        }
        
        # Store in database
        scan_result = {
            'scan_id': scan_id,
            'url': url,
            'risk_score': risk_score,
            'threat_category': threat_category,
            'is_malicious': risk_score > 60,
            'analysis_details': analysis_details,
            'recommendations': recommendations,
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
            scan_id=scan_id
        )

    def generate_recommendations(self, risk_score: int, content_features: Dict, lexical_features: Dict, domain_features: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if risk_score > 80:
            recommendations.append("🚨 HIGH RISK: Do not visit this URL")
            recommendations.append("Block this URL in your firewall/security software")
        elif risk_score > 60:
            recommendations.append("⚠️ CAUTION: Proceed with extreme caution")
            recommendations.append("Use a secure browser with anti-phishing protection")
        elif risk_score > 40:
            recommendations.append("⚡ MODERATE RISK: Be cautious when visiting")
            recommendations.append("Verify the URL authenticity before entering sensitive information")
        else:
            recommendations.append("✅ LOW RISK: Appears to be safe")
        
        if content_features['phishing_keywords'] > 2:
            recommendations.append("Contains multiple phishing-related keywords")
        
        if lexical_features['has_ip_address']:
            recommendations.append("Uses IP address instead of domain name - suspicious")
        
        if not domain_features['has_ssl']:
            recommendations.append("No SSL certificate - data transmission not secure")
        
        if content_features['url_shortener']:
            recommendations.append("URL shortener detected - destination unclear")
        
        return recommendations

    def get_threat_indicators(self, content_features: Dict, lexical_features: Dict, domain_features: Dict) -> List[str]:
        """Get specific threat indicators found"""
        indicators = []
        
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
        
        return indicators

# Initialize analyzer
analyzer = URLAnalyzer()

@app.get("/")
async def root():
    return {"message": "Malicious URL Detection API", "version": "1.0.0", "status": "active"}

@app.post("/api/scan", response_model=ThreatAnalysis)
async def scan_url(request: URLScanRequest):
    """Scan a URL for malicious content"""
    try:
        result = await analyzer.analyze_url(request.url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/api/scan/{scan_id}")
async def get_scan_result(scan_id: str):
    """Get scan result by ID"""
    result = await db.scan_results.find_one({"scan_id": scan_id})
    if not result:
        raise HTTPException(status_code=404, detail="Scan result not found")
    
    # Remove MongoDB _id field
    result.pop('_id', None)
    return result

@app.get("/api/stats")
async def get_stats():
    """Get scanning statistics"""
    total_scans = await db.scan_results.count_documents({})
    malicious_count = await db.scan_results.count_documents({"is_malicious": True})
    
    # Get recent scans
    recent_scans = []
    async for scan in db.scan_results.find().sort("scan_timestamp", -1).limit(10):
        scan.pop('_id', None)
        recent_scans.append(scan)
    
    return {
        "total_scans": total_scans,
        "malicious_urls_detected": malicious_count,
        "safe_urls": total_scans - malicious_count,
        "detection_rate": round((malicious_count / total_scans * 100), 2) if total_scans > 0 else 0,
        "recent_scans": recent_scans
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)