#!/usr/bin/env python3

import requests
import json
import sys

def test_suspicious_url():
    """Test DNS availability with suspicious URL patterns"""
    base_url = "https://643588f0-ae8a-4b2f-a5b7-cae8af3974d3.preview.emergentagent.com"
    
    # Test URLs that should trigger different threat intelligence feeds
    test_cases = [
        {
            "name": "Phishing Pattern",
            "url": "https://fake-phish-login.suspicious-site.tk"
        },
        {
            "name": "Malware Pattern", 
            "url": "https://evil-malware-botnet.malicious-domain.ml"
        },
        {
            "name": "Spam Pattern",
            "url": "https://spam-bulk-sender.suspicious-site.ml"
        }
    ]
    
    for test_case in test_cases:
        print(f"\n🔍 Testing {test_case['name']}: {test_case['url']}")
        
        try:
            response = requests.post(
                f"{base_url}/api/scan",
                json={"url": test_case["url"], "scan_type": "standard"},
                headers={'Content-Type': 'application/json'},
                timeout=60
            )
            
            if response.status_code == 200:
                data = response.json()
                analysis_details = data.get('analysis_details', {})
                detailed_report = analysis_details.get('detailed_report', {})
                dns_availability = detailed_report.get('dns_availability_check', {})
                
                if dns_availability:
                    url_online = dns_availability.get('url_online')
                    availability_score = dns_availability.get('availability_score')
                    threat_feeds = dns_availability.get('threat_intelligence_feeds', {})
                    
                    print(f"  URL Online: {url_online}")
                    print(f"  Availability Score: {availability_score}/100")
                    
                    # Check which threat feeds listed this URL
                    listed_feeds = []
                    for feed_name, feed_data in threat_feeds.items():
                        if feed_data.get('listed', False):
                            categories = feed_data.get('categories', [])
                            listed_feeds.append(f"{feed_name} ({', '.join(categories)})")
                    
                    if listed_feeds:
                        print(f"  ⚠️ Listed in threat feeds: {', '.join(listed_feeds)}")
                    else:
                        print(f"  ✅ Not listed in any threat feeds")
                    
                    # Show DNS resolver blocking
                    dns_resolvers = dns_availability.get('dns_resolvers', {})
                    blocked_resolvers = [name for name, data in dns_resolvers.items() if data.get('blocked', False)]
                    
                    if blocked_resolvers:
                        print(f"  🚫 Blocked by DNS resolvers: {', '.join(blocked_resolvers)}")
                    else:
                        print(f"  ✅ Not blocked by DNS resolvers")
                        
                else:
                    print("  ❌ No DNS availability data")
            else:
                print(f"  ❌ API request failed: {response.status_code}")
                
        except Exception as e:
            print(f"  ❌ Error: {str(e)}")

if __name__ == "__main__":
    test_suspicious_url()