#!/usr/bin/env python3

import requests
import json
import sys
from datetime import datetime

def test_dns_availability():
    """Focused test for DNS availability checking"""
    base_url = "https://643588f0-ae8a-4b2f-a5b7-cae8af3974d3.preview.emergentagent.com"
    
    print("🌐 Testing DNS & Availability Checking...")
    
    # Test with Google (should work)
    test_url = "https://google.com"
    
    try:
        response = requests.post(
            f"{base_url}/api/scan",
            json={"url": test_url, "scan_type": "standard"},
            headers={'Content-Type': 'application/json'},
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            
            # Check if DNS availability data is present
            analysis_details = data.get('analysis_details', {})
            detailed_report = analysis_details.get('detailed_report', {})
            dns_availability = detailed_report.get('dns_availability_check', {})
            
            if dns_availability:
                print("✅ DNS availability check found in response")
                
                # Check key fields
                url_online = dns_availability.get('url_online')
                response_time_ms = dns_availability.get('response_time_ms')
                http_status_code = dns_availability.get('http_status_code')
                dns_resolvers = dns_availability.get('dns_resolvers', {})
                threat_feeds = dns_availability.get('threat_intelligence_feeds', {})
                availability_score = dns_availability.get('availability_score')
                
                print(f"  URL Online: {url_online}")
                print(f"  Response Time: {response_time_ms}ms")
                print(f"  HTTP Status: {http_status_code}")
                print(f"  DNS Resolvers tested: {len(dns_resolvers)}")
                print(f"  Threat feeds checked: {len(threat_feeds)}")
                print(f"  Availability Score: {availability_score}/100")
                
                # Show some DNS resolver results
                if dns_resolvers:
                    print("\n  DNS Resolver Results:")
                    for resolver_name, resolver_data in list(dns_resolvers.items())[:5]:
                        status = resolver_data.get('status', 'Unknown')
                        blocked = resolver_data.get('blocked', False)
                        print(f"    {resolver_name}: {status} (Blocked: {blocked})")
                
                # Show some threat feed results
                if threat_feeds:
                    print("\n  Threat Intelligence Results:")
                    for feed_name, feed_data in list(threat_feeds.items())[:5]:
                        status = feed_data.get('status', 'Unknown')
                        listed = feed_data.get('listed', False)
                        print(f"    {feed_name}: {status} (Listed: {listed})")
                
                return True
            else:
                print("❌ DNS availability check NOT found in response")
                print("Available detailed report sections:", list(detailed_report.keys()))
                return False
        else:
            print(f"❌ API request failed with status {response.status_code}")
            print(f"Response: {response.text[:200]}")
            return False
            
    except Exception as e:
        print(f"❌ Test failed with error: {str(e)}")
        return False

if __name__ == "__main__":
    success = test_dns_availability()
    sys.exit(0 if success else 1)