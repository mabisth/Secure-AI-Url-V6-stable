#!/usr/bin/env python3
"""
Comprehensive Backend API Testing for Malicious URL Detection Platform
Tests all API endpoints with various URL types and edge cases
"""

import requests
import sys
import json
from datetime import datetime
from typing import Dict, List

class URLSecurityAPITester:
    def __init__(self, base_url="https://a5121a2e-4dcd-4999-9f62-27d72917efae.preview.emergentagent.com"):
        self.base_url = base_url
        self.tests_run = 0
        self.tests_passed = 0
        self.scan_ids = []  # Store scan IDs for later retrieval tests

    def log_test(self, name: str, success: bool, details: str = ""):
        """Log test results"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name}: PASSED {details}")
        else:
            print(f"❌ {name}: FAILED {details}")
        return success

    def test_root_endpoint(self):
        """Test the root endpoint"""
        try:
            response = requests.get(f"{self.base_url}/", timeout=10)
            success = response.status_code == 200
            if success:
                data = response.json()
                expected_keys = ["message", "version", "status"]
                has_keys = all(key in data for key in expected_keys)
                return self.log_test("Root Endpoint", has_keys, f"- Status: {response.status_code}, Data: {data}")
            else:
                return self.log_test("Root Endpoint", False, f"- Status: {response.status_code}")
        except Exception as e:
            return self.log_test("Root Endpoint", False, f"- Error: {str(e)}")

    def test_stats_endpoint(self):
        """Test the statistics endpoint"""
        try:
            response = requests.get(f"{self.base_url}/api/stats", timeout=10)
            success = response.status_code == 200
            if success:
                data = response.json()
                expected_keys = ["total_scans", "malicious_urls_detected", "safe_urls", "detection_rate", "recent_scans"]
                has_keys = all(key in data for key in expected_keys)
                return self.log_test("Stats Endpoint", has_keys, f"- Total scans: {data.get('total_scans', 'N/A')}")
            else:
                return self.log_test("Stats Endpoint", False, f"- Status: {response.status_code}")
        except Exception as e:
            return self.log_test("Stats Endpoint", False, f"- Error: {str(e)}")

    def test_url_scan(self, url: str, test_name: str, expected_risk_range: tuple = None):
        """Test URL scanning with specific URL"""
        try:
            payload = {"url": url}
            response = requests.post(
                f"{self.base_url}/api/scan", 
                json=payload, 
                headers={"Content-Type": "application/json"},
                timeout=30
            )
            
            success = response.status_code == 200
            if success:
                data = response.json()
                required_fields = ["risk_score", "threat_category", "is_malicious", "analysis_details", "recommendations", "scan_timestamp", "scan_id"]
                has_fields = all(field in data for field in required_fields)
                
                if has_fields:
                    # Store scan ID for later retrieval test
                    self.scan_ids.append(data["scan_id"])
                    
                    risk_score = data["risk_score"]
                    threat_category = data["threat_category"]
                    is_malicious = data["is_malicious"]
                    
                    # Check if risk score is in expected range
                    risk_in_range = True
                    if expected_risk_range:
                        risk_in_range = expected_risk_range[0] <= risk_score <= expected_risk_range[1]
                    
                    details = f"- Risk: {risk_score}/100, Category: {threat_category}, Malicious: {is_malicious}"
                    return self.log_test(f"Scan URL ({test_name})", has_fields and risk_in_range, details)
                else:
                    return self.log_test(f"Scan URL ({test_name})", False, f"- Missing required fields")
            else:
                error_detail = ""
                try:
                    error_data = response.json()
                    error_detail = error_data.get("detail", "Unknown error")
                except:
                    error_detail = response.text
                return self.log_test(f"Scan URL ({test_name})", False, f"- Status: {response.status_code}, Error: {error_detail}")
        except Exception as e:
            return self.log_test(f"Scan URL ({test_name})", False, f"- Error: {str(e)}")

    def test_scan_retrieval(self, scan_id: str):
        """Test retrieving scan results by ID"""
        try:
            response = requests.get(f"{self.base_url}/api/scan/{scan_id}", timeout=10)
            success = response.status_code == 200
            if success:
                data = response.json()
                has_scan_id = data.get("scan_id") == scan_id
                return self.log_test("Scan Retrieval", has_scan_id, f"- Retrieved scan: {scan_id}")
            else:
                return self.log_test("Scan Retrieval", False, f"- Status: {response.status_code}")
        except Exception as e:
            return self.log_test("Scan Retrieval", False, f"- Error: {str(e)}")

    def test_invalid_scan_retrieval(self):
        """Test retrieving non-existent scan"""
        try:
            fake_id = "non-existent-scan-id"
            response = requests.get(f"{self.base_url}/api/scan/{fake_id}", timeout=10)
            success = response.status_code == 404
            return self.log_test("Invalid Scan Retrieval", success, f"- Status: {response.status_code}")
        except Exception as e:
            return self.log_test("Invalid Scan Retrieval", False, f"- Error: {str(e)}")

    def test_malformed_url_scan(self):
        """Test scanning with malformed URLs"""
        malformed_urls = [
            "",  # Empty URL
            "not-a-url",  # Invalid format
            "ftp://invalid-protocol.com",  # Unsupported protocol
            "http://",  # Incomplete URL
        ]
        
        for url in malformed_urls:
            try:
                payload = {"url": url}
                response = requests.post(
                    f"{self.base_url}/api/scan", 
                    json=payload, 
                    headers={"Content-Type": "application/json"},
                    timeout=10
                )
                
                # Should either handle gracefully or return appropriate error
                if response.status_code in [200, 400]:
                    self.log_test(f"Malformed URL ({url or 'empty'})", True, f"- Status: {response.status_code}")
                else:
                    self.log_test(f"Malformed URL ({url or 'empty'})", False, f"- Status: {response.status_code}")
            except Exception as e:
                self.log_test(f"Malformed URL ({url or 'empty'})", False, f"- Error: {str(e)}")

    def run_comprehensive_tests(self):
        """Run all tests"""
        print("🚀 Starting Comprehensive API Testing for Malicious URL Detection Platform")
        print("=" * 80)
        
        # Test basic endpoints
        print("\n📡 Testing Basic Endpoints:")
        self.test_root_endpoint()
        self.test_stats_endpoint()
        
        # Test URL scanning with different types of URLs
        print("\n🔍 Testing URL Scanning:")
        
        # Safe URLs (should have low risk scores)
        self.test_url_scan("https://google.com", "Safe URL - Google", (0, 30))
        self.test_url_scan("https://github.com", "Safe URL - GitHub", (0, 30))
        self.test_url_scan("https://stackoverflow.com", "Safe URL - StackOverflow", (0, 30))
        
        # Suspicious URLs (should have moderate risk scores)
        self.test_url_scan("http://bit.ly/test", "Suspicious URL - URL Shortener", (20, 80))
        self.test_url_scan("http://192.168.1.1", "Suspicious URL - IP Address", (30, 90))
        self.test_url_scan("http://very-long-suspicious-domain-name-that-might-be-phishing.tk", "Suspicious URL - Long Domain + Suspicious TLD", (40, 90))
        
        # Potentially malicious URLs (should have high risk scores)
        self.test_url_scan("http://paypal-security-update.suspicious-domain.tk", "Malicious URL - Phishing Keywords", (60, 100))
        self.test_url_scan("http://download-crack-software.malware-site.xyz", "Malicious URL - Malware Indicators", (60, 100))
        self.test_url_scan("http://аррӏе.com", "Malicious URL - Homograph Attack", (70, 100))
        
        # Test malformed URLs
        print("\n⚠️ Testing Malformed URLs:")
        self.test_malformed_url_scan()
        
        # Test scan retrieval
        print("\n📋 Testing Scan Retrieval:")
        if self.scan_ids:
            self.test_scan_retrieval(self.scan_ids[0])
        self.test_invalid_scan_retrieval()
        
        # Final statistics check
        print("\n📊 Final Statistics Check:")
        self.test_stats_endpoint()
        
        # Print results
        print("\n" + "=" * 80)
        print(f"🏁 Testing Complete!")
        print(f"📈 Tests Passed: {self.tests_passed}/{self.tests_run}")
        print(f"📉 Success Rate: {(self.tests_passed/self.tests_run*100):.1f}%")
        
        if self.tests_passed == self.tests_run:
            print("🎉 All tests passed! The API is working correctly.")
            return 0
        else:
            print("⚠️ Some tests failed. Please check the API implementation.")
            return 1

def main():
    """Main test execution"""
    tester = URLSecurityAPITester()
    return tester.run_comprehensive_tests()

if __name__ == "__main__":
    sys.exit(main())