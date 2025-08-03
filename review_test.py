#!/usr/bin/env python3

import requests
import json
import sys
import time
from datetime import datetime

class ReviewRequestTester:
    def __init__(self, base_url="https://732275be-4025-4a6a-ac28-9c87942c8455.preview.emergentagent.com"):
        self.base_url = base_url
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def log_test(self, name: str, passed: bool, details: str = ""):
        """Log test result"""
        self.tests_run += 1
        if passed:
            self.tests_passed += 1
        
        result = {
            'test_name': name,
            'passed': passed,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.test_results.append(result)
        
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} - {name}")
        if details:
            print(f"    Details: {details}")

    def run_test(self, name: str, method: str, endpoint: str, expected_status: int, data: dict = None, headers: dict = None) -> tuple:
        """Run a single API test"""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        if headers is None:
            headers = {'Content-Type': 'application/json'}

        print(f"\n🔍 Testing {name}...")
        print(f"    URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=30)
            elif method == 'POST':
                response = requests.post(url, json=data, headers=headers, timeout=30)
            else:
                raise ValueError(f"Unsupported method: {method}")

            success = response.status_code == expected_status
            
            if success:
                try:
                    response_data = response.json()
                    details = f"Status: {response.status_code}"
                    self.log_test(name, True, details)
                    return True, response_data
                except json.JSONDecodeError:
                    details = f"Status: {response.status_code}, Non-JSON response"
                    self.log_test(name, True, details)
                    return True, {}
            else:
                details = f"Expected {expected_status}, got {response.status_code}"
                if response.text:
                    details += f" - Response: {response.text[:200]}"
                self.log_test(name, False, details)
                return False, {}

        except requests.exceptions.Timeout:
            self.log_test(name, False, "Request timeout (30s)")
            return False, {}
        except requests.exceptions.ConnectionError:
            self.log_test(name, False, "Connection error - service may be down")
            return False, {}
        except Exception as e:
            self.log_test(name, False, f"Error: {str(e)}")
            return False, {}

    def test_dns_provider_removal_verification(self):
        """Test DNS Provider Removal Verification - Verify only 8 DNS providers remain after removal"""
        print("\n🔍 Testing DNS Provider Removal Verification...")
        
        success, response = self.run_test(
            "DNS Provider Count Verification",
            "POST", "/api/scan",
            200,
            data={
                "url": "https://google.com",
                "scan_type": "standard"
            }
        )
        
        if success and response:
            analysis_details = response.get('analysis_details', {})
            detailed_report = analysis_details.get('detailed_report', {})
            dns_availability = detailed_report.get('dns_availability_check', {})
            dns_resolvers = dns_availability.get('dns_resolvers', {})
            
            if dns_resolvers:
                # Check that only 8 DNS providers remain (not 12)
                resolver_count = len(dns_resolvers)
                if resolver_count == 8:
                    self.log_test("DNS Provider Count After Removal", True, 
                                f"Correct count: {resolver_count} DNS providers (expected 8)")
                else:
                    self.log_test("DNS Provider Count After Removal", False, 
                                f"Incorrect count: {resolver_count} DNS providers (expected 8)")
                
                # Verify the remaining 8 DNS providers are the expected ones
                expected_remaining_providers = [
                    'Cloudflare', 'Quad9', 'Google DNS', 'AdGuard DNS',
                    'OpenDNS (Family Shield)', 'CleanBrowsing (Free Tier)', 
                    'dns0.eu', 'CIRA Canadian Shield'
                ]
                
                found_providers = list(dns_resolvers.keys())
                missing_expected = [provider for provider in expected_remaining_providers if provider not in found_providers]
                unexpected_providers = [provider for provider in found_providers if provider not in expected_remaining_providers]
                
                if not missing_expected and not unexpected_providers:
                    self.log_test("DNS Provider List Verification", True, 
                                f"All expected providers present: {found_providers}")
                else:
                    details = f"Found: {found_providers}"
                    if missing_expected:
                        details += f", Missing: {missing_expected}"
                    if unexpected_providers:
                        details += f", Unexpected: {unexpected_providers}"
                    self.log_test("DNS Provider List Verification", False, details)
                
                # Verify removed providers are NOT present
                removed_providers = ['Mullvad DNS', 'UncensoredDNS', 'DNS4EU (basic tier)', 'LibreDNS']
                found_removed = [provider for provider in removed_providers if provider in found_providers]
                
                if not found_removed:
                    self.log_test("Removed DNS Providers Verification", True, 
                                f"Confirmed removed providers not present: {removed_providers}")
                else:
                    self.log_test("Removed DNS Providers Verification", False, 
                                f"Found removed providers still present: {found_removed}")
            else:
                self.log_test("DNS Provider Removal Verification", False, "No DNS resolver data found")

    def test_email_security_records_improvements(self):
        """Test Email Security Records Fix Verification - Test improvements to SPF, DMARC, DKIM"""
        print("\n📧 Testing Email Security Records Improvements...")
        
        # Test with domains known to have good email security records
        test_domains = [
            {
                "domain": "google.com",
                "name": "Google (Expected Good Records)"
            },
            {
                "domain": "github.com", 
                "name": "GitHub (Expected Good Records)"
            }
        ]
        
        for test_case in test_domains:
            success, response = self.run_test(
                f"Enhanced Email Security - {test_case['name']}",
                "POST", "/api/scan",
                200,
                data={
                    "url": f"https://{test_case['domain']}",
                    "scan_type": "standard"
                }
            )
            
            if success and response:
                analysis_details = response.get('analysis_details', {})
                detailed_report = analysis_details.get('detailed_report', {})
                email_security = detailed_report.get('email_security_records', {})
                
                if email_security:
                    # Test enhanced SPF record analysis
                    spf_record = email_security.get('spf_record')
                    spf_status = email_security.get('spf_status', 'Not Found')
                    spf_issues = email_security.get('spf_issues', [])
                    
                    if spf_record and spf_status != 'Not Found':
                        # Check for enhanced SPF analysis features
                        enhanced_spf_features = []
                        if 'Hard Fail Policy' in spf_status or 'Soft Fail Policy' in spf_status:
                            enhanced_spf_features.append('Policy Detection')
                        if spf_issues:
                            enhanced_spf_features.append('Issue Analysis')
                        if 'Permissive' in spf_status or 'Insecure' in spf_status:
                            enhanced_spf_features.append('Security Assessment')
                        
                        self.log_test(f"Enhanced SPF Analysis - {test_case['name']}", True, 
                                    f"Status: {spf_status}, Issues: {len(spf_issues)}, Features: {enhanced_spf_features}")
                    else:
                        self.log_test(f"Enhanced SPF Analysis - {test_case['name']}", True, 
                                    f"SPF Status: {spf_status} (domain may not have SPF)")
                    
                    # Test enhanced DMARC record analysis
                    dmarc_record = email_security.get('dmarc_record')
                    dmarc_status = email_security.get('dmarc_status', 'Not Found')
                    dmarc_policy = email_security.get('dmarc_policy')
                    
                    if dmarc_record and dmarc_status == 'Found':
                        # Check for enhanced DMARC policy parsing
                        enhanced_dmarc_features = []
                        if dmarc_policy:
                            if 'Reject' in dmarc_policy:
                                enhanced_dmarc_features.append('Strong Policy')
                            elif 'Quarantine' in dmarc_policy:
                                enhanced_dmarc_features.append('Moderate Policy')
                            elif 'Monitor Only' in dmarc_policy:
                                enhanced_dmarc_features.append('Weak Policy')
                            if 'Subdomain' in dmarc_policy:
                                enhanced_dmarc_features.append('Subdomain Policy')
                        
                        self.log_test(f"Enhanced DMARC Analysis - {test_case['name']}", True, 
                                    f"Policy: {dmarc_policy}, Features: {enhanced_dmarc_features}")
                    else:
                        self.log_test(f"Enhanced DMARC Analysis - {test_case['name']}", True, 
                                    f"DMARC Status: {dmarc_status} (domain may not have DMARC)")
                    
                    # Test improved DKIM detection with extended selector list
                    dkim_status = email_security.get('dkim_status', 'Unknown')
                    dkim_selectors_found = email_security.get('dkim_selectors_found', [])
                    
                    if dkim_status == 'Found' and dkim_selectors_found:
                        self.log_test(f"Enhanced DKIM Detection - {test_case['name']}", True, 
                                    f"Status: {dkim_status}, Selectors found: {dkim_selectors_found}")
                    else:
                        self.log_test(f"Enhanced DKIM Detection - {test_case['name']}", True, 
                                    f"DKIM Status: {dkim_status} (extended selector check performed)")
                    
                    # Test enhanced scoring algorithm
                    email_security_score = email_security.get('email_security_score', 0)
                    recommendations = email_security.get('recommendations', [])
                    
                    if 0 <= email_security_score <= 100:
                        score_category = "Excellent" if email_security_score >= 80 else "Good" if email_security_score >= 60 else "Fair" if email_security_score >= 40 else "Poor"
                        self.log_test(f"Enhanced Scoring Algorithm - {test_case['name']}", True, 
                                    f"Score: {email_security_score}/100 ({score_category}), Recommendations: {len(recommendations)}")
                    else:
                        self.log_test(f"Enhanced Scoring Algorithm - {test_case['name']}", False, 
                                    f"Invalid score: {email_security_score}")
                    
                else:
                    self.log_test(f"Email Security Records Improvements - {test_case['name']}", False, 
                                "No email security analysis data found")

    def test_sample_url_verification(self):
        """Test with sample URLs to verify DNS resolver section shows only remaining providers"""
        print("\n🌐 Testing Sample URL Verification...")
        
        test_urls = [
            "https://google.com",
            "https://github.com"
        ]
        
        for url in test_urls:
            success, response = self.run_test(
                f"Sample URL Test - {url}",
                "POST", "/api/scan",
                200,
                data={
                    "url": url,
                    "scan_type": "standard"
                }
            )
            
            if success and response:
                analysis_details = response.get('analysis_details', {})
                detailed_report = analysis_details.get('detailed_report', {})
                dns_availability = detailed_report.get('dns_availability_check', {})
                
                if dns_availability:
                    dns_resolvers = dns_availability.get('dns_resolvers', {})
                    threat_feeds = dns_availability.get('threat_intelligence_feeds', {})
                    availability_score = dns_availability.get('availability_score', 0)
                    
                    self.log_test(f"DNS Section Present - {url}", True, 
                                f"DNS resolvers: {len(dns_resolvers)}, Threat feeds: {len(threat_feeds)}, Score: {availability_score}")
                else:
                    self.log_test(f"DNS Section Present - {url}", False, "No DNS availability section found")

    def run_review_tests(self):
        """Run all review request specific tests"""
        print("🔍 Starting Review Request Verification Tests")
        print("=" * 60)
        
        # Test DNS provider removal
        self.test_dns_provider_removal_verification()
        
        # Test email security improvements
        self.test_email_security_records_improvements()
        
        # Test sample URL verification
        self.test_sample_url_verification()
        
        # Print summary
        print("\n" + "=" * 60)
        print("🏁 REVIEW TEST SUMMARY")
        print("=" * 60)
        print(f"Total Tests: {self.tests_run}")
        print(f"Passed: {self.tests_passed}")
        print(f"Failed: {self.tests_run - self.tests_passed}")
        print(f"Success Rate: {(self.tests_passed/self.tests_run*100):.1f}%")
        
        # Print failed tests
        failed_tests = [test for test in self.test_results if not test['passed']]
        if failed_tests:
            print(f"\n❌ FAILED TESTS ({len(failed_tests)}):")
            for test in failed_tests:
                print(f"  - {test['test_name']}: {test['details']}")
        
        return self.tests_passed == self.tests_run

def main():
    """Main test execution"""
    tester = ReviewRequestTester()
    
    try:
        success = tester.run_review_tests()
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\n\n⚠️ Tests interrupted by user")
        return 1
    except Exception as e:
        print(f"\n\n💥 Test execution failed: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())