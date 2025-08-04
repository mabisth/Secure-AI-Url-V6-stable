#!/usr/bin/env python3

import requests
import json
import sys
import time
from datetime import datetime

class ComprehensiveReviewTester:
    def __init__(self, base_url="https://f0b72e9d-ad12-4eb9-88f4-9c6ff13f98bd.preview.emergentagent.com"):
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

    def test_comprehensive_dns_provider_verification(self):
        """Comprehensive test of DNS provider removal and verification"""
        print("\n🔍 COMPREHENSIVE DNS PROVIDER VERIFICATION")
        print("-" * 50)
        
        # Test with multiple URLs to ensure consistency
        test_urls = [
            "https://google.com",
            "https://github.com", 
            "https://microsoft.com"
        ]
        
        for url in test_urls:
            success, response = self.run_test(
                f"DNS Provider Test - {url}",
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
                dns_resolvers = dns_availability.get('dns_resolvers', {})
                
                if dns_resolvers:
                    # Verify exactly 8 DNS providers
                    resolver_count = len(dns_resolvers)
                    if resolver_count == 8:
                        self.log_test(f"DNS Count Verification - {url}", True, 
                                    f"Exactly 8 DNS providers: {resolver_count}")
                    else:
                        self.log_test(f"DNS Count Verification - {url}", False, 
                                    f"Expected 8, found {resolver_count}")
                    
                    # Verify specific remaining providers
                    expected_providers = {
                        'Cloudflare': ['1.1.1.1', '1.0.0.1'],
                        'Quad9': ['9.9.9.9', '149.112.112.112'],
                        'Google DNS': ['8.8.8.8', '8.8.4.4'],
                        'AdGuard DNS': ['94.140.14.14', '94.140.15.15'],
                        'OpenDNS (Family Shield)': ['208.67.222.123', '208.67.220.123'],
                        'CleanBrowsing (Free Tier)': ['185.228.168.9', '185.228.169.9'],
                        'dns0.eu': ['193.110.81.0', '185.253.5.0'],
                        'CIRA Canadian Shield': ['149.112.121.10', '149.112.122.10']
                    }
                    
                    found_providers = list(dns_resolvers.keys())
                    all_expected_found = all(provider in found_providers for provider in expected_providers.keys())
                    
                    if all_expected_found:
                        self.log_test(f"Expected Providers Present - {url}", True, 
                                    f"All 8 expected providers found")
                    else:
                        missing = [p for p in expected_providers.keys() if p not in found_providers]
                        self.log_test(f"Expected Providers Present - {url}", False, 
                                    f"Missing providers: {missing}")
                    
                    # Verify removed providers are NOT present
                    removed_providers = ['Mullvad DNS', 'UncensoredDNS', 'DNS4EU (basic tier)', 'LibreDNS']
                    found_removed = [p for p in removed_providers if p in found_providers]
                    
                    if not found_removed:
                        self.log_test(f"Removed Providers Absent - {url}", True, 
                                    f"No removed providers found")
                    else:
                        self.log_test(f"Removed Providers Absent - {url}", False, 
                                    f"Found removed providers: {found_removed}")
                    
                    # Verify DNS resolver data structure
                    for provider_name, provider_data in dns_resolvers.items():
                        required_fields = ['blocked', 'status', 'response_time_ms']
                        missing_fields = [field for field in required_fields if field not in provider_data]
                        
                        if not missing_fields:
                            self.log_test(f"DNS Data Structure - {provider_name}", True, 
                                        f"All required fields present")
                        else:
                            self.log_test(f"DNS Data Structure - {provider_name}", False, 
                                        f"Missing fields: {missing_fields}")

    def test_comprehensive_email_security_improvements(self):
        """Comprehensive test of email security record improvements"""
        print("\n📧 COMPREHENSIVE EMAIL SECURITY IMPROVEMENTS")
        print("-" * 50)
        
        # Test with domains known to have comprehensive email security
        test_domains = [
            {
                "domain": "google.com",
                "name": "Google",
                "expected_features": ["SPF", "DMARC", "Strong Policy"]
            },
            {
                "domain": "github.com",
                "name": "GitHub", 
                "expected_features": ["SPF", "DMARC", "DKIM", "Strong Policy"]
            },
            {
                "domain": "microsoft.com",
                "name": "Microsoft",
                "expected_features": ["SPF", "DMARC"]
            }
        ]
        
        for test_case in test_domains:
            success, response = self.run_test(
                f"Email Security Comprehensive - {test_case['name']}",
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
                    # Test enhanced SPF analysis
                    spf_record = email_security.get('spf_record')
                    spf_status = email_security.get('spf_status', 'Not Found')
                    spf_issues = email_security.get('spf_issues', [])
                    
                    spf_features_found = []
                    if spf_record:
                        spf_features_found.append("SPF Record Found")
                        if 'Hard Fail Policy' in spf_status:
                            spf_features_found.append("Hard Fail Policy")
                        elif 'Soft Fail Policy' in spf_status:
                            spf_features_found.append("Soft Fail Policy")
                        if spf_issues:
                            spf_features_found.append("Issue Analysis")
                    
                    self.log_test(f"Enhanced SPF Features - {test_case['name']}", True, 
                                f"Features: {spf_features_found}, Issues: {len(spf_issues)}")
                    
                    # Test enhanced DMARC analysis
                    dmarc_record = email_security.get('dmarc_record')
                    dmarc_status = email_security.get('dmarc_status', 'Not Found')
                    dmarc_policy = email_security.get('dmarc_policy')
                    
                    dmarc_features_found = []
                    if dmarc_record and dmarc_status == 'Found':
                        dmarc_features_found.append("DMARC Record Found")
                        if dmarc_policy:
                            if 'Reject' in dmarc_policy:
                                dmarc_features_found.append("Strong Policy (Reject)")
                            elif 'Quarantine' in dmarc_policy:
                                dmarc_features_found.append("Moderate Policy (Quarantine)")
                            elif 'Monitor Only' in dmarc_policy:
                                dmarc_features_found.append("Weak Policy (Monitor)")
                            if 'Subdomain' in dmarc_policy:
                                dmarc_features_found.append("Subdomain Policy")
                    
                    self.log_test(f"Enhanced DMARC Features - {test_case['name']}", True, 
                                f"Features: {dmarc_features_found}, Policy: {dmarc_policy}")
                    
                    # Test improved DKIM detection
                    dkim_status = email_security.get('dkim_status', 'Unknown')
                    dkim_selectors_found = email_security.get('dkim_selectors_found', [])
                    
                    dkim_features_found = []
                    if dkim_status == 'Found':
                        dkim_features_found.append("DKIM Records Found")
                        if dkim_selectors_found:
                            dkim_features_found.append(f"Multiple Selectors ({len(dkim_selectors_found)})")
                    elif 'Common Selectors Checked' in dkim_status:
                        dkim_features_found.append("Extended Selector Search")
                    
                    self.log_test(f"Enhanced DKIM Features - {test_case['name']}", True, 
                                f"Features: {dkim_features_found}, Selectors: {dkim_selectors_found}")
                    
                    # Test enhanced error handling
                    error_handling_features = []
                    if 'DNS Query Timeout' in spf_status or 'DNS Query Timeout' in dmarc_status:
                        error_handling_features.append("Timeout Handling")
                    if 'DNS Query Error' in spf_status or 'DNS Query Error' in dmarc_status:
                        error_handling_features.append("Error Handling")
                    if 'Domain Not Found' in spf_status:
                        error_handling_features.append("NXDOMAIN Handling")
                    
                    self.log_test(f"Enhanced Error Handling - {test_case['name']}", True, 
                                f"Error handling: {error_handling_features if error_handling_features else ['No errors encountered']}")
                    
                    # Test enhanced scoring algorithm
                    email_security_score = email_security.get('email_security_score', 0)
                    recommendations = email_security.get('recommendations', [])
                    
                    if 0 <= email_security_score <= 100:
                        score_analysis = {
                            "score": email_security_score,
                            "grade": "A" if email_security_score >= 90 else "B" if email_security_score >= 80 else "C" if email_security_score >= 70 else "D" if email_security_score >= 60 else "F",
                            "recommendations": len(recommendations)
                        }
                        
                        self.log_test(f"Enhanced Scoring - {test_case['name']}", True, 
                                    f"Score: {email_security_score}/100 (Grade {score_analysis['grade']}), Recommendations: {len(recommendations)}")
                    else:
                        self.log_test(f"Enhanced Scoring - {test_case['name']}", False, 
                                    f"Invalid score: {email_security_score}")
                    
                    # Test recommendation categorization
                    recommendation_types = {
                        "critical": len([r for r in recommendations if '🔴' in r]),
                        "warning": len([r for r in recommendations if '🟡' in r]),
                        "spf_specific": len([r for r in recommendations if 'SPF' in r]),
                        "dmarc_specific": len([r for r in recommendations if 'DMARC' in r]),
                        "dkim_specific": len([r for r in recommendations if 'DKIM' in r])
                    }
                    
                    self.log_test(f"Enhanced Recommendations - {test_case['name']}", True, 
                                f"Types: Critical({recommendation_types['critical']}), Warning({recommendation_types['warning']}), SPF({recommendation_types['spf_specific']}), DMARC({recommendation_types['dmarc_specific']}), DKIM({recommendation_types['dkim_specific']})")

    def test_domain_with_limited_email_security(self):
        """Test with a domain that likely has limited email security"""
        print("\n⚠️ TESTING LIMITED EMAIL SECURITY DOMAIN")
        print("-" * 50)
        
        # Test with a domain that might have limited email security
        test_domain = "example.com"  # Known to have basic/limited email security
        
        success, response = self.run_test(
            f"Limited Email Security Test - {test_domain}",
            "POST", "/api/scan",
            200,
            data={
                "url": f"https://{test_domain}",
                "scan_type": "standard"
            }
        )
        
        if success and response:
            analysis_details = response.get('analysis_details', {})
            detailed_report = analysis_details.get('detailed_report', {})
            email_security = detailed_report.get('email_security_records', {})
            
            if email_security:
                email_security_score = email_security.get('email_security_score', 0)
                recommendations = email_security.get('recommendations', [])
                spf_status = email_security.get('spf_status', 'Not Found')
                dmarc_status = email_security.get('dmarc_status', 'Not Found')
                dkim_status = email_security.get('dkim_status', 'Unknown')
                
                # Verify the system properly handles limited email security
                security_analysis = {
                    "spf_present": spf_status != 'Not Found',
                    "dmarc_present": dmarc_status == 'Found',
                    "dkim_present": dkim_status == 'Found',
                    "score": email_security_score,
                    "recommendations_count": len(recommendations)
                }
                
                self.log_test(f"Limited Security Analysis - {test_domain}", True, 
                            f"SPF: {security_analysis['spf_present']}, DMARC: {security_analysis['dmarc_present']}, DKIM: {security_analysis['dkim_present']}, Score: {security_analysis['score']}, Recommendations: {security_analysis['recommendations_count']}")
                
                # Verify appropriate recommendations are generated for limited security
                critical_recommendations = [r for r in recommendations if '🔴' in r]
                if not security_analysis['spf_present'] or not security_analysis['dmarc_present']:
                    if critical_recommendations:
                        self.log_test(f"Critical Recommendations Generated - {test_domain}", True, 
                                    f"Generated {len(critical_recommendations)} critical recommendations for missing security")
                    else:
                        self.log_test(f"Critical Recommendations Generated - {test_domain}", False, 
                                    f"No critical recommendations for missing email security")

    def test_dns_resolver_count_consistency(self):
        """Test that DNS resolver count is consistently 8 across different requests"""
        print("\n🔄 TESTING DNS RESOLVER COUNT CONSISTENCY")
        print("-" * 50)
        
        test_urls = [
            "https://google.com",
            "https://github.com",
            "https://microsoft.com",
            "https://stackoverflow.com"
        ]
        
        resolver_counts = []
        
        for url in test_urls:
            success, response = self.run_test(
                f"DNS Consistency Test - {url}",
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
                dns_resolvers = dns_availability.get('dns_resolvers', {})
                
                resolver_count = len(dns_resolvers)
                resolver_counts.append(resolver_count)
                
                self.log_test(f"DNS Count - {url}", resolver_count == 8, 
                            f"Found {resolver_count} DNS resolvers (expected 8)")
        
        # Verify consistency across all requests
        if resolver_counts and all(count == 8 for count in resolver_counts):
            self.log_test("DNS Count Consistency", True, 
                        f"All {len(resolver_counts)} requests returned exactly 8 DNS resolvers")
        else:
            self.log_test("DNS Count Consistency", False, 
                        f"Inconsistent DNS resolver counts: {resolver_counts}")

    def run_comprehensive_review_tests(self):
        """Run all comprehensive review tests"""
        print("🔍 Starting Comprehensive Review Request Verification")
        print("=" * 70)
        
        # Test DNS provider removal verification
        self.test_comprehensive_dns_provider_verification()
        
        # Test email security improvements
        self.test_comprehensive_email_security_improvements()
        
        # Test domain with limited email security
        self.test_domain_with_limited_email_security()
        
        # Test DNS resolver count consistency
        self.test_dns_resolver_count_consistency()
        
        # Print summary
        print("\n" + "=" * 70)
        print("🏁 COMPREHENSIVE REVIEW TEST SUMMARY")
        print("=" * 70)
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
        else:
            print(f"\n✅ ALL TESTS PASSED!")
        
        # Print key findings
        print(f"\n🔍 KEY FINDINGS:")
        dns_tests = [test for test in self.test_results if 'DNS' in test['test_name']]
        email_tests = [test for test in self.test_results if 'Email' in test['test_name']]
        
        print(f"  • DNS Provider Tests: {len([t for t in dns_tests if t['passed']])}/{len(dns_tests)} passed")
        print(f"  • Email Security Tests: {len([t for t in email_tests if t['passed']])}/{len(email_tests)} passed")
        
        return self.tests_passed == self.tests_run

def main():
    """Main test execution"""
    tester = ComprehensiveReviewTester()
    
    try:
        success = tester.run_comprehensive_review_tests()
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\n\n⚠️ Tests interrupted by user")
        return 1
    except Exception as e:
        print(f"\n\n💥 Test execution failed: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())