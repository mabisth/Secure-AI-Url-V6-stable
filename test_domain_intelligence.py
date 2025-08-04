#!/usr/bin/env python3

import requests
import json
import sys
import time
from datetime import datetime
from typing import Dict, List, Any

class DomainIntelligenceTester:
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

    def run_test(self, name: str, method: str, endpoint: str, expected_status: int, data: Dict = None, headers: Dict = None) -> tuple:
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
            elif method == 'PUT':
                response = requests.put(url, json=data, headers=headers, timeout=30)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers, timeout=30)
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

    def test_enhanced_domain_intelligence(self):
        """Test Enhanced Domain Intelligence functionality with comprehensive geographic intelligence"""
        print("\n🌍 Testing Enhanced Domain Intelligence...")
        
        # Test domains as requested in the review
        test_domains = [
            {
                "domain": "google.com",
                "name": "Google",
                "expected_fields": {
                    "country_code": ["US"],
                    "country_name": ["United States"],
                    "continent": ["North America"],
                    "country_risk_level": ["Low"],
                    "is_high_risk_country": [False],
                    "tld_country": ["Generic TLD (.com, .org, .net, etc.)"],
                    "international_popularity": [100, 90],
                    "local_popularity": [100, 85]
                }
            },
            {
                "domain": "github.com", 
                "name": "GitHub",
                "expected_fields": {
                    "country_code": ["US", "EU", "AP"],
                    "country_name": ["United States", "European Union", "Asia-Pacific"],
                    "continent": ["North America", "Europe", "Asia"],
                    "country_risk_level": ["Low", "Medium"],
                    "is_high_risk_country": [False],
                    "tld_country": ["Generic TLD (.com, .org, .net, etc.)"],
                    "international_popularity": [60, 90],
                    "local_popularity": [50, 85]
                }
            },
            {
                "domain": "mashreqbank.com",
                "name": "Mashreq Bank",
                "expected_fields": {
                    "country_code": ["US", "EU", "AP", "Unknown"],
                    "country_name": ["United States", "European Union", "Asia-Pacific", "Unknown"],
                    "continent": ["North America", "Europe", "Asia", "Unknown"],
                    "country_risk_level": ["Low", "Medium", "Unknown"],
                    "is_high_risk_country": [False],
                    "tld_country": ["Generic TLD (.com, .org, .net, etc.)"],
                    "international_popularity": [60],
                    "local_popularity": [50]
                }
            },
            {
                "domain": "amazon.com",
                "name": "Amazon",
                "expected_fields": {
                    "country_code": ["US"],
                    "country_name": ["United States"],
                    "continent": ["North America"],
                    "country_risk_level": ["Low"],
                    "is_high_risk_country": [False],
                    "tld_country": ["Generic TLD (.com, .org, .net, etc.)"],
                    "international_popularity": [100, 90],
                    "local_popularity": [100, 85]
                }
            }
        ]
        
        for test_case in test_domains:
            domain = test_case["domain"]
            name = test_case["name"]
            expected = test_case["expected_fields"]
            
            success, response = self.run_test(
                f"Enhanced Domain Intelligence - {name}",
                "POST", "/api/scan",
                200,
                data={"url": f"https://{domain}", "scan_type": "detailed"}
            )
            
            if success and response:
                analysis_details = response.get('analysis_details', {})
                domain_analysis = analysis_details.get('domain_analysis', {})
                
                if domain_analysis:
                    print(f"\n📊 Domain Analysis Results for {name}:")
                    print(f"    Country Code: {domain_analysis.get('country_code')}")
                    print(f"    Country Name: {domain_analysis.get('country_name')}")
                    print(f"    Continent: {domain_analysis.get('continent')}")
                    print(f"    Region: {domain_analysis.get('region')}")
                    print(f"    City: {domain_analysis.get('city')}")
                    print(f"    Timezone: {domain_analysis.get('timezone')}")
                    print(f"    Language: {domain_analysis.get('language')}")
                    print(f"    Currency: {domain_analysis.get('currency')}")
                    print(f"    Country Flag: {domain_analysis.get('country_flag')}")
                    print(f"    Country Risk Level: {domain_analysis.get('country_risk_level')}")
                    print(f"    Is High Risk Country: {domain_analysis.get('is_high_risk_country')}")
                    print(f"    TLD Country: {domain_analysis.get('tld_country')}")
                    print(f"    Domain Extensions: {domain_analysis.get('domain_extensions')}")
                    print(f"    International Popularity: {domain_analysis.get('international_popularity')}")
                    print(f"    Local Popularity: {domain_analysis.get('local_popularity')}")
                    print(f"    Geographic Location: {domain_analysis.get('geographic_location')}")
                    
                    # Test comprehensive field verification
                    required_domain_fields = [
                        'country_code', 'country_name', 'continent', 'region', 'city',
                        'timezone', 'language', 'currency', 'country_flag',
                        'country_risk_level', 'is_high_risk_country', 'tld_country',
                        'domain_extensions', 'international_popularity', 'local_popularity'
                    ]
                    
                    found_fields = [field for field in required_domain_fields if field in domain_analysis]
                    missing_fields = [field for field in required_domain_fields if field not in domain_analysis]
                    
                    if len(found_fields) >= 13:  # At least 13 out of 15 fields
                        self.log_test(f"Domain Intelligence Fields Complete - {name}", True, 
                                    f"Found {len(found_fields)}/15 fields")
                    else:
                        self.log_test(f"Domain Intelligence Fields Complete - {name}", False, 
                                    f"Only {len(found_fields)}/15 fields found. Missing: {missing_fields}")
                    
                    # Test data quality
                    non_unknown_fields = 0
                    for field in ['country_code', 'country_name', 'continent', 'timezone', 'language', 'currency']:
                        value = domain_analysis.get(field)
                        if value and value != 'Unknown':
                            non_unknown_fields += 1
                    
                    if non_unknown_fields >= 3:  # At least 3 fields should have meaningful data
                        self.log_test(f"Domain Intelligence Data Quality - {name}", True, 
                                    f"{non_unknown_fields}/6 key fields have meaningful data")
                    else:
                        self.log_test(f"Domain Intelligence Data Quality - {name}", False, 
                                    f"Only {non_unknown_fields}/6 key fields have meaningful data")
                        
                else:
                    self.log_test(f"Enhanced Domain Intelligence - {name}", False, 
                                "No domain_analysis section found in response")
            else:
                self.log_test(f"Enhanced Domain Intelligence - {name}", False, 
                            f"API request failed for {domain}")

    def run_tests(self):
        """Run Enhanced Domain Intelligence tests"""
        print("🌍 Starting Enhanced Domain Intelligence Tests")
        print("=" * 60)
        
        self.test_enhanced_domain_intelligence()
        
        # Print summary
        print("\n" + "=" * 60)
        print("🏁 ENHANCED DOMAIN INTELLIGENCE TEST SUMMARY")
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
        else:
            print("\n✅ ALL TESTS PASSED!")

if __name__ == "__main__":
    tester = DomainIntelligenceTester()
    tester.run_tests()