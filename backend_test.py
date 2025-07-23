#!/usr/bin/env python3

import requests
import json
import sys
import time
from datetime import datetime
from typing import Dict, List, Any

class ESkimmingProtectionTester:
    def __init__(self, base_url="https://a5121a2e-4dcd-4999-9f62-27d72917efae.preview.emergentagent.com"):
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

    def test_root_endpoint(self):
        """Test root endpoint for E-Skimming features"""
        success, response = self.run_test(
            "Root Endpoint - E-Skimming Features",
            "GET", "/", 200
        )
        
        if success and response:
            # Verify E-Skimming specific features
            expected_features = [
                "E-Skimming Detection",
                "Payment Gateway Security", 
                "Regulatory Compliance",
                "Daily Merchant Scanning",
                "Transaction Halt Recommendations"
            ]
            
            features = response.get('features', [])
            missing_features = [f for f in expected_features if f not in features]
            
            if not missing_features:
                self.log_test("E-Skimming Features Present", True, f"All features found: {features}")
            else:
                self.log_test("E-Skimming Features Present", False, f"Missing: {missing_features}")
            
            # Check version
            version = response.get('version')
            if version == "3.0.0":
                self.log_test("Version Check", True, f"Version: {version}")
            else:
                self.log_test("Version Check", False, f"Expected 3.0.0, got {version}")
            
            # Check compliance info
            compliance = response.get('compliance')
            if "Retail Payment Services" in str(compliance):
                self.log_test("Regulatory Compliance Info", True, f"Compliance: {compliance}")
            else:
                self.log_test("Regulatory Compliance Info", False, f"Missing compliance info: {compliance}")

    def test_e_skimming_detection(self):
        """Test E-Skimming specific detection"""
        print("\n🔍 Testing E-Skimming Detection System...")
        
        # Test cases for E-skimming detection
        test_cases = [
            {
                "name": "Legitimate Payment URL (Stripe)",
                "url": "https://checkout.stripe.com/pay",
                "scan_type": "e_skimming",
                "expected_safe": True
            },
            {
                "name": "Legitimate Payment URL (PayPal)",
                "url": "https://www.paypal.com/checkout",
                "scan_type": "e_skimming", 
                "expected_safe": True
            },
            {
                "name": "Suspicious E-Skimming URL (Magecart)",
                "url": "https://fake-checkout.magecart-malware.tk/billing.php",
                "scan_type": "e_skimming",
                "expected_safe": False
            },
            {
                "name": "Suspicious E-Skimming URL (Skimmer)",
                "url": "https://evil-payment.skimmer-site.ml/cardstealer.php",
                "scan_type": "e_skimming",
                "expected_safe": False
            },
            {
                "name": "Payment Gateway Impersonation",
                "url": "https://fake-stripe.malicious-site.xyz/checkout",
                "scan_type": "payment_gateway",
                "expected_safe": False
            }
        ]
        
        for test_case in test_cases:
            success, response = self.run_test(
                f"E-Skimming Scan - {test_case['name']}",
                "POST", "/api/scan",
                200,
                data={
                    "url": test_case["url"],
                    "scan_type": test_case["scan_type"]
                }
            )
            
            if success and response:
                # Check if response has e-skimming specific fields
                risk_score = response.get('risk_score', 0)
                is_malicious = response.get('is_malicious', False)
                threat_category = response.get('threat_category', '')
                
                # Verify expected safety level
                if test_case['expected_safe']:
                    if not is_malicious and risk_score < 50:
                        self.log_test(f"Safety Check - {test_case['name']}", True, 
                                    f"Safe as expected - Risk: {risk_score}, Malicious: {is_malicious}")
                    else:
                        self.log_test(f"Safety Check - {test_case['name']}", False,
                                    f"Expected safe but got - Risk: {risk_score}, Malicious: {is_malicious}")
                else:
                    if is_malicious or risk_score > 60:
                        self.log_test(f"Threat Detection - {test_case['name']}", True,
                                    f"Threat detected as expected - Risk: {risk_score}, Category: {threat_category}")
                    else:
                        self.log_test(f"Threat Detection - {test_case['name']}", False,
                                    f"Expected threat but got - Risk: {risk_score}, Malicious: {is_malicious}")
                
                # Check for E-skimming specific analysis fields
                analysis_details = response.get('analysis_details', {})
                if analysis_details:
                    self.log_test(f"Analysis Details - {test_case['name']}", True, "Analysis details present")
                else:
                    self.log_test(f"Analysis Details - {test_case['name']}", False, "Missing analysis details")

    def test_payment_security_features(self):
        """Test payment security specific features"""
        print("\n💳 Testing Payment Security Features...")
        
        # Test with a payment URL
        success, response = self.run_test(
            "Payment Security Analysis",
            "POST", "/api/scan",
            200,
            data={
                "url": "https://checkout.example-merchant.com/payment",
                "scan_type": "e_skimming"
            }
        )
        
        if success and response:
            # Check for payment security score (should be 0-100)
            analysis_details = response.get('analysis_details', {})
            
            # Check ML predictions
            ml_predictions = response.get('ml_predictions', {})
            if ml_predictions:
                phishing_prob = ml_predictions.get('phishing_probability')
                malware_prob = ml_predictions.get('malware_probability')
                
                if phishing_prob is not None and malware_prob is not None:
                    self.log_test("ML Predictions Present", True, 
                                f"Phishing: {phishing_prob:.2f}, Malware: {malware_prob:.2f}")
                else:
                    self.log_test("ML Predictions Present", False, "Missing ML prediction values")
            
            # Check recommendations
            recommendations = response.get('recommendations', [])
            if recommendations:
                self.log_test("Security Recommendations", True, f"Found {len(recommendations)} recommendations")
            else:
                self.log_test("Security Recommendations", False, "No recommendations provided")

    def test_merchant_compliance_scanning(self):
        """Test merchant compliance scanning endpoint"""
        print("\n🏛️ Testing Merchant Compliance Scanning...")
        
        merchant_data = {
            "merchant_id": "TEST_MERCHANT_001",
            "merchant_name": "Test E-commerce Store",
            "urls": [
                "https://test-merchant.com/checkout",
                "https://test-merchant.com/payment",
                "https://test-merchant.com/billing"
            ],
            "contact_email": "compliance@test-merchant.com"
        }
        
        success, response = self.run_test(
            "Merchant Compliance Scan",
            "POST", "/api/scan/merchant",
            200,
            data=merchant_data
        )
        
        if success and response:
            job_id = response.get('job_id')
            merchant_id = response.get('merchant_id')
            scan_type = response.get('scan_type')
            compliance_check = response.get('compliance_check')
            
            if job_id:
                self.log_test("Merchant Job Creation", True, f"Job ID: {job_id}")
            else:
                self.log_test("Merchant Job Creation", False, "No job ID returned")
            
            if scan_type == "e_skimming":
                self.log_test("E-Skimming Scan Type", True, f"Scan type: {scan_type}")
            else:
                self.log_test("E-Skimming Scan Type", False, f"Expected e_skimming, got: {scan_type}")
            
            if compliance_check:
                self.log_test("Compliance Check Flag", True, "Compliance check enabled")
            else:
                self.log_test("Compliance Check Flag", False, "Compliance check not enabled")

    def test_compliance_dashboard(self):
        """Test regulatory compliance dashboard"""
        print("\n📊 Testing Compliance Dashboard...")
        
        success, response = self.run_test(
            "Compliance Dashboard",
            "GET", "/api/compliance/dashboard",
            200
        )
        
        if success and response:
            # Check for required compliance metrics
            required_fields = [
                'today_scans',
                'today_threats_detected', 
                'today_e_skimming_detected',
                'today_transaction_halts',
                'compliance_distribution',
                'active_merchants',
                'regulatory_compliance'
            ]
            
            missing_fields = [field for field in required_fields if field not in response]
            
            if not missing_fields:
                self.log_test("Compliance Dashboard Fields", True, "All required fields present")
            else:
                self.log_test("Compliance Dashboard Fields", False, f"Missing fields: {missing_fields}")
            
            # Check regulatory compliance info
            regulatory_info = response.get('regulatory_compliance')
            if "Retail Payment Services" in str(regulatory_info):
                self.log_test("Regulatory Compliance Info", True, f"Info: {regulatory_info}")
            else:
                self.log_test("Regulatory Compliance Info", False, f"Missing or incorrect info: {regulatory_info}")

    def test_enhanced_statistics(self):
        """Test enhanced statistics with e-skimming metrics"""
        print("\n📈 Testing Enhanced Statistics...")
        
        success, response = self.run_test(
            "Enhanced Statistics",
            "GET", "/api/stats",
            200
        )
        
        if success and response:
            # Check for enhanced statistics
            expected_fields = [
                'total_scans',
                'malicious_urls_detected',
                'detection_rate',
                'recent_scans',
                'threat_categories',
                'daily_stats',
                'campaign_count'
            ]
            
            missing_fields = [field for field in expected_fields if field not in response]
            
            if not missing_fields:
                self.log_test("Statistics Fields", True, "All statistics fields present")
            else:
                self.log_test("Statistics Fields", False, f"Missing fields: {missing_fields}")
            
            # Check threat categories for e-skimming
            threat_categories = response.get('threat_categories', {})
            if threat_categories:
                self.log_test("Threat Categories", True, f"Categories: {list(threat_categories.keys())}")
            else:
                self.log_test("Threat Categories", False, "No threat categories found")

    def test_bulk_scanning_with_e_skimming(self):
        """Test bulk scanning with e-skimming scan types"""
        print("\n📊 Testing Bulk Scanning with E-Skimming...")
        
        bulk_urls = [
            "https://stripe.com/checkout",
            "https://paypal.com/payment",
            "https://fake-payment.malicious.tk/skimmer.php"
        ]
        
        success, response = self.run_test(
            "Bulk E-Skimming Scan",
            "POST", "/api/scan/bulk",
            200,
            data={
                "urls": bulk_urls,
                "scan_type": "e_skimming"
            }
        )
        
        if success and response:
            job_id = response.get('job_id')
            status = response.get('status')
            total_urls = response.get('total_urls')
            
            if job_id and status == "started":
                self.log_test("Bulk Scan Job Creation", True, f"Job ID: {job_id}, Status: {status}")
                
                # Test job status endpoint
                time.sleep(2)  # Wait a bit for processing
                success_status, status_response = self.run_test(
                    "Bulk Scan Status Check",
                    "GET", f"/api/scan/bulk/{job_id}",
                    200
                )
                
                if success_status and status_response:
                    job_status = status_response.get('status')
                    processed_urls = status_response.get('processed_urls', 0)
                    self.log_test("Bulk Scan Status", True, 
                                f"Status: {job_status}, Processed: {processed_urls}/{total_urls}")
                else:
                    self.log_test("Bulk Scan Status", False, "Could not retrieve job status")
            else:
                self.log_test("Bulk Scan Job Creation", False, f"Job creation failed: {response}")

    def test_campaign_detection(self):
        """Test campaign detection capabilities"""
        print("\n🎯 Testing Campaign Detection...")
        
        success, response = self.run_test(
            "Campaign Detection",
            "GET", "/api/campaigns",
            200
        )
        
        if success and response:
            campaigns = response.get('campaigns', [])
            self.log_test("Campaign Detection Endpoint", True, f"Found {len(campaigns)} campaigns")
        else:
            self.log_test("Campaign Detection Endpoint", False, "Campaign endpoint failed")

    def test_analytics_trends(self):
        """Test analytics trends endpoint"""
        print("\n📊 Testing Analytics Trends...")
        
        success, response = self.run_test(
            "Analytics Trends",
            "GET", "/api/analytics/trends",
            200
        )
        
        if success and response:
            trends = response.get('trends', [])
            self.log_test("Analytics Trends", True, f"Retrieved {len(trends)} trend data points")
        else:
            self.log_test("Analytics Trends", False, "Trends endpoint failed")

    def run_all_tests(self):
        """Run all E-Skimming protection tests"""
        print("🛡️ Starting E-Skimming Protection Platform Tests")
        print("=" * 60)
        
        # Test all endpoints and features
        self.test_root_endpoint()
        self.test_e_skimming_detection()
        self.test_payment_security_features()
        self.test_merchant_compliance_scanning()
        self.test_compliance_dashboard()
        self.test_enhanced_statistics()
        self.test_bulk_scanning_with_e_skimming()
        self.test_campaign_detection()
        self.test_analytics_trends()
        
        # Print summary
        print("\n" + "=" * 60)
        print("🏁 TEST SUMMARY")
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
    tester = ESkimmingProtectionTester()
    
    try:
        success = tester.run_all_tests()
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\n\n⚠️ Tests interrupted by user")
        return 1
    except Exception as e:
        print(f"\n\n💥 Test execution failed: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())