#!/usr/bin/env python3

import requests
import json
import sys
from datetime import datetime

class ReviewRequestTester:
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

    def test_authentication_issues(self):
        """Test authentication issues mentioned in review request"""
        print("\n🔐 TESTING AUTHENTICATION ISSUES FROM REVIEW REQUEST")
        print("=" * 60)
        
        # Test 1: Login with specific credentials from review request
        print("\n1️⃣ Testing Login with ohm/Namah1!!Sivaya")
        login_data = {
            "username": "ohm",
            "password": "Namah1!!Sivaya"
        }
        
        success, response = self.run_test(
            "Login with ohm/Namah1!!Sivaya",
            "POST", "/api/auth/login",
            200,
            data=login_data
        )
        
        if success and response:
            # Check for proper login response structure
            user_id = response.get('user_id')
            username = response.get('username')
            role = response.get('role')
            session_token = response.get('session_token')
            message = response.get('message')
            
            print(f"    📋 Login Response Details:")
            print(f"       Message: {message}")
            print(f"       User ID: {user_id}")
            print(f"       Username: {username}")
            print(f"       Role: {role}")
            print(f"       Session Token: {'Present' if session_token else 'Missing'}")
            
            if user_id and username == "ohm" and role and session_token:
                self.log_test("Login Response Structure Complete", True, 
                            f"All required fields present: user_id, username={username}, role={role}, session_token")
            else:
                self.log_test("Login Response Structure Complete", False, 
                            f"Missing fields in response: {response}")
        
        # Test 2: Invalid login attempts to verify proper error handling
        print("\n2️⃣ Testing Invalid Login Attempts")
        invalid_credentials = [
            {"username": "ohm", "password": "wrongpassword", "name": "Wrong Password"},
            {"username": "wronguser", "password": "Namah1!!Sivaya", "name": "Wrong Username"},
            {"username": "", "password": "", "name": "Empty Credentials"},
        ]
        
        for invalid_cred in invalid_credentials:
            success, response = self.run_test(
                f"Invalid Login - {invalid_cred['name']}",
                "POST", "/api/auth/login",
                401,  # Expect 401 for invalid credentials
                data={"username": invalid_cred["username"], "password": invalid_cred["password"]}
            )
            
            if success:
                self.log_test(f"Invalid Login Properly Rejected - {invalid_cred['name']}", True, 
                            "Invalid credentials properly rejected with 401")
            else:
                self.log_test(f"Invalid Login Properly Rejected - {invalid_cred['name']}", False, 
                            "Invalid credentials not properly rejected")
        
        # Test 3: Logout endpoint accessibility
        print("\n3️⃣ Testing Logout Endpoint")
        success, response = self.run_test(
            "Logout Endpoint Accessibility",
            "POST", "/api/auth/logout",
            200
        )
        
        if success:
            self.log_test("Logout Functionality Working", True, "Logout endpoint accessible and responding")
        else:
            self.log_test("Logout Functionality Working", False, "Logout endpoint not working")

    def test_scan_functionality_issues(self):
        """Test scan functionality issues mentioned in review request"""
        print("\n🔍 TESTING SCAN FUNCTIONALITY ISSUES FROM REVIEW REQUEST")
        print("=" * 60)
        
        # Test different scan types mentioned in review request
        scan_types = ["basic", "detailed", "e_skimming"]
        test_url = "https://www.mashreqbank.com"  # Use the specific URL mentioned in review
        
        print(f"\n🎯 Testing scan types with {test_url}")
        
        for scan_type in scan_types:
            print(f"\n{scan_type.upper()} SCAN TYPE TESTING")
            print("-" * 40)
            
            success, response = self.run_test(
                f"{scan_type.upper()} Scan Type",
                "POST", "/api/scan",
                200,
                data={
                    "url": test_url,
                    "scan_type": scan_type
                }
            )
            
            if success and response:
                # Check for comprehensive scan results
                analysis_details = response.get('analysis_details', {})
                detailed_report = analysis_details.get('detailed_report', {})
                
                # Count available analysis components
                components = {
                    'Domain Analysis': response.get('threat_category') is not None,
                    'DNS Availability': detailed_report.get('dns_availability_check') is not None,
                    'SSL Analysis': detailed_report.get('ssl_detailed_analysis') is not None,
                    'Email Security': detailed_report.get('email_security_records') is not None,
                    'Threat Intelligence': detailed_report.get('comprehensive_threat_assessment') is not None,
                    'ML Predictions': response.get('ml_predictions') is not None,
                    'Content Analysis': analysis_details.get('content_analysis') is not None,
                    'Technical Details': analysis_details.get('technical_details') is not None,
                    'AI Recommendations': response.get('recommendations') is not None
                }
                
                available_components = [name for name, available in components.items() if available]
                missing_components = [name for name, available in components.items() if not available]
                
                print(f"    📊 Analysis Components for {scan_type.upper()}:")
                print(f"       Available ({len(available_components)}): {available_components}")
                print(f"       Missing ({len(missing_components)}): {missing_components}")
                
                self.log_test(f"{scan_type.upper()} Scan Components Available", True, 
                            f"Available: {len(available_components)}/9 components")
                
                # Detailed analysis of each component
                self.analyze_domain_analysis(response, scan_type)
                self.analyze_dns_availability(detailed_report, scan_type)
                self.analyze_ssl_analysis(detailed_report, scan_type)
                self.analyze_email_security(detailed_report, scan_type)
                self.analyze_threat_intelligence(detailed_report, scan_type)
                self.analyze_ml_predictions(response, scan_type)
                self.analyze_ai_recommendations(response, scan_type)
                
                # Check if detailed scan type provides enhanced results
                if scan_type == "detailed":
                    self.verify_detailed_scan_enhancement(detailed_report)
            else:
                self.log_test(f"{scan_type.upper()} Scan Failed", False, 
                            f"Scan type {scan_type} not working")

    def analyze_domain_analysis(self, response, scan_type):
        """Analyze domain analysis component"""
        domain_info = {
            'threat_category': response.get('threat_category'),
            'risk_score': response.get('risk_score'),
            'is_malicious': response.get('is_malicious'),
            'scan_timestamp': response.get('scan_timestamp')
        }
        
        available_info = [key for key, value in domain_info.items() if value is not None]
        
        print(f"    🌐 Domain Analysis ({scan_type}):")
        for key, value in domain_info.items():
            if value is not None:
                print(f"       ✅ {key}: {value}")
            else:
                print(f"       ❌ {key}: Missing")
        
        if len(available_info) >= 3:
            self.log_test(f"Domain Analysis Complete - {scan_type}", True, 
                        f"Available info: {available_info}")
        else:
            self.log_test(f"Domain Analysis Complete - {scan_type}", False, 
                        f"Limited domain info: {available_info}")

    def analyze_dns_availability(self, detailed_report, scan_type):
        """Analyze DNS availability component"""
        dns_check = detailed_report.get('dns_availability_check', {})
        
        if dns_check:
            dns_features = {}
            if dns_check.get('url_online') is not None: 
                dns_features['URL Status'] = dns_check.get('url_online')
            if dns_check.get('dns_resolvers'): 
                dns_features['DNS Resolvers'] = len(dns_check.get('dns_resolvers'))
            if dns_check.get('threat_intelligence_feeds'): 
                dns_features['Threat Feeds'] = len(dns_check.get('threat_intelligence_feeds'))
            if dns_check.get('availability_score') is not None: 
                dns_features['Availability Score'] = dns_check.get('availability_score')
            
            print(f"    🌐 DNS Availability ({scan_type}):")
            for feature, value in dns_features.items():
                print(f"       ✅ {feature}: {value}")
            
            if len(dns_features) >= 3:
                self.log_test(f"DNS Availability Complete - {scan_type}", True, 
                            f"Features: {list(dns_features.keys())}")
            else:
                self.log_test(f"DNS Availability Complete - {scan_type}", False, 
                            f"Limited DNS features: {list(dns_features.keys())}")
        else:
            print(f"    🌐 DNS Availability ({scan_type}): ❌ No data")
            self.log_test(f"DNS Availability Complete - {scan_type}", False, "No DNS availability data")

    def analyze_ssl_analysis(self, detailed_report, scan_type):
        """Analyze SSL analysis component"""
        ssl_analysis = detailed_report.get('ssl_detailed_analysis', {})
        
        if ssl_analysis:
            ssl_features = {}
            if ssl_analysis.get('grade'): 
                ssl_features['SSL Grade'] = ssl_analysis.get('grade')
            if ssl_analysis.get('certificate_info'): 
                ssl_features['Certificate Info'] = "Present"
            if ssl_analysis.get('security_issues'): 
                ssl_features['Security Issues'] = len(ssl_analysis.get('security_issues'))
            if ssl_analysis.get('vulnerabilities'): 
                ssl_features['Vulnerabilities'] = len(ssl_analysis.get('vulnerabilities'))
            if ssl_analysis.get('recommendations'): 
                ssl_features['Recommendations'] = len(ssl_analysis.get('recommendations'))
            
            print(f"    🔒 SSL Analysis ({scan_type}):")
            for feature, value in ssl_features.items():
                print(f"       ✅ {feature}: {value}")
            
            if len(ssl_features) >= 3:
                self.log_test(f"SSL Analysis Complete - {scan_type}", True, 
                            f"Features: {list(ssl_features.keys())}")
            else:
                self.log_test(f"SSL Analysis Complete - {scan_type}", False, 
                            f"Limited SSL features: {list(ssl_features.keys())}")
        else:
            print(f"    🔒 SSL Analysis ({scan_type}): ❌ No data")
            self.log_test(f"SSL Analysis Complete - {scan_type}", False, "No SSL analysis data")

    def analyze_email_security(self, detailed_report, scan_type):
        """Analyze email security component"""
        email_security = detailed_report.get('email_security_records', {})
        
        if email_security:
            email_features = {}
            if email_security.get('spf_status'): 
                email_features['SPF Records'] = email_security.get('spf_status')
            if email_security.get('dmarc_status'): 
                email_features['DMARC Records'] = email_security.get('dmarc_status')
            if email_security.get('dkim_status'): 
                email_features['DKIM Records'] = email_security.get('dkim_status')
            if email_security.get('email_security_score') is not None: 
                email_features['Security Score'] = f"{email_security.get('email_security_score')}/100"
            if email_security.get('recommendations'): 
                email_features['Recommendations'] = len(email_security.get('recommendations'))
            
            print(f"    📧 Email Security ({scan_type}):")
            for feature, value in email_features.items():
                print(f"       ✅ {feature}: {value}")
            
            if len(email_features) >= 3:
                self.log_test(f"Email Security Complete - {scan_type}", True, 
                            f"Features: {list(email_features.keys())}")
            else:
                self.log_test(f"Email Security Complete - {scan_type}", False, 
                            f"Limited email features: {list(email_features.keys())}")
        else:
            print(f"    📧 Email Security ({scan_type}): ❌ No data")
            self.log_test(f"Email Security Complete - {scan_type}", False, "No email security data")

    def analyze_threat_intelligence(self, detailed_report, scan_type):
        """Analyze threat intelligence component"""
        threat_assessment = detailed_report.get('comprehensive_threat_assessment', {})
        
        if threat_assessment:
            threat_features = {}
            if threat_assessment.get('overall_risk_score') is not None: 
                threat_features['Risk Score'] = f"{threat_assessment.get('overall_risk_score')}/100"
            if threat_assessment.get('malware_detection'): 
                threat_features['Malware Detection'] = threat_assessment.get('malware_detection', {}).get('detected', False)
            if threat_assessment.get('phishing_detection'): 
                threat_features['Phishing Detection'] = threat_assessment.get('phishing_detection', {}).get('detected', False)
            if threat_assessment.get('suspicious_activities'): 
                threat_features['Suspicious Activities'] = len(threat_assessment.get('suspicious_activities'))
            if threat_assessment.get('domain_reputation'): 
                threat_features['Domain Reputation'] = "Present"
            
            print(f"    🛡️ Threat Intelligence ({scan_type}):")
            for feature, value in threat_features.items():
                print(f"       ✅ {feature}: {value}")
            
            if len(threat_features) >= 3:
                self.log_test(f"Threat Intelligence Complete - {scan_type}", True, 
                            f"Features: {list(threat_features.keys())}")
            else:
                self.log_test(f"Threat Intelligence Complete - {scan_type}", False, 
                            f"Limited threat features: {list(threat_features.keys())}")
        else:
            print(f"    🛡️ Threat Intelligence ({scan_type}): ❌ No data")
            self.log_test(f"Threat Intelligence Complete - {scan_type}", False, "No threat intelligence data")

    def analyze_ml_predictions(self, response, scan_type):
        """Analyze ML predictions component"""
        ml_predictions = response.get('ml_predictions', {})
        
        if ml_predictions:
            ml_features = {}
            if ml_predictions.get('phishing_probability') is not None: 
                ml_features['Phishing Probability'] = f"{ml_predictions.get('phishing_probability'):.2f}"
            if ml_predictions.get('malware_probability') is not None: 
                ml_features['Malware Probability'] = f"{ml_predictions.get('malware_probability'):.2f}"
            if ml_predictions.get('e_skimming_probability') is not None: 
                ml_features['E-Skimming Probability'] = f"{ml_predictions.get('e_skimming_probability'):.2f}"
            if ml_predictions.get('confidence_score') is not None: 
                ml_features['Confidence Score'] = f"{ml_predictions.get('confidence_score'):.2f}"
            
            print(f"    🤖 ML Predictions ({scan_type}):")
            for feature, value in ml_features.items():
                print(f"       ✅ {feature}: {value}")
            
            if len(ml_features) >= 2:
                self.log_test(f"ML Predictions Complete - {scan_type}", True, 
                            f"Features: {list(ml_features.keys())}")
            else:
                self.log_test(f"ML Predictions Complete - {scan_type}", False, 
                            f"Limited ML features: {list(ml_features.keys())}")
        else:
            print(f"    🤖 ML Predictions ({scan_type}): ❌ No data")
            self.log_test(f"ML Predictions Complete - {scan_type}", False, "No ML predictions data")

    def analyze_ai_recommendations(self, response, scan_type):
        """Analyze AI recommendations component"""
        recommendations = response.get('recommendations', [])
        
        if recommendations and len(recommendations) > 0:
            print(f"    🎯 AI Recommendations ({scan_type}):")
            for i, rec in enumerate(recommendations[:3], 1):  # Show first 3
                print(f"       {i}. {rec}")
            if len(recommendations) > 3:
                print(f"       ... and {len(recommendations) - 3} more")
            
            self.log_test(f"AI Recommendations Complete - {scan_type}", True, 
                        f"Found {len(recommendations)} recommendations")
        else:
            print(f"    🎯 AI Recommendations ({scan_type}): ❌ No recommendations")
            self.log_test(f"AI Recommendations Complete - {scan_type}", False, "No AI recommendations")

    def verify_detailed_scan_enhancement(self, detailed_report):
        """Verify that detailed scan provides enhanced results"""
        print(f"\n    🔬 DETAILED SCAN ENHANCEMENT VERIFICATION:")
        
        # Detailed scans should have more comprehensive data
        ssl_analysis = detailed_report.get('ssl_detailed_analysis', {})
        email_security = detailed_report.get('email_security_records', {})
        threat_assessment = detailed_report.get('comprehensive_threat_assessment', {})
        
        detailed_features = []
        if ssl_analysis.get('grade'): 
            detailed_features.append("SSL Grading")
            print(f"       ✅ SSL Grading: {ssl_analysis.get('grade')}")
        if ssl_analysis.get('vulnerabilities'): 
            detailed_features.append("SSL Vulnerabilities")
            print(f"       ✅ SSL Vulnerabilities: {len(ssl_analysis.get('vulnerabilities'))} found")
        if email_security.get('email_security_score'): 
            detailed_features.append("Email Security Score")
            print(f"       ✅ Email Security Score: {email_security.get('email_security_score')}/100")
        if threat_assessment.get('overall_risk_score'): 
            detailed_features.append("Risk Assessment")
            print(f"       ✅ Risk Assessment: {threat_assessment.get('overall_risk_score')}/100")
        
        if len(detailed_features) >= 3:
            self.log_test("Detailed Scan Enhancement Verified", True, 
                        f"Enhanced features: {detailed_features}")
        else:
            self.log_test("Detailed Scan Enhancement Verified", False, 
                        f"Limited enhancement: {detailed_features}")

    def test_comprehensive_analysis_requirement(self):
        """Test comprehensive analysis as requested in review"""
        print("\n🎯 TESTING COMPREHENSIVE ANALYSIS REQUIREMENT")
        print("=" * 60)
        
        # Test with the specific URL mentioned in review request
        test_url = "https://www.mashreqbank.com"
        
        print(f"\n🏦 Testing comprehensive analysis for {test_url}")
        
        success, response = self.run_test(
            "Comprehensive Analysis - Mashreq Bank",
            "POST", "/api/scan",
            200,
            data={
                "url": test_url,
                "scan_type": "detailed"
            }
        )
        
        if success and response:
            # Comprehensive analysis checklist from review request
            analysis_checklist = {
                'Domain Analysis': False,
                'DNS Availability': False,
                'SSL Analysis (detailed)': False,
                'Email Security (SPF/DMARC/DKIM)': False,
                'Threat Intelligence': False,
                'ML Predictions': False,
                'Content Analysis': False,
                'Technical Details': False,
                'AI Recommendations': False
            }
            
            # Check each component
            analysis_details = response.get('analysis_details', {})
            detailed_report = analysis_details.get('detailed_report', {})
            
            print(f"\n    📋 COMPREHENSIVE ANALYSIS CHECKLIST:")
            
            # Domain Analysis
            if response.get('threat_category') and response.get('risk_score') is not None:
                analysis_checklist['Domain Analysis'] = True
                print(f"       ✅ Domain Analysis: Category={response.get('threat_category')}, Risk={response.get('risk_score')}")
            else:
                print(f"       ❌ Domain Analysis: Missing")
            
            # DNS Availability
            dns_check = detailed_report.get('dns_availability_check', {})
            if dns_check and dns_check.get('dns_resolvers') and dns_check.get('threat_intelligence_feeds'):
                analysis_checklist['DNS Availability'] = True
                print(f"       ✅ DNS Availability: {len(dns_check.get('dns_resolvers', {}))} resolvers, {len(dns_check.get('threat_intelligence_feeds', {}))} feeds")
            else:
                print(f"       ❌ DNS Availability: Missing or incomplete")
            
            # SSL Analysis (detailed)
            ssl_analysis = detailed_report.get('ssl_detailed_analysis', {})
            if ssl_analysis and ssl_analysis.get('grade'):
                analysis_checklist['SSL Analysis (detailed)'] = True
                print(f"       ✅ SSL Analysis: Grade={ssl_analysis.get('grade')}, Issues={len(ssl_analysis.get('security_issues', []))}")
            else:
                print(f"       ❌ SSL Analysis: Missing or incomplete")
            
            # Email Security
            email_security = detailed_report.get('email_security_records', {})
            if email_security and email_security.get('spf_status') and email_security.get('dmarc_status'):
                analysis_checklist['Email Security (SPF/DMARC/DKIM)'] = True
                print(f"       ✅ Email Security: SPF={email_security.get('spf_status')}, DMARC={email_security.get('dmarc_status')}, Score={email_security.get('email_security_score')}")
            else:
                print(f"       ❌ Email Security: Missing or incomplete")
            
            # Threat Intelligence
            threat_assessment = detailed_report.get('comprehensive_threat_assessment', {})
            if threat_assessment and threat_assessment.get('overall_risk_score') is not None:
                analysis_checklist['Threat Intelligence'] = True
                print(f"       ✅ Threat Intelligence: Risk={threat_assessment.get('overall_risk_score')}, Verdict={threat_assessment.get('verdict')}")
            else:
                print(f"       ❌ Threat Intelligence: Missing")
            
            # ML Predictions
            ml_predictions = response.get('ml_predictions', {})
            if ml_predictions and ml_predictions.get('phishing_probability') is not None:
                analysis_checklist['ML Predictions'] = True
                print(f"       ✅ ML Predictions: Phishing={ml_predictions.get('phishing_probability'):.2f}, Malware={ml_predictions.get('malware_probability'):.2f}")
            else:
                print(f"       ❌ ML Predictions: Missing")
            
            # Content Analysis
            if analysis_details.get('content_analysis') or analysis_details.get('page_content'):
                analysis_checklist['Content Analysis'] = True
                print(f"       ✅ Content Analysis: Present")
            else:
                print(f"       ❌ Content Analysis: Missing")
            
            # Technical Details
            if analysis_details.get('technical_details') or analysis_details.get('whois_info'):
                analysis_checklist['Technical Details'] = True
                print(f"       ✅ Technical Details: Present")
            else:
                print(f"       ❌ Technical Details: Missing")
            
            # AI Recommendations
            recommendations = response.get('recommendations', [])
            if recommendations and len(recommendations) > 0:
                analysis_checklist['AI Recommendations'] = True
                print(f"       ✅ AI Recommendations: {len(recommendations)} recommendations")
            else:
                print(f"       ❌ AI Recommendations: Missing")
            
            # Report results
            completed_analyses = [name for name, completed in analysis_checklist.items() if completed]
            missing_analyses = [name for name, completed in analysis_checklist.items() if not completed]
            
            completion_rate = len(completed_analyses) / len(analysis_checklist) * 100
            
            print(f"\n    📊 ANALYSIS COMPLETION SUMMARY:")
            print(f"       Completion Rate: {completion_rate:.1f}% ({len(completed_analyses)}/{len(analysis_checklist)})")
            print(f"       Working Components: {completed_analyses}")
            if missing_analyses:
                print(f"       Missing Components: {missing_analyses}")
            
            self.log_test("Comprehensive Analysis Completion", True, 
                        f"Completion: {completion_rate:.1f}% ({len(completed_analyses)}/{len(analysis_checklist)})")
            
            # Check if this meets "maximum information" requirement
            if completion_rate >= 80:
                self.log_test("Maximum Information Requirement Met", True, 
                            f"Meets requirement with {completion_rate:.1f}% completion")
            else:
                self.log_test("Maximum Information Requirement Met", False, 
                            f"Does not meet requirement - only {completion_rate:.1f}% completion")

    def run_review_request_tests(self):
        """Run all review request specific tests"""
        print("🎯 REVIEW REQUEST TESTING - SecureURL AI Backend Issues")
        print("=" * 70)
        print("Testing specific issues reported:")
        print("1. Unable to login - Authentication system not working")
        print("2. No detailed analysis - Scan results not comprehensive")
        print("3. Very limited scan output - Missing security components")
        print("4. Need maximum information - All features should work")
        print("=" * 70)
        
        # Test authentication issues
        self.test_authentication_issues()
        
        # Test scan functionality issues
        self.test_scan_functionality_issues()
        
        # Test comprehensive analysis requirement
        self.test_comprehensive_analysis_requirement()
        
        # Print final results
        print("\n" + "=" * 70)
        print("🏁 REVIEW REQUEST TEST SUMMARY")
        print("=" * 70)
        print(f"Total Tests Run: {self.tests_run}")
        print(f"Tests Passed: {self.tests_passed}")
        print(f"Tests Failed: {self.tests_run - self.tests_passed}")
        print(f"Success Rate: {(self.tests_passed / self.tests_run * 100):.1f}%")
        
        # Categorize results
        auth_tests = [test for test in self.test_results if 'Login' in test['test_name'] or 'Logout' in test['test_name']]
        scan_tests = [test for test in self.test_results if 'Scan' in test['test_name'] or 'Analysis' in test['test_name']]
        
        print(f"\n🔐 AUTHENTICATION TESTS: {len([t for t in auth_tests if t['passed']])}/{len(auth_tests)} passed")
        for test in auth_tests:
            status = "✅" if test['passed'] else "❌"
            print(f"  {status} {test['test_name']}")
        
        print(f"\n🔍 SCAN FUNCTIONALITY TESTS: {len([t for t in scan_tests if t['passed']])}/{len(scan_tests)} passed")
        for test in scan_tests:
            status = "✅" if test['passed'] else "❌"
            print(f"  {status} {test['test_name']}")
        
        # Failed tests summary
        failed_tests = [test for test in self.test_results if not test['passed']]
        if failed_tests:
            print(f"\n❌ FAILED TESTS ({len(failed_tests)}):")
            for test in failed_tests:
                print(f"  - {test['test_name']}: {test['details']}")
        
        # Success assessment
        if self.tests_passed == self.tests_run:
            print("\n🎉 ALL REVIEW REQUEST ISSUES RESOLVED!")
            print("✅ Authentication system working correctly")
            print("✅ Detailed analysis providing comprehensive results")
            print("✅ Scan output includes all security components")
            print("✅ Maximum information requirement met")
        else:
            print(f"\n⚠️ {self.tests_run - self.tests_passed} issues still need attention")
            
            # Identify main problem areas
            if any('Login' in test['test_name'] for test in failed_tests):
                print("🔴 Authentication system still has issues")
            if any('Scan' in test['test_name'] or 'Analysis' in test['test_name'] for test in failed_tests):
                print("🔴 Scan functionality still has issues")
            if any('Maximum Information' in test['test_name'] for test in failed_tests):
                print("🔴 Comprehensive analysis requirement not met")
        
        return self.tests_passed == self.tests_run

if __name__ == "__main__":
    tester = ReviewRequestTester()
    success = tester.run_review_request_tests()
    sys.exit(0 if success else 1)