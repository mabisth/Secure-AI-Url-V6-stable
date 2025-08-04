#!/usr/bin/env python3

import requests
import json
import sys
from datetime import datetime

class AuthenticationTester:
    def __init__(self, base_url="https://f0b72e9d-ad12-4eb9-88f4-9c6ff13f98bd.preview.emergentagent.com"):
        self.base_url = base_url
        self.tests_run = 0
        self.tests_passed = 0

    def log_test(self, name: str, passed: bool, details: str = ""):
        """Log test result"""
        self.tests_run += 1
        if passed:
            self.tests_passed += 1
        
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
            if method == 'POST':
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

    def test_authentication_password_change(self):
        """Test Authentication System - Focus on password change verification"""
        print("\n" + "="*80)
        print("🔐 AUTHENTICATION SYSTEM - PASSWORD CHANGE VERIFICATION")
        print("🎯 REVIEW REQUEST: Verifying superuser 'ohm' password changed from 'Namah1!!Sivaya' to 'admin'")
        print("="*80)
        
        # Test 1: NEW PASSWORD LOGIN - Should work with "admin"
        print("\n🔍 Test 1: NEW PASSWORD LOGIN - Username 'ohm' with password 'admin'")
        success, response = self.run_test(
            "✅ NEW PASSWORD LOGIN - Username 'ohm' with password 'admin'",
            "POST", "/api/auth/login",
            200,
            data={
                "username": "ohm",
                "password": "admin"
            }
        )
        
        session_token = None
        if success and response:
            user_id = response.get('user_id')
            username = response.get('username')
            role = response.get('role')
            session_token = response.get('session_token')
            message = response.get('message')
            
            print(f"    Response: {json.dumps(response, indent=2)}")
            
            # Verify all required fields are present
            required_fields = ['user_id', 'username', 'role', 'session_token']
            missing_fields = [field for field in required_fields if not response.get(field)]
            
            if not missing_fields:
                self.log_test("✅ NEW PASSWORD - Login Response Fields", True, 
                            f"All required fields present: user_id={user_id}, username={username}, role={role}")
            else:
                self.log_test("❌ NEW PASSWORD - Login Response Fields", False, 
                            f"Missing fields: {missing_fields}")
            
            # Verify role is super_admin
            if role == "super_admin":
                self.log_test("✅ NEW PASSWORD - Super Admin Role", True, f"Role: {role}")
            else:
                self.log_test("❌ NEW PASSWORD - Super Admin Role", False, f"Expected super_admin, got: {role}")
            
            # Verify username is correct
            if username == "ohm":
                self.log_test("✅ NEW PASSWORD - Username Verification", True, f"Username: {username}")
            else:
                self.log_test("❌ NEW PASSWORD - Username Verification", False, f"Expected ohm, got: {username}")
            
            # Verify session token is generated
            if session_token:
                self.log_test("✅ NEW PASSWORD - Session Token Generated", True, f"Session token: {session_token[:20]}...")
            else:
                self.log_test("❌ NEW PASSWORD - Session Token Generated", False, "No session token provided")
        else:
            self.log_test("❌ CRITICAL - NEW PASSWORD LOGIN FAILED", False, 
                        "Login with new password 'admin' should work but failed")
        
        # Test 2: OLD PASSWORD LOGIN - Should fail with 401 for "Namah1!!Sivaya"
        print("\n🔍 Test 2: OLD PASSWORD LOGIN - Username 'ohm' with password 'Namah1!!Sivaya'")
        success, response = self.run_test(
            "❌ OLD PASSWORD LOGIN - Username 'ohm' with password 'Namah1!!Sivaya'",
            "POST", "/api/auth/login",
            401,
            data={
                "username": "ohm",
                "password": "Namah1!!Sivaya"
            }
        )
        
        if success:
            self.log_test("✅ OLD PASSWORD - Correctly Rejected", True, 
                        "Old password 'Namah1!!Sivaya' correctly rejected with 401")
        else:
            self.log_test("❌ CRITICAL - OLD PASSWORD STILL WORKS", False, 
                        "Old password 'Namah1!!Sivaya' should be rejected with 401 but wasn't")
        
        # Test 3: Verify Response Structure for Successful Login
        print("\n🔍 Test 3: Password Change Verification Summary")
        if session_token:
            self.log_test("🎉 PASSWORD CHANGE VERIFICATION COMPLETE", True, 
                        "Password successfully changed from 'Namah1!!Sivaya' to 'admin' - Authentication working correctly")
        else:
            self.log_test("❌ PASSWORD CHANGE VERIFICATION FAILED", False, 
                        "Password change verification failed - new password login did not work")
        
        # Test 4: Additional Invalid Login Tests
        print("\n🔍 Test 4: Additional Security Validation")
        success, response = self.run_test(
            "Invalid Login - Wrong Username",
            "POST", "/api/auth/login",
            401,
            data={
                "username": "wronguser",
                "password": "admin"
            }
        )
        
        if success:
            self.log_test("Wrong Username Rejection", True, "Invalid username correctly rejected with 401")
        else:
            self.log_test("Wrong Username Rejection", False, "Wrong username should return 401")
        
        # Test 5: Empty Credentials
        success, response = self.run_test(
            "Invalid Login - Empty Credentials",
            "POST", "/api/auth/login",
            401,
            data={
                "username": "",
                "password": ""
            }
        )
        
        if success:
            self.log_test("Empty Credentials Rejection", True, "Empty credentials correctly rejected with 401")
        else:
            self.log_test("Empty Credentials Rejection", False, "Empty credentials should return 401")
        
        # Test 6: Logout (POST /api/auth/logout)
        print("\n🔍 Test 5: Logout Functionality")
        if session_token:
            success, response = self.run_test(
                "User Logout",
                "POST", "/api/auth/logout",
                200,
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': f'Bearer {session_token}'
                }
            )
            
            if success:
                self.log_test("Logout Success", True, "User logout successful")
            else:
                self.log_test("Logout Success", False, "Logout failed")
        else:
            self.log_test("Logout Test", False, "Cannot test logout - no session token from login")

    def print_summary(self):
        """Print test summary"""
        print("\n" + "="*80)
        print("📊 AUTHENTICATION TEST SUMMARY")
        print("="*80)
        print(f"Total Tests Run: {self.tests_run}")
        print(f"Tests Passed: {self.tests_passed}")
        print(f"Tests Failed: {self.tests_run - self.tests_passed}")
        print(f"Success Rate: {(self.tests_passed/self.tests_run)*100:.1f}%" if self.tests_run > 0 else "No tests run")
        
        if self.tests_passed == self.tests_run:
            print("🎉 ALL TESTS PASSED - Authentication system working correctly!")
        else:
            print("⚠️  Some tests failed - Review the results above")

if __name__ == "__main__":
    tester = AuthenticationTester()
    tester.test_authentication_password_change()
    tester.print_summary()