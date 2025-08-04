#!/usr/bin/env python3

import requests
import json
import sys
import time
import io
import csv
from datetime import datetime
from typing import Dict, List, Any

class BulkScannerTester:
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

    def run_test(self, name: str, method: str, endpoint: str, expected_status: int, data: Dict = None, headers: Dict = None, files: Dict = None) -> tuple:
        """Run a single API test"""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        if headers is None:
            headers = {'Content-Type': 'application/json'} if not files else {}

        print(f"\n🔍 Testing {name}...")
        print(f"    URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, timeout=30)
            elif method == 'POST':
                if files:
                    response = requests.post(url, files=files, data=data, timeout=30)
                else:
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

    def test_bulk_scan_endpoint_standard(self):
        """Test POST /api/scan/bulk with standard scan type"""
        print("\n📊 Testing Bulk Scan Endpoint - Standard Scan Type...")
        
        test_urls = [
            "https://google.com",
            "https://github.com", 
            "https://example.com"
        ]
        
        success, response = self.run_test(
            "Bulk Scan - Standard Type",
            "POST", "/api/scan/bulk",
            200,
            data={
                "urls": test_urls,
                "scan_type": "standard"
            }
        )
        
        if success and response:
            # Verify response structure
            job_id = response.get('job_id')
            status = response.get('status')
            total_urls = response.get('total_urls')
            
            if job_id and status == "started" and total_urls == len(test_urls):
                self.log_test("Bulk Scan Response Structure", True, 
                            f"Job ID: {job_id}, Status: {status}, Total URLs: {total_urls}")
                return job_id
            else:
                self.log_test("Bulk Scan Response Structure", False, 
                            f"Invalid response: {response}")
                return None
        return None

    def test_bulk_scan_endpoint_e_skimming(self):
        """Test POST /api/scan/bulk with e_skimming scan type"""
        print("\n🛡️ Testing Bulk Scan Endpoint - E-Skimming Scan Type...")
        
        test_urls = [
            "https://stripe.com",
            "https://paypal.com"
        ]
        
        success, response = self.run_test(
            "Bulk Scan - E-Skimming Type",
            "POST", "/api/scan/bulk",
            200,
            data={
                "urls": test_urls,
                "scan_type": "e_skimming"
            }
        )
        
        if success and response:
            job_id = response.get('job_id')
            status = response.get('status')
            total_urls = response.get('total_urls')
            
            if job_id and status == "started" and total_urls == len(test_urls):
                self.log_test("E-Skimming Bulk Scan Response", True, 
                            f"Job ID: {job_id}, Status: {status}, Total URLs: {total_urls}")
                return job_id
            else:
                self.log_test("E-Skimming Bulk Scan Response", False, 
                            f"Invalid response: {response}")
                return None
        return None

    def test_bulk_scan_endpoint_payment_gateway(self):
        """Test POST /api/scan/bulk with payment_gateway scan type"""
        print("\n💳 Testing Bulk Scan Endpoint - Payment Gateway Scan Type...")
        
        test_urls = [
            "https://checkout.stripe.com",
            "https://www.paypal.com/checkout"
        ]
        
        success, response = self.run_test(
            "Bulk Scan - Payment Gateway Type",
            "POST", "/api/scan/bulk",
            200,
            data={
                "urls": test_urls,
                "scan_type": "payment_gateway"
            }
        )
        
        if success and response:
            job_id = response.get('job_id')
            status = response.get('status')
            total_urls = response.get('total_urls')
            
            if job_id and status == "started" and total_urls == len(test_urls):
                self.log_test("Payment Gateway Bulk Scan Response", True, 
                            f"Job ID: {job_id}, Status: {status}, Total URLs: {total_urls}")
                return job_id
            else:
                self.log_test("Payment Gateway Bulk Scan Response", False, 
                            f"Invalid response: {response}")
                return None
        return None

    def test_bulk_scan_endpoint_comprehensive(self):
        """Test POST /api/scan/bulk with comprehensive scan type"""
        print("\n🔍 Testing Bulk Scan Endpoint - Comprehensive Scan Type...")
        
        test_urls = [
            "https://microsoft.com",
            "https://apple.com"
        ]
        
        success, response = self.run_test(
            "Bulk Scan - Comprehensive Type",
            "POST", "/api/scan/bulk",
            200,
            data={
                "urls": test_urls,
                "scan_type": "comprehensive"
            }
        )
        
        if success and response:
            job_id = response.get('job_id')
            status = response.get('status')
            total_urls = response.get('total_urls')
            
            if job_id and status == "started" and total_urls == len(test_urls):
                self.log_test("Comprehensive Bulk Scan Response", True, 
                            f"Job ID: {job_id}, Status: {status}, Total URLs: {total_urls}")
                return job_id
            else:
                self.log_test("Comprehensive Bulk Scan Response", False, 
                            f"Invalid response: {response}")
                return None
        return None

    def test_bulk_status_endpoint(self, job_id: str):
        """Test GET /api/scan/bulk/{job_id} for status tracking"""
        if not job_id:
            self.log_test("Bulk Status Check", False, "No job ID provided")
            return None
            
        print(f"\n📈 Testing Bulk Status Endpoint for Job: {job_id}...")
        
        # Wait a moment for processing to start
        time.sleep(2)
        
        success, response = self.run_test(
            f"Bulk Status Check - {job_id[:8]}",
            "GET", f"/api/scan/bulk/{job_id}",
            200
        )
        
        if success and response:
            # Verify status response structure
            required_fields = ['job_id', 'total_urls', 'processed_urls', 'status', 'results']
            missing_fields = [field for field in required_fields if field not in response]
            
            if not missing_fields:
                job_status = response.get('status')
                processed_urls = response.get('processed_urls', 0)
                total_urls = response.get('total_urls', 0)
                results_count = len(response.get('results', []))
                
                self.log_test("Bulk Status Response Structure", True, 
                            f"Status: {job_status}, Progress: {processed_urls}/{total_urls}, Results: {results_count}")
                return response
            else:
                self.log_test("Bulk Status Response Structure", False, 
                            f"Missing fields: {missing_fields}")
                return None
        return None

    def test_bulk_status_invalid_job_id(self):
        """Test GET /api/scan/bulk/{job_id} with invalid job ID"""
        print("\n❌ Testing Bulk Status Endpoint - Invalid Job ID...")
        
        invalid_job_id = "invalid-job-id-12345"
        
        success, response = self.run_test(
            "Bulk Status - Invalid Job ID",
            "GET", f"/api/scan/bulk/{invalid_job_id}",
            404
        )
        
        if success:
            self.log_test("Invalid Job ID Handling", True, "Correctly returned 404 for invalid job ID")
        else:
            self.log_test("Invalid Job ID Handling", False, "Did not handle invalid job ID correctly")

    def test_bulk_processing_with_error_handling(self):
        """Test bulk processing with URLs that will cause errors"""
        print("\n⚠️ Testing Bulk Processing Error Handling...")
        
        test_urls = [
            "https://google.com",  # Valid URL
            "https://this-domain-definitely-does-not-exist-12345.com",  # Invalid URL
            "invalid-url-format",  # Malformed URL
            "https://github.com"  # Valid URL
        ]
        
        success, response = self.run_test(
            "Bulk Scan - Error Handling Test",
            "POST", "/api/scan/bulk",
            200,
            data={
                "urls": test_urls,
                "scan_type": "standard"
            }
        )
        
        if success and response:
            job_id = response.get('job_id')
            if job_id:
                # Wait for processing to complete
                time.sleep(10)
                
                # Check final status
                status_success, status_response = self.run_test(
                    "Bulk Error Handling - Final Status",
                    "GET", f"/api/scan/bulk/{job_id}",
                    200
                )
                
                if status_success and status_response:
                    results = status_response.get('results', [])
                    error_results = [r for r in results if 'error' in r]
                    success_results = [r for r in results if 'error' not in r]
                    
                    self.log_test("Bulk Error Handling Results", True, 
                                f"Total: {len(results)}, Errors: {len(error_results)}, Success: {len(success_results)}")
                    
                    # Verify error results have proper structure
                    for error_result in error_results:
                        if 'url' in error_result and 'error' in error_result:
                            self.log_test(f"Error Result Structure - {error_result['url'][:30]}", True, 
                                        f"Error: {error_result['error'][:50]}")
                        else:
                            self.log_test(f"Error Result Structure", False, 
                                        f"Missing required fields in error result: {error_result}")
                    
                    return job_id
        return None

    def test_csv_upload_functionality(self):
        """Test POST /api/scan/bulk/upload with CSV file uploads"""
        print("\n📄 Testing CSV Upload Functionality...")
        
        # Create test CSV content
        csv_content = """https://google.com
https://github.com
https://example.com
https://microsoft.com"""
        
        # Create CSV file-like object
        csv_file = io.StringIO(csv_content)
        csv_bytes = io.BytesIO(csv_content.encode('utf-8'))
        
        files = {
            'file': ('test_urls.csv', csv_bytes, 'text/csv')
        }
        
        data = {
            'scan_type': 'standard'
        }
        
        success, response = self.run_test(
            "CSV Upload - Standard Scan",
            "POST", "/api/scan/bulk/upload",
            200,
            data=data,
            files=files
        )
        
        if success and response:
            job_id = response.get('job_id')
            status = response.get('status')
            total_urls = response.get('total_urls')
            
            if job_id and status == "started" and total_urls == 4:
                self.log_test("CSV Upload Response Structure", True, 
                            f"Job ID: {job_id}, Status: {status}, Total URLs: {total_urls}")
                return job_id
            else:
                self.log_test("CSV Upload Response Structure", False, 
                            f"Invalid response: {response}")
                return None
        return None

    def test_csv_upload_with_e_skimming_scan_type(self):
        """Test CSV upload with e_skimming scan type"""
        print("\n🛡️ Testing CSV Upload - E-Skimming Scan Type...")
        
        csv_content = """https://stripe.com
https://paypal.com
https://checkout.example.com"""
        
        csv_bytes = io.BytesIO(csv_content.encode('utf-8'))
        
        files = {
            'file': ('payment_urls.csv', csv_bytes, 'text/csv')
        }
        
        data = {
            'scan_type': 'e_skimming'
        }
        
        success, response = self.run_test(
            "CSV Upload - E-Skimming Scan",
            "POST", "/api/scan/bulk/upload",
            200,
            data=data,
            files=files
        )
        
        if success and response:
            job_id = response.get('job_id')
            status = response.get('status')
            total_urls = response.get('total_urls')
            
            if job_id and status == "started" and total_urls == 3:
                self.log_test("CSV E-Skimming Upload Response", True, 
                            f"Job ID: {job_id}, Status: {status}, Total URLs: {total_urls}")
                return job_id
            else:
                self.log_test("CSV E-Skimming Upload Response", False, 
                            f"Invalid response: {response}")
                return None
        return None

    def test_csv_upload_error_handling(self):
        """Test CSV upload error handling for invalid files"""
        print("\n❌ Testing CSV Upload Error Handling...")
        
        # Test with non-CSV file
        txt_content = "This is not a CSV file"
        txt_bytes = io.BytesIO(txt_content.encode('utf-8'))
        
        files = {
            'file': ('test.txt', txt_bytes, 'text/plain')
        }
        
        data = {
            'scan_type': 'standard'
        }
        
        success, response = self.run_test(
            "CSV Upload - Invalid File Type",
            "POST", "/api/scan/bulk/upload",
            400,
            data=data,
            files=files
        )
        
        if success:
            self.log_test("Invalid File Type Handling", True, "Correctly rejected non-CSV file")
        
        # Test with empty CSV
        empty_csv = io.BytesIO(b"")
        
        files = {
            'file': ('empty.csv', empty_csv, 'text/csv')
        }
        
        success, response = self.run_test(
            "CSV Upload - Empty File",
            "POST", "/api/scan/bulk/upload",
            400,
            data=data,
            files=files
        )
        
        if success:
            self.log_test("Empty CSV Handling", True, "Correctly rejected empty CSV file")

    def test_export_functionality_csv(self, job_id: str):
        """Test GET /api/scan/bulk/{job_id}/export for CSV export"""
        if not job_id:
            self.log_test("CSV Export Test", False, "No job ID provided")
            return
            
        print(f"\n📊 Testing CSV Export for Job: {job_id}...")
        
        # Wait for job to complete
        max_wait = 30  # 30 seconds max wait
        wait_time = 0
        job_completed = False
        
        while wait_time < max_wait:
            status_success, status_response = self.run_test(
                f"Export Wait - Job Status Check",
                "GET", f"/api/scan/bulk/{job_id}",
                200
            )
            
            if status_success and status_response:
                if status_response.get('status') == 'completed':
                    job_completed = True
                    break
            
            time.sleep(2)
            wait_time += 2
        
        if not job_completed:
            self.log_test("CSV Export - Job Completion Wait", False, 
                        f"Job did not complete within {max_wait} seconds")
            return
        
        # Test CSV export
        success, response = self.run_test(
            f"CSV Export - {job_id[:8]}",
            "GET", f"/api/scan/bulk/{job_id}/export?format=csv",
            200
        )
        
        if success:
            self.log_test("CSV Export Success", True, "CSV export endpoint responded successfully")
        else:
            self.log_test("CSV Export Success", False, "CSV export failed")

    def test_export_functionality_json(self, job_id: str):
        """Test GET /api/scan/bulk/{job_id}/export for JSON export"""
        if not job_id:
            self.log_test("JSON Export Test", False, "No job ID provided")
            return
            
        print(f"\n📋 Testing JSON Export for Job: {job_id}...")
        
        success, response = self.run_test(
            f"JSON Export - {job_id[:8]}",
            "GET", f"/api/scan/bulk/{job_id}/export?format=json",
            200
        )
        
        if success:
            self.log_test("JSON Export Success", True, "JSON export endpoint responded successfully")
        else:
            self.log_test("JSON Export Success", False, "JSON export failed")

    def test_export_with_incomplete_job(self):
        """Test export functionality with incomplete job"""
        print("\n⏳ Testing Export with Incomplete Job...")
        
        # Start a job but don't wait for completion
        test_urls = ["https://google.com", "https://github.com"]
        
        success, response = self.run_test(
            "Export Test - Job Creation",
            "POST", "/api/scan/bulk",
            200,
            data={
                "urls": test_urls,
                "scan_type": "standard"
            }
        )
        
        if success and response:
            job_id = response.get('job_id')
            if job_id:
                # Immediately try to export (should fail)
                export_success, export_response = self.run_test(
                    "Export - Incomplete Job",
                    "GET", f"/api/scan/bulk/{job_id}/export?format=csv",
                    400
                )
                
                if export_success:
                    self.log_test("Incomplete Job Export Handling", True, 
                                "Correctly rejected export of incomplete job")
                else:
                    self.log_test("Incomplete Job Export Handling", False, 
                                "Did not handle incomplete job export correctly")

    def test_progress_updates(self):
        """Test that progress updates work correctly during bulk processing"""
        print("\n📈 Testing Progress Updates During Bulk Processing...")
        
        # Use more URLs to have time to check progress
        test_urls = [
            "https://google.com",
            "https://github.com",
            "https://microsoft.com",
            "https://apple.com",
            "https://amazon.com",
            "https://facebook.com"
        ]
        
        success, response = self.run_test(
            "Progress Test - Job Creation",
            "POST", "/api/scan/bulk",
            200,
            data={
                "urls": test_urls,
                "scan_type": "standard"
            }
        )
        
        if success and response:
            job_id = response.get('job_id')
            if job_id:
                # Check progress multiple times
                progress_checks = []
                
                for i in range(5):  # Check 5 times over 10 seconds
                    time.sleep(2)
                    
                    status_success, status_response = self.run_test(
                        f"Progress Check {i+1}",
                        "GET", f"/api/scan/bulk/{job_id}",
                        200
                    )
                    
                    if status_success and status_response:
                        processed = status_response.get('processed_urls', 0)
                        total = status_response.get('total_urls', 0)
                        status = status_response.get('status', 'unknown')
                        
                        progress_checks.append({
                            'check': i+1,
                            'processed': processed,
                            'total': total,
                            'status': status
                        })
                
                # Analyze progress
                if progress_checks:
                    final_check = progress_checks[-1]
                    initial_check = progress_checks[0]
                    
                    if final_check['processed'] >= initial_check['processed']:
                        self.log_test("Progress Updates Working", True, 
                                    f"Progress increased from {initial_check['processed']} to {final_check['processed']}")
                    else:
                        self.log_test("Progress Updates Working", False, 
                                    f"Progress did not increase properly")
                    
                    # Check if job completed
                    if final_check['status'] == 'completed':
                        self.log_test("Job Completion", True, 
                                    f"Job completed successfully with {final_check['processed']}/{final_check['total']} URLs")
                    else:
                        self.log_test("Job Completion", True, 
                                    f"Job in progress: {final_check['status']} - {final_check['processed']}/{final_check['total']}")
                
                return job_id
        return None

    def test_scan_type_parameter_handling(self):
        """Test that scan_type parameter is properly handled and passed through"""
        print("\n🔧 Testing Scan Type Parameter Handling...")
        
        scan_types = ["standard", "e_skimming", "payment_gateway", "comprehensive"]
        test_url = "https://example.com"
        
        for scan_type in scan_types:
            success, response = self.run_test(
                f"Scan Type Test - {scan_type}",
                "POST", "/api/scan/bulk",
                200,
                data={
                    "urls": [test_url],
                    "scan_type": scan_type
                }
            )
            
            if success and response:
                job_id = response.get('job_id')
                if job_id:
                    # Wait a moment then check job details
                    time.sleep(3)
                    
                    status_success, status_response = self.run_test(
                        f"Scan Type Verification - {scan_type}",
                        "GET", f"/api/scan/bulk/{job_id}",
                        200
                    )
                    
                    if status_success and status_response:
                        job_scan_type = status_response.get('scan_type')
                        if job_scan_type == scan_type:
                            self.log_test(f"Scan Type Persistence - {scan_type}", True, 
                                        f"Scan type correctly stored: {job_scan_type}")
                        else:
                            self.log_test(f"Scan Type Persistence - {scan_type}", False, 
                                        f"Expected {scan_type}, got {job_scan_type}")

    def test_results_serialization(self):
        """Test that results are properly serialized (dict/model_dump handling)"""
        print("\n🔄 Testing Results Serialization...")
        
        test_urls = ["https://google.com", "https://github.com"]
        
        success, response = self.run_test(
            "Serialization Test - Job Creation",
            "POST", "/api/scan/bulk",
            200,
            data={
                "urls": test_urls,
                "scan_type": "standard"
            }
        )
        
        if success and response:
            job_id = response.get('job_id')
            if job_id:
                # Wait for completion
                time.sleep(8)
                
                status_success, status_response = self.run_test(
                    "Serialization Test - Results Check",
                    "GET", f"/api/scan/bulk/{job_id}",
                    200
                )
                
                if status_success and status_response:
                    results = status_response.get('results', [])
                    
                    if results:
                        # Check that results are properly serialized dictionaries
                        for i, result in enumerate(results):
                            if isinstance(result, dict):
                                # Check for expected fields
                                expected_fields = ['url', 'risk_score', 'is_malicious', 'threat_category', 'scan_timestamp']
                                missing_fields = [field for field in expected_fields if field not in result]
                                
                                if not missing_fields:
                                    self.log_test(f"Result Serialization - URL {i+1}", True, 
                                                f"All expected fields present: {list(result.keys())[:5]}")
                                else:
                                    self.log_test(f"Result Serialization - URL {i+1}", False, 
                                                f"Missing fields: {missing_fields}")
                            else:
                                self.log_test(f"Result Serialization - URL {i+1}", False, 
                                            f"Result is not a dictionary: {type(result)}")
                    else:
                        self.log_test("Results Serialization", False, "No results found")

    def run_all_bulk_scanner_tests(self):
        """Run all bulk scanner functionality tests"""
        print("🚀 Starting Bulk Scanner Functionality Tests")
        print("=" * 60)
        
        # Test 1: Bulk Scan Endpoint Testing
        print("\n📊 TESTING BULK SCAN ENDPOINTS")
        print("-" * 40)
        job_id_standard = self.test_bulk_scan_endpoint_standard()
        job_id_e_skimming = self.test_bulk_scan_endpoint_e_skimming()
        job_id_payment_gateway = self.test_bulk_scan_endpoint_payment_gateway()
        job_id_comprehensive = self.test_bulk_scan_endpoint_comprehensive()
        
        # Test 2: Bulk Status Endpoint Testing
        print("\n📈 TESTING BULK STATUS ENDPOINTS")
        print("-" * 40)
        if job_id_standard:
            self.test_bulk_status_endpoint(job_id_standard)
        self.test_bulk_status_invalid_job_id()
        
        # Test 3: Bulk Processing Testing
        print("\n⚙️ TESTING BULK PROCESSING")
        print("-" * 40)
        job_id_error_test = self.test_bulk_processing_with_error_handling()
        self.test_progress_updates()
        self.test_scan_type_parameter_handling()
        self.test_results_serialization()
        
        # Test 4: CSV Upload Testing
        print("\n📄 TESTING CSV UPLOAD FUNCTIONALITY")
        print("-" * 40)
        job_id_csv = self.test_csv_upload_functionality()
        job_id_csv_e_skimming = self.test_csv_upload_with_e_skimming_scan_type()
        self.test_csv_upload_error_handling()
        
        # Test 5: Export Functionality
        print("\n📊 TESTING EXPORT FUNCTIONALITY")
        print("-" * 40)
        if job_id_csv:
            self.test_export_functionality_csv(job_id_csv)
            self.test_export_functionality_json(job_id_csv)
        self.test_export_with_incomplete_job()
        
        # Print summary
        print("\n" + "=" * 60)
        print("🏁 BULK SCANNER TEST SUMMARY")
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
            print(f"\n✅ ALL TESTS PASSED!")
        
        # Print test categories summary
        categories = {
            'Bulk Scan Endpoints': [t for t in self.test_results if 'Bulk Scan' in t['test_name']],
            'Status Endpoints': [t for t in self.test_results if 'Status' in t['test_name']],
            'Processing Tests': [t for t in self.test_results if any(keyword in t['test_name'] for keyword in ['Progress', 'Error Handling', 'Serialization', 'Scan Type'])],
            'CSV Upload Tests': [t for t in self.test_results if 'CSV' in t['test_name']],
            'Export Tests': [t for t in self.test_results if 'Export' in t['test_name']]
        }
        
        print(f"\n📊 TEST CATEGORIES BREAKDOWN:")
        for category, tests in categories.items():
            passed = len([t for t in tests if t['passed']])
            total = len(tests)
            if total > 0:
                print(f"  {category}: {passed}/{total} ({(passed/total*100):.1f}%)")
        
        return self.tests_passed == self.tests_run

def main():
    """Main test execution"""
    tester = BulkScannerTester()
    
    try:
        success = tester.run_all_bulk_scanner_tests()
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\n\n⚠️ Tests interrupted by user")
        return 1
    except Exception as e:
        print(f"\n\n💥 Test execution failed: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())