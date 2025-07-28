#!/usr/bin/env python3

import sys
import os
sys.path.append('/app')

from backend_test import ESkimmingProtectionTester

def main():
    """Run only the Mashreq Bank SSL test"""
    tester = ESkimmingProtectionTester()
    
    print("🏦 Running Mashreq Bank SSL Analysis Test")
    print("=" * 50)
    
    try:
        tester.test_mashreqbank_ssl_analysis()
        
        # Print summary
        print(f"\nTests Run: {tester.tests_run}")
        print(f"Tests Passed: {tester.tests_passed}")
        print(f"Tests Failed: {tester.tests_run - tester.tests_passed}")
        
        # Print failed tests
        failed_tests = [test for test in tester.test_results if not test['passed']]
        if failed_tests:
            print(f"\n❌ FAILED TESTS ({len(failed_tests)}):")
            for test in failed_tests:
                print(f"  - {test['test_name']}: {test['details']}")
        
        return 0
        
    except Exception as e:
        print(f"Test execution failed: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())