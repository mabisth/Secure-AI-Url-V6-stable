#!/usr/bin/env python3

import requests
import json
import ssl
import socket
import subprocess
from datetime import datetime

def test_mashreq_ssl_direct():
    """Test direct SSL connection to www.mashreqbank.com"""
    print("🔍 Testing Direct SSL Connection to www.mashreqbank.com:443")
    
    domain = "www.mashreqbank.com"
    
    try:
        context = ssl.create_default_context()
        socket.setdefaulttimeout(15)
        
        with socket.create_connection((domain, 443), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                
                print(f"✅ SSL Connection Successful!")
                
                if cert:
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    print(f"   Subject: {subject}")
                    print(f"   Issuer: {issuer}")
                    print(f"   Not After: {cert.get('notAfter', 'Unknown')}")
                    print(f"   Serial Number: {cert.get('serialNumber', 'Unknown')}")
                    
                if cipher:
                    print(f"   Protocol: {cipher[1]}")
                    print(f"   Cipher Suite: {cipher[0]}")
                    
                return True, cert, cipher
                
    except Exception as e:
        print(f"❌ SSL Connection Failed: {str(e)}")
        return False, None, None

def test_mashreq_https_request():
    """Test HTTPS request to www.mashreqbank.com"""
    print("\n🌐 Testing HTTPS Request to https://www.mashreqbank.com")
    
    url = "https://www.mashreqbank.com"
    
    try:
        response = requests.head(url, timeout=15, verify=True, headers={
            'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'
        })
        print(f"✅ HTTPS Request Successful!")
        print(f"   Status Code: {response.status_code}")
        print(f"   Headers: {dict(response.headers)}")
        return True, response
        
    except requests.exceptions.SSLError as e:
        print(f"❌ SSL Error: {str(e)}")
        return False, None
    except Exception as e:
        print(f"❌ Request Failed: {str(e)}")
        return False, None

def test_mashreq_backend_analysis():
    """Test backend SSL analysis for www.mashreqbank.com"""
    print("\n🔧 Testing Backend SSL Analysis")
    
    base_url = "https://f0b72e9d-ad12-4eb9-88f4-9c6ff13f98bd.preview.emergentagent.com"
    url = f"{base_url}/api/scan"
    
    data = {
        "url": "https://www.mashreqbank.com",
        "scan_type": "standard"
    }
    
    try:
        response = requests.post(url, json=data, timeout=60, headers={
            'Content-Type': 'application/json'
        })
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ Backend Analysis Successful!")
            
            # Check SSL analysis
            analysis_details = result.get('analysis_details', {})
            detailed_report = analysis_details.get('detailed_report', {})
            ssl_analysis = detailed_report.get('ssl_detailed_analysis', {})
            
            if ssl_analysis:
                print(f"   SSL Analysis Found:")
                print(f"   - Grade: {ssl_analysis.get('grade', 'Unknown')}")
                print(f"   - Certificate Info: {bool(ssl_analysis.get('certificate_info'))}")
                print(f"   - Security Issues: {len(ssl_analysis.get('security_issues', []))}")
                print(f"   - Vulnerabilities: {len(ssl_analysis.get('vulnerabilities', []))}")
                print(f"   - Error: {ssl_analysis.get('error', 'None')}")
                
                cert_info = ssl_analysis.get('certificate_info', {})
                if cert_info:
                    print(f"   - Subject: {cert_info.get('subject', {})}")
                    print(f"   - Issuer: {cert_info.get('issuer', {})}")
                else:
                    print(f"   - No Certificate Info Found")
            else:
                print(f"❌ No SSL Analysis Data Found")
            
            # Check domain features
            domain_features = analysis_details.get('domain_features', {})
            has_ssl = domain_features.get('has_ssl', False)
            print(f"   Domain Features - has_ssl: {has_ssl}")
            
            return True, result
            
        else:
            print(f"❌ Backend Request Failed: {response.status_code}")
            print(f"   Response: {response.text}")
            return False, None
            
    except Exception as e:
        print(f"❌ Backend Analysis Failed: {str(e)}")
        return False, None

def test_mashreq_openssl():
    """Test OpenSSL connection to www.mashreqbank.com"""
    print("\n🔐 Testing OpenSSL Connection")
    
    domain = "www.mashreqbank.com"
    
    try:
        # Test SSL connection with openssl
        result = subprocess.run([
            'openssl', 's_client', '-connect', f'{domain}:443', 
            '-servername', domain, '-verify_return_error'
        ], input='', text=True, capture_output=True, timeout=15)
        
        if result.returncode == 0:
            print(f"✅ OpenSSL Connection Successful!")
            
            # Extract certificate info
            lines = result.stdout.split('\n')
            for line in lines:
                if 'subject=' in line:
                    print(f"   Subject: {line}")
                elif 'issuer=' in line:
                    print(f"   Issuer: {line}")
                elif 'Cipher is' in line:
                    print(f"   Cipher: {line}")
                elif 'Protocol' in line and 'TLS' in line:
                    print(f"   Protocol: {line}")
            
            return True, result.stdout
        else:
            print(f"❌ OpenSSL Failed: {result.stderr}")
            return False, None
            
    except subprocess.TimeoutExpired:
        print(f"❌ OpenSSL Timeout")
        return False, None
    except FileNotFoundError:
        print(f"❌ OpenSSL Not Available")
        return False, None
    except Exception as e:
        print(f"❌ OpenSSL Error: {str(e)}")
        return False, None

def main():
    print("🏦 MASHREQ BANK SSL ANALYSIS DEBUG")
    print("=" * 50)
    
    # Run all tests
    ssl_success, cert, cipher = test_mashreq_ssl_direct()
    https_success, response = test_mashreq_https_request()
    backend_success, backend_result = test_mashreq_backend_analysis()
    openssl_success, openssl_output = test_mashreq_openssl()
    
    print("\n📊 SUMMARY")
    print("=" * 30)
    print(f"Direct SSL Connection: {'✅ PASS' if ssl_success else '❌ FAIL'}")
    print(f"HTTPS Request: {'✅ PASS' if https_success else '❌ FAIL'}")
    print(f"Backend Analysis: {'✅ PASS' if backend_success else '❌ FAIL'}")
    print(f"OpenSSL Test: {'✅ PASS' if openssl_success else '❌ FAIL'}")
    
    # Analysis
    print("\n🔍 ANALYSIS")
    print("=" * 20)
    
    if ssl_success and https_success:
        print("✅ SSL is working correctly for www.mashreqbank.com")
        if not backend_success:
            print("❌ Issue is in the backend SSL analysis implementation")
        else:
            print("✅ Backend analysis is also working")
    else:
        print("❌ SSL connection issues detected")
    
    return 0

if __name__ == "__main__":
    main()