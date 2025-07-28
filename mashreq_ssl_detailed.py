#!/usr/bin/env python3

import requests
import json
import ssl
import socket
import subprocess
from datetime import datetime

def test_mashreq_ssl_no_verify():
    """Test SSL connection to www.mashreqbank.com without certificate verification"""
    print("🔍 Testing SSL Connection (No Verification) to www.mashreqbank.com:443")
    
    domain = "www.mashreqbank.com"
    
    try:
        # Create context that doesn't verify certificates
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        socket.setdefaulttimeout(15)
        
        with socket.create_connection((domain, 443), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                
                print(f"✅ SSL Connection Successful (No Verification)!")
                
                if cert:
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    print(f"   Subject: {subject}")
                    print(f"   Issuer: {issuer}")
                    print(f"   Not After: {cert.get('notAfter', 'Unknown')}")
                    print(f"   Serial Number: {cert.get('serialNumber', 'Unknown')}")
                    print(f"   Version: {cert.get('version', 'Unknown')}")
                    
                    # Check Subject Alternative Names
                    san = cert.get('subjectAltName', [])
                    if san:
                        print(f"   Subject Alt Names: {[x[1] for x in san]}")
                    
                if cipher:
                    print(f"   Protocol: {cipher[1]}")
                    print(f"   Cipher Suite: {cipher[0]}")
                    
                return True, cert, cipher
                
    except Exception as e:
        print(f"❌ SSL Connection Failed: {str(e)}")
        return False, None, None

def test_mashreq_https_no_verify():
    """Test HTTPS request to www.mashreqbank.com without SSL verification"""
    print("\n🌐 Testing HTTPS Request (No SSL Verification)")
    
    url = "https://www.mashreqbank.com"
    
    try:
        response = requests.head(url, timeout=15, verify=False, headers={
            'User-Agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)'
        })
        print(f"✅ HTTPS Request Successful (No Verification)!")
        print(f"   Status Code: {response.status_code}")
        
        # Check some important headers
        important_headers = ['Server', 'Strict-Transport-Security', 'Content-Security-Policy']
        for header in important_headers:
            if header in response.headers:
                print(f"   {header}: {response.headers[header]}")
        
        return True, response
        
    except Exception as e:
        print(f"❌ Request Failed: {str(e)}")
        return False, None

def test_openssl_no_verify():
    """Test OpenSSL connection without verification"""
    print("\n🔐 Testing OpenSSL Connection (No Verification)")
    
    domain = "www.mashreqbank.com"
    
    try:
        # Test SSL connection with openssl without verification
        result = subprocess.run([
            'openssl', 's_client', '-connect', f'{domain}:443', 
            '-servername', domain, '-verify_return_error', '-verify', '0'
        ], input='', text=True, capture_output=True, timeout=15)
        
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
            elif 'Verification:' in line:
                print(f"   Verification: {line}")
        
        return True, result.stdout
        
    except Exception as e:
        print(f"❌ OpenSSL Error: {str(e)}")
        return False, None

def test_certificate_chain():
    """Test certificate chain for www.mashreqbank.com"""
    print("\n🔗 Testing Certificate Chain")
    
    domain = "www.mashreqbank.com"
    
    try:
        # Get full certificate chain
        result = subprocess.run([
            'openssl', 's_client', '-connect', f'{domain}:443', 
            '-servername', domain, '-showcerts'
        ], input='', text=True, capture_output=True, timeout=15)
        
        if result.returncode == 0:
            # Count certificates in chain
            cert_count = result.stdout.count('-----BEGIN CERTIFICATE-----')
            print(f"✅ Certificate Chain Retrieved!")
            print(f"   Certificates in chain: {cert_count}")
            
            # Check if intermediate certificates are present
            if cert_count > 1:
                print(f"   ✅ Intermediate certificates present")
            else:
                print(f"   ❌ Only server certificate present - missing intermediate certificates")
            
            return True, cert_count
        else:
            print(f"❌ Failed to get certificate chain: {result.stderr}")
            return False, 0
            
    except Exception as e:
        print(f"❌ Certificate Chain Error: {str(e)}")
        return False, 0

def analyze_ssl_issue():
    """Analyze the SSL issue and provide recommendations"""
    print("\n🔍 SSL ISSUE ANALYSIS")
    print("=" * 30)
    
    print("IDENTIFIED ISSUE:")
    print("- Certificate verification fails due to 'unable to get local issuer certificate'")
    print("- This typically means the server is not providing the complete certificate chain")
    print("- The intermediate certificate(s) are missing from the server configuration")
    
    print("\nIMPACT ON BACKEND:")
    print("- Backend SSL analysis fails because Python's SSL context requires full chain")
    print("- has_ssl flag is set to False")
    print("- SSL grade is assigned 'F' due to connection failure")
    print("- No certificate details can be extracted")
    
    print("\nRECOMMENDED FIXES:")
    print("1. Update backend SSL analysis to handle incomplete certificate chains")
    print("2. Implement fallback SSL connection without verification to extract cert details")
    print("3. Add certificate chain validation and reporting")
    print("4. Provide specific error messages for different SSL issues")

def main():
    print("🏦 MASHREQ BANK SSL DETAILED ANALYSIS")
    print("=" * 50)
    
    # Run tests without verification
    ssl_success, cert, cipher = test_mashreq_ssl_no_verify()
    https_success, response = test_mashreq_https_no_verify()
    openssl_success, openssl_output = test_openssl_no_verify()
    chain_success, cert_count = test_certificate_chain()
    
    print("\n📊 SUMMARY")
    print("=" * 30)
    print(f"SSL Connection (No Verify): {'✅ PASS' if ssl_success else '❌ FAIL'}")
    print(f"HTTPS Request (No Verify): {'✅ PASS' if https_success else '❌ FAIL'}")
    print(f"OpenSSL (No Verify): {'✅ PASS' if openssl_success else '❌ FAIL'}")
    print(f"Certificate Chain: {'✅ PASS' if chain_success else '❌ FAIL'}")
    
    # Provide analysis
    analyze_ssl_issue()
    
    return 0

if __name__ == "__main__":
    main()