#!/usr/bin/env python3
"""
Quick test script to verify BAC detection enhancements
"""

import sys
import os

# Test the detection patterns
def test_authbypass_detection():
    """Test that authbypass URLs are properly detected"""
    
    # Simulate the detection logic
    protected_keywords = [
        'admin', 'dashboard', 'manage', 'settings', 'config', 'users', 
        'control', 'panel', 'vulnerabilities', 'security', 'upload',
        'file', 'exec', 'command', 'sqli', 'xss', 'csrf', 'brute',
        'authbypass', 'bypassauth', 'auth', 'authenticate', 'private', 'protected'
    ]
    
    authbypass_keywords = ['authbypass', 'bypassauth', 'bypass']
    
    # Test URLs
    test_urls = [
        'http://localhost/DVWA/vulnerabilities/authbypass',
        'http://localhost/DVWA/vulnerabilities/auth',
        'http://localhost/app/bypass-auth',
        'http://localhost/admin/dashboard',
        'http://localhost/public/page',
    ]
    
    print("🔍 Testing AUTHBYPASS detection patterns...")
    print("=" * 60)
    
    for url in test_urls:
        url_lower = url.lower()
        
        # Check protected keywords
        is_protected = any(kw in url_lower for kw in protected_keywords)
        
        # Check authbypass keywords
        has_auth_keyword = any(kw in url_lower for kw in authbypass_keywords)
        
        status = "✅" if (is_protected or has_auth_keyword) else "❌"
        print(f"\n{status} URL: {url}")
        print(f"   Protected keyword match: {is_protected}")
        print(f"   Authbypass keyword match: {has_auth_keyword}")
        print(f"   Will trigger DETECTION 6: {has_auth_keyword}")
    
    print("\n" + "=" * 60)
    print("✅ Test complete!")
    print("\nExpected behavior:")
    print("  - /authbypass URLs should trigger DETECTION 6")
    print("  - Guest access to these URLs will be flagged as BAC (Sub-detection 6a/6b)")
    print("  - User access to admin-only URLs will be flagged as BAC (Sub-detection 6c/6d)")
    print("  - Content comparison will detect authentication bypasses and privilege escalation")

def test_auth_indicators():
    """Test that auth indicators are properly detected"""
    
    auth_indicators = [
        'logout', 'log out', 'sign out', 'signout',
        'my account', 'myaccount', 'my profile', 'myprofile',
        'welcome,', 'hello,', 'hi,',
        'dashboard', 'admin panel',
        'you are logged in', 'logged in as',
        'user settings', 'account settings',
        # DVWA specific
        'phpids', 'security level', 'dvwa security',
        'welcome back', 'authenticated', 'auth success',
        'logged-in', 'user authenticated', 'access granted',
        'login required', 'authentication required', 'please log in',
        'unauthorized', 'forbidden', 'access denied'
    ]
    
    test_content = [
        ('DVWA Security Level: low', True),
        ('Logout | My Account', True),
        ('Please log in to continue', True),
        ('Access denied', True),
        ('Public page content', False),
        ('This is a regular page', False),
    ]
    
    print("\n🔍 Testing AUTH INDICATORS detection...")
    print("=" * 60)
    
    for content, expected in test_content:
        content_lower = content.lower()
        detected = any(indicator in content_lower for indicator in auth_indicators)
        status = "✅" if detected == expected else "❌"
        
        print(f"\n{status} Content: {content}")
        print(f"   Expected auth indicator: {expected}")
        print(f"   Detected: {detected}")
    
    print("\n" + "=" * 60)
    print("✅ Auth indicator test complete!")

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("BAC Detection Enhancement Tests")
    print("=" * 60)
    
    test_authbypass_detection()
    test_auth_indicators()
    
    print("\n" + "=" * 60)
    print("ℹ️  Next Steps:")
    print("  1. Start a quick scan of DVWA at http://localhost/DVWA")
    print("  2. Provide admin credentials (or leave blank for low security)")
    print("  3. Monitor for BAC violations on /authbypass endpoint")
    print("  4. Check scan report for detailed violation information")
    print("=" * 60)
