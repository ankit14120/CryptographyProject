#!/usr/bin/env python3

import requests
import sys
import json
import base64
from datetime import datetime
import time

class CryptoSecureAPITester:
    def __init__(self, base_url="https://crypto-secure-1.preview.emergentagent.com"):
        self.base_url = base_url
        self.api_url = f"{base_url}/api"
        self.token = None
        self.user_id = None
        self.tests_run = 0
        self.tests_passed = 0
        self.test_results = []

    def log_test(self, name, success, details=""):
        """Log test result"""
        self.tests_run += 1
        if success:
            self.tests_passed += 1
            print(f"✅ {name} - PASSED")
        else:
            print(f"❌ {name} - FAILED: {details}")
        
        self.test_results.append({
            "test": name,
            "success": success,
            "details": details,
            "timestamp": datetime.now().isoformat()
        })

    def run_test(self, name, method, endpoint, expected_status, data=None, files=None):
        """Run a single API test"""
        url = f"{self.api_url}/{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        
        print(f"\n🔍 Testing {name}...")
        print(f"   URL: {url}")
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers)
            elif method == 'POST':
                if files:
                    # Remove Content-Type for file uploads
                    headers.pop('Content-Type', None)
                    response = requests.post(url, files=files, headers=headers)
                else:
                    response = requests.post(url, json=data, headers=headers)
            elif method == 'DELETE':
                response = requests.delete(url, headers=headers)

            success = response.status_code == expected_status
            
            if success:
                self.log_test(name, True)
                try:
                    return True, response.json()
                except:
                    return True, response.text
            else:
                error_msg = f"Expected {expected_status}, got {response.status_code}"
                try:
                    error_detail = response.json()
                    error_msg += f" - {error_detail}"
                except:
                    error_msg += f" - {response.text}"
                
                self.log_test(name, False, error_msg)
                return False, {}

        except Exception as e:
            self.log_test(name, False, f"Exception: {str(e)}")
            return False, {}

    def test_root_endpoint(self):
        """Test API root endpoint"""
        return self.run_test("API Root", "GET", "", 200)

    def test_user_registration(self):
        """Test user registration"""
        timestamp = int(time.time())
        test_user_data = {
            "name": f"Test User {timestamp}",
            "email": f"testuser{timestamp}@example.com",
            "password": "TestPass123!"
        }
        
        success, response = self.run_test(
            "User Registration",
            "POST",
            "auth/register",
            200,
            data=test_user_data
        )
        
        if success and 'token' in response:
            self.token = response['token']
            self.user_id = response['user']['id']
            self.test_email = test_user_data['email']
            self.test_password = test_user_data['password']
            return True
        return False

    def test_user_login(self):
        """Test user login with registered credentials"""
        if not hasattr(self, 'test_email'):
            self.log_test("User Login", False, "No registered user to test login")
            return False
            
        login_data = {
            "email": self.test_email,
            "password": self.test_password
        }
        
        success, response = self.run_test(
            "User Login",
            "POST",
            "auth/login",
            200,
            data=login_data
        )
        
        if success and 'token' in response:
            self.token = response['token']
            return True
        return False

    def test_invalid_login(self):
        """Test login with invalid credentials"""
        invalid_data = {
            "email": "nonexistent@example.com",
            "password": "wrongpassword"
        }
        
        return self.run_test(
            "Invalid Login",
            "POST",
            "auth/login",
            401,
            data=invalid_data
        )

    def create_test_file_content(self):
        """Create test file content with sensitive data"""
        content = """Sample Test Data:
Email: john.doe@example.com
Phone: 555-123-4567
SSN: 123-45-6789
Credit Card: 4532015112830366
Bank Account: 1234567890
Passport: AB1234567
Date of Birth: 01/15/1990

This is a test file containing sensitive information that should be detected and encrypted."""
        return content

    def test_file_analysis(self):
        """Test file upload and analysis for sensitive data"""
        if not self.token:
            self.log_test("File Analysis", False, "No authentication token")
            return False, None
            
        test_content = self.create_test_file_content()
        
        files = {
            'file': ('test_sensitive_data.txt', test_content, 'text/plain')
        }
        
        success, response = self.run_test(
            "File Analysis",
            "POST",
            "files/analyze",
            200,
            files=files
        )
        
        if success:
            # Verify sensitive data was detected
            if response.get('has_sensitive_data'):
                print(f"   ✓ Sensitive data detected: {len(response.get('detected_patterns', []))} patterns")
                return True, response
            else:
                self.log_test("File Analysis - Sensitive Data Detection", False, "Expected sensitive data to be detected")
                return False, None
        return False, None

    def test_file_encryption(self):
        """Test file encryption"""
        if not self.token:
            self.log_test("File Encryption", False, "No authentication token")
            return False, None
            
        # First analyze a file
        analysis_success, analysis_results = self.test_file_analysis()
        if not analysis_success:
            return False, None
            
        # Encrypt the file
        test_content = self.create_test_file_content()
        base64_content = base64.b64encode(test_content.encode()).decode()
        
        encryption_data = {
            "file_content": base64_content,
            "filename": "test_sensitive_data.txt",
            "password": "EncryptionPass123!",
            "detection_results": analysis_results
        }
        
        success, response = self.run_test(
            "File Encryption",
            "POST",
            "files/encrypt",
            200,
            data=encryption_data
        )
        
        if success and 'id' in response:
            self.encrypted_file_id = response['id']
            self.encryption_password = "EncryptionPass123!"
            return True, response
        return False, None

    def test_get_user_files(self):
        """Test getting user's encrypted files"""
        if not self.token:
            self.log_test("Get User Files", False, "No authentication token")
            return False
            
        success, response = self.run_test(
            "Get User Files",
            "GET",
            "files",
            200
        )
        
        if success:
            print(f"   ✓ Found {len(response)} encrypted files")
            return True
        return False

    def test_file_decryption(self):
        """Test file decryption"""
        if not self.token or not hasattr(self, 'encrypted_file_id'):
            self.log_test("File Decryption", False, "No authentication token or encrypted file")
            return False
            
        decrypt_data = {
            "password": self.encryption_password
        }
        
        success, response = self.run_test(
            "File Decryption",
            "POST",
            f"files/{self.encrypted_file_id}/decrypt",
            200,
            data=decrypt_data
        )
        
        if success and 'content' in response:
            # Verify decrypted content matches original
            decrypted_content = base64.b64decode(response['content']).decode()
            original_content = self.create_test_file_content()
            
            if decrypted_content == original_content:
                print("   ✓ Decrypted content matches original")
                return True
            else:
                self.log_test("File Decryption - Content Verification", False, "Decrypted content doesn't match original")
                return False
        return False

    def test_file_decryption_wrong_password(self):
        """Test file decryption with wrong password"""
        if not self.token or not hasattr(self, 'encrypted_file_id'):
            self.log_test("File Decryption Wrong Password", False, "No authentication token or encrypted file")
            return False
            
        decrypt_data = {
            "password": "WrongPassword123!"
        }
        
        return self.run_test(
            "File Decryption Wrong Password",
            "POST",
            f"files/{self.encrypted_file_id}/decrypt",
            400,
            data=decrypt_data
        )

    def test_file_deletion(self):
        """Test file deletion"""
        if not self.token or not hasattr(self, 'encrypted_file_id'):
            self.log_test("File Deletion", False, "No authentication token or encrypted file")
            return False
            
        return self.run_test(
            "File Deletion",
            "DELETE",
            f"files/{self.encrypted_file_id}",
            200
        )

    def test_unauthorized_access(self):
        """Test accessing protected endpoints without token"""
        # Temporarily remove token
        original_token = self.token
        self.token = None
        
        success, _ = self.run_test(
            "Unauthorized Access - Get Files",
            "GET",
            "files",
            401
        )
        
        # Restore token
        self.token = original_token
        return success

    def run_all_tests(self):
        """Run all API tests"""
        print("🚀 Starting CryptoSecure API Tests")
        print("=" * 50)
        
        # Test API availability
        self.test_root_endpoint()
        
        # Test authentication
        if self.test_user_registration():
            self.test_user_login()
        
        self.test_invalid_login()
        
        # Test file operations (requires authentication)
        if self.token:
            analysis_success, _ = self.test_file_analysis()
            
            if analysis_success:
                encryption_success, _ = self.test_file_encryption()
                
                if encryption_success:
                    self.test_get_user_files()
                    self.test_file_decryption()
                    self.test_file_decryption_wrong_password()
                    self.test_file_deletion()
        
        # Test security
        self.test_unauthorized_access()
        
        # Print summary
        print("\n" + "=" * 50)
        print(f"📊 Test Summary: {self.tests_passed}/{self.tests_run} tests passed")
        
        if self.tests_passed == self.tests_run:
            print("🎉 All tests passed!")
            return 0
        else:
            print(f"❌ {self.tests_run - self.tests_passed} tests failed")
            return 1

def main():
    tester = CryptoSecureAPITester()
    return tester.run_all_tests()

if __name__ == "__main__":
    sys.exit(main())