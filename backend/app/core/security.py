import os
import hashlib
import jwt
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
from passlib.context import CryptContext

# Password hashing context
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

class SecurityManager:
    def __init__(self):
        self.secret_key = os.getenv('SECRET_KEY', 'your-secret-key')
        self.algorithm = 'HS256'
        self.access_token_expire_minutes = 30
    
    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    def get_password_hash(self, password: str) -> str:
        """Generate password hash"""
        return pwd_context.hash(password)
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def decode_access_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Decode JWT access token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.PyJWTError:
            return None
    
    def generate_csrf_token(self, user_id: str) -> str:
        """Generate CSRF token"""
        token = hashlib.sha256(f"{user_id}{datetime.now()}{self.secret_key}".encode()).hexdigest()
        return token
    
    def verify_csrf_token(self, token: str, user_id: str) -> bool:
        """Verify CSRF token"""
        # In production, you would store CSRF tokens in the session or database
        # For demonstration, we'll just check if it's a valid hash
        return len(token) == 64  # SHA-256 produces 64-character hex string
    
    def encrypt_data(self, data: str) -> str:
        """Encrypt data (simple XOR encryption for demonstration)"""
        # In production, use a proper encryption library like cryptography
        key = self.secret_key[:16]  # Use first 16 bytes of secret key
        encrypted = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))
        return encrypted
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt data"""
        # In production, use a proper encryption library like cryptography
        key = self.secret_key[:16]  # Use first 16 bytes of secret key
        decrypted = ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(encrypted_data))
        return decrypted
    
    def check_permissions(self, user_role: str, required_role: str) -> bool:
        """Check if user has required permissions"""
        # Role hierarchy: admin > user
        roles = ['user', 'admin']
        user_role_index = roles.index(user_role) if user_role in roles else -1
        required_role_index = roles.index(required_role) if required_role in roles else -1
        
        return user_role_index >= required_role_index

# Create singleton instance
security_manager = SecurityManager()