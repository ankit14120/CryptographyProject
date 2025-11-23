from fastapi import FastAPI, APIRouter, HTTPException, Depends, status, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
import re
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'your-super-secret-jwt-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24

# Security
security = HTTPBearer()

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")

# ============ MODELS ============

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class TokenResponse(BaseModel):
    token: str
    user: User

class SensitiveDataResult(BaseModel):
    has_sensitive_data: bool
    detected_patterns: List[Dict[str, Any]]
    file_info: Dict[str, Any]

class EncryptionRequest(BaseModel):
    file_content: str  # base64 encoded
    filename: str
    password: str
    detection_results: Dict[str, Any]

class EncryptedFile(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    original_filename: str
    encrypted_data: str  # base64
    salt: str  # base64
    detection_results: Dict[str, Any]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    file_size: int

# ============ UTILITIES ============

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_jwt_token(user_id: str, email: str) -> str:
    payload = {
        'user_id': user_id,
        'email': email,
        'exp': datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    token = credentials.credentials
    payload = verify_jwt_token(token)
    user = await db.users.find_one({"id": payload['user_id']}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

# Sensitive Data Detection Patterns
PATTERNS = {
    'email': (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email Address'),
    'phone_us': (r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b', 'US Phone Number'),
    'ssn': (r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b', 'Social Security Number'),
    'credit_card': (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b', 'Credit Card Number'),
    'passport': (r'\b[A-Z]{1,2}[0-9]{6,9}\b', 'Passport Number'),
    'bank_account': (r'\b[0-9]{8,17}\b', 'Bank Account Number'),
    'ip_address': (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', 'IP Address'),
    'date_of_birth': (r'\b(?:0[1-9]|1[0-2])/(?:0[1-9]|[12][0-9]|3[01])/(?:19|20)\d{2}\b', 'Date of Birth'),
}

def detect_sensitive_data(content: str) -> Dict[str, Any]:
    detected = []
    for pattern_name, (pattern, label) in PATTERNS.items():
        matches = re.findall(pattern, content)
        if matches:
            # Mask the sensitive data for display
            masked_matches = []
            for match in matches:
                if isinstance(match, tuple):
                    match_str = ''.join(match)
                else:
                    match_str = str(match)
                masked = match_str[:3] + '*' * (len(match_str) - 3) if len(match_str) > 3 else '***'
                masked_matches.append(masked)
            
            detected.append({
                'type': label,
                'pattern': pattern_name,
                'count': len(matches),
                'samples': masked_matches[:5]  # Show first 5 samples
            })
    
    return {
        'has_sensitive_data': len(detected) > 0,
        'detected_patterns': detected,
        'total_patterns_found': len(detected)
    }

def encrypt_file_content(content: bytes, password: str) -> tuple[bytes, bytes]:
    # Generate a random salt
    salt = os.urandom(16)
    
    # Derive key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    
    # Generate random IV
    iv = os.urandom(16)
    
    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad content to multiple of 16 bytes
    padding_length = 16 - (len(content) % 16)
    padded_content = content + bytes([padding_length] * padding_length)
    
    encrypted = encryptor.update(padded_content) + encryptor.finalize()
    
    # Combine IV and encrypted data
    encrypted_data = iv + encrypted
    
    return encrypted_data, salt

def decrypt_file_content(encrypted_data: bytes, password: str, salt: bytes) -> bytes:
    # Derive key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    
    # Extract IV and encrypted content
    iv = encrypted_data[:16]
    encrypted_content = encrypted_data[16:]
    
    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    try:
        padded_content = decryptor.update(encrypted_content) + decryptor.finalize()
        
        # Validate and remove padding (PKCS7)
        padding_length = padded_content[-1]
        
        # Validate padding length
        if padding_length < 1 or padding_length > 16:
            raise ValueError("Invalid padding length")
        
        # Validate all padding bytes are correct
        for i in range(padding_length):
            if padded_content[-(i+1)] != padding_length:
                raise ValueError("Invalid padding")
        
        content = padded_content[:-padding_length]
        
        return content
    except (ValueError, IndexError) as e:
        raise ValueError("Decryption failed - incorrect password")

# ============ ROUTES ============

@api_router.get("/")
async def root():
    return {"message": "CryptoSecure API v1.0", "status": "active"}

@api_router.post("/auth/register", response_model=TokenResponse)
async def register(user_data: UserRegister):
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user = User(
        email=user_data.email,
        name=user_data.name
    )
    
    user_dict = user.model_dump()
    user_dict['password_hash'] = hash_password(user_data.password)
    user_dict['created_at'] = user_dict['created_at'].isoformat()
    
    await db.users.insert_one(user_dict)
    
    # Create token
    token = create_jwt_token(user.id, user.email)
    
    return TokenResponse(token=token, user=user)

@api_router.post("/auth/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    # Find user
    user_doc = await db.users.find_one({"email": credentials.email})
    if not user_doc:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Verify password
    if not verify_password(credentials.password, user_doc['password_hash']):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create user object (without password)
    user = User(
        id=user_doc['id'],
        email=user_doc['email'],
        name=user_doc['name'],
        created_at=datetime.fromisoformat(user_doc['created_at']) if isinstance(user_doc['created_at'], str) else user_doc['created_at']
    )
    
    # Create token
    token = create_jwt_token(user.id, user.email)
    
    return TokenResponse(token=token, user=user)

@api_router.post("/files/analyze", response_model=SensitiveDataResult)
async def analyze_file(
    file: UploadFile = File(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    # Read file content
    content = await file.read()
    
    # Try to decode as text
    try:
        text_content = content.decode('utf-8')
    except UnicodeDecodeError:
        # Try other encodings
        try:
            text_content = content.decode('latin-1')
        except:
            raise HTTPException(status_code=400, detail="Unable to read file. Please upload a text-based file.")
    
    # Detect sensitive data
    detection_results = detect_sensitive_data(text_content)
    
    return SensitiveDataResult(
        has_sensitive_data=detection_results['has_sensitive_data'],
        detected_patterns=detection_results['detected_patterns'],
        file_info={
            'filename': file.filename,
            'size': len(content),
            'type': file.content_type
        }
    )

@api_router.post("/files/encrypt", response_model=EncryptedFile)
async def encrypt_file(
    request: EncryptionRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    try:
        # Decode base64 file content
        file_content = base64.b64decode(request.file_content)
        
        # Encrypt the file
        encrypted_data, salt = encrypt_file_content(file_content, request.password)
        
        # Create encrypted file record
        encrypted_file = EncryptedFile(
            user_id=current_user['id'],
            original_filename=request.filename,
            encrypted_data=base64.b64encode(encrypted_data).decode('utf-8'),
            salt=base64.b64encode(salt).decode('utf-8'),
            detection_results=request.detection_results,
            file_size=len(file_content)
        )
        
        # Save to database
        file_dict = encrypted_file.model_dump()
        file_dict['created_at'] = file_dict['created_at'].isoformat()
        
        await db.encrypted_files.insert_one(file_dict)
        
        return encrypted_file
        
    except Exception as e:
        logging.error(f"Encryption error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Encryption failed: {str(e)}")

@api_router.get("/files", response_model=List[EncryptedFile])
async def get_user_files(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    files = await db.encrypted_files.find(
        {"user_id": current_user['id']},
        {"_id": 0}
    ).sort("created_at", -1).to_list(1000)
    
    # Convert ISO string timestamps back to datetime objects
    for file in files:
        if isinstance(file['created_at'], str):
            file['created_at'] = datetime.fromisoformat(file['created_at'])
    
    return files

@api_router.get("/files/{file_id}")
async def get_file_details(
    file_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    file = await db.encrypted_files.find_one(
        {"id": file_id, "user_id": current_user['id']},
        {"_id": 0}
    )
    
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    
    return file

class DecryptRequest(BaseModel):
    password: str

@api_router.post("/files/{file_id}/decrypt")
async def decrypt_file_endpoint(
    file_id: str,
    request: DecryptRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    file = await db.encrypted_files.find_one(
        {"id": file_id, "user_id": current_user['id']},
        {"_id": 0}
    )
    
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    
    try:
        encrypted_data = base64.b64decode(file['encrypted_data'])
        salt = base64.b64decode(file['salt'])
        
        decrypted_content = decrypt_file_content(encrypted_data, request.password, salt)
        
        return {
            "filename": file['original_filename'],
            "content": base64.b64encode(decrypted_content).decode('utf-8')
        }
    except (ValueError, KeyError) as e:
        # Wrong password will cause decryption to fail
        raise HTTPException(status_code=400, detail="Incorrect password or corrupted file")
    except Exception as e:
        logging.error(f"Decryption error: {str(e)}")
        raise HTTPException(status_code=400, detail="Incorrect password or corrupted file")

@api_router.delete("/files/{file_id}")
async def delete_file(
    file_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    result = await db.encrypted_files.delete_one(
        {"id": file_id, "user_id": current_user['id']}
    )
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="File not found")
    
    return {"message": "File deleted successfully"}

# Include router
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()