"""
FastAPI â€“ Secure Tax Preparation Service with Data Collection
Complete working version with all imports and missing code fixed
"""
import json
import os
import re
import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum
from typing import List, Optional, Dict, Any, Union
from io import BytesIO
import base64

# Core FastAPI imports
import pyotp
import uvicorn
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    UploadFile,
    status,
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware

# Security and validation imports
from jose import JWTError, jwt
from passlib.hash import bcrypt
from pydantic import BaseModel, EmailStr, Field, validator

# Database imports
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    JSON,
    String,
    Text,
    Numeric,
    create_engine,
    ForeignKey,
    Enum as SQLEnum,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker, relationship

# File processing imports
from PIL import Image
import PyPDF2
import magic
import requests

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# CONFIGURATION
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
DATABASE_URL = "sqlite:///./taxbox.db"
SECRET_KEY = os.getenv("SECRET_KEY", "INSECURE_DEMO_KEY_CHANGE_IN_PRODUCTION")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MIN = 60 * 24

# Create uploads directories
UPLOAD_DIR = "./uploads"
PROCESSED_DIR = "./processed"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(PROCESSED_DIR, exist_ok=True)

# Database setup (THIS WAS MISSING IN YOUR ORIGINAL CODE)
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# ENUMS
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class FilingStatus(str, Enum):
    SINGLE = "single"
    MARRIED_FILING_JOINTLY = "married_filing_jointly"
    MARRIED_FILING_SEPARATELY = "married_filing_separately"
    HEAD_OF_HOUSEHOLD = "head_of_household"
    QUALIFYING_WIDOW = "qualifying_widow"

class IncomeType(str, Enum):
    W2 = "w2"
    FORM_1099_MISC = "1099_misc"
    FORM_1099_NEC = "1099_nec"
    FORM_1099_INT = "1099_int"
    FORM_1099_DIV = "1099_div"
    FORM_1099_B = "1099_b"
    SELF_EMPLOYMENT = "self_employment"
    RENTAL = "rental"
    BUSINESS = "business"
    RETIREMENT = "retirement"
    UNEMPLOYMENT = "unemployment"
    OTHER = "other"

class DeductionType(str, Enum):
    STANDARD = "standard"
    ITEMIZED = "itemized"

class DocumentType(str, Enum):
    W2 = "w2"
    FORM_1099 = "1099"
    RECEIPT = "receipt"
    BANK_STATEMENT = "bank_statement"
    INVESTMENT_STATEMENT = "investment_statement"
    MORTGAGE_STATEMENT = "mortgage_statement"
    PROPERTY_TAX = "property_tax"
    CHARITABLE_DONATION = "charitable_donation"
    MEDICAL_EXPENSE = "medical_expense"
    EDUCATION_EXPENSE = "education_expense"
    OTHER = "other"

class ImportProvider(str, Enum):
    ADP = "adp"
    PAYCHEX = "paychex"
    QUICKBOOKS = "quickbooks"
    CHASE = "chase"
    BANK_OF_AMERICA = "bank_of_america"
    WELLS_FARGO = "wells_fargo"
    TURBOTAX = "turbotax"
    HR_BLOCK = "hr_block"
    OTHER = "other"

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# DATABASE MODELS
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    mfa_secret = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    identity_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    profile = relationship("Profile", back_populates="user", uselist=False)
    tax_profile = relationship("TaxProfile", back_populates="user", uselist=False)
    documents = relationship("Document", back_populates="user")
    kba = relationship("KBA", back_populates="user", uselist=False)
    income_records = relationship("IncomeRecord", back_populates="user")
    deduction_records = relationship("DeductionRecord", back_populates="user")
    import_sessions = relationship("ImportSession", back_populates="user")

class Profile(Base):
    __tablename__ = "profiles"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    first_name = Column(String)
    last_name = Column(String)
    date_of_birth = Column(String)
    phone = Column(String)
    address = Column(String)
    dependents = Column(JSON, default=list)
    
    user = relationship("User", back_populates="profile")

class TaxProfile(Base):
    __tablename__ = "tax_profiles"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    ssn = Column(String)
    spouse_ssn = Column(String, nullable=True)
    filing_status = Column(SQLEnum(FilingStatus))
    state = Column(String)
    address_line1 = Column(String)
    address_line2 = Column(String, nullable=True)
    city = Column(String)
    zip_code = Column(String)
    occupation = Column(String, nullable=True)
    spouse_occupation = Column(String, nullable=True)
    bank_routing = Column(String, nullable=True)
    bank_account = Column(String, nullable=True)
    prior_year_agi = Column(Numeric(12, 2), nullable=True)
    
    user = relationship("User", back_populates="tax_profile")

class IncomeRecord(Base):
    __tablename__ = "income_records"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    income_type = Column(SQLEnum(IncomeType))
    employer_name = Column(String, nullable=True)
    employer_ein = Column(String, nullable=True)
    gross_income = Column(Numeric(12, 2))
    federal_withholding = Column(Numeric(12, 2), default=0)
    state_withholding = Column(Numeric(12, 2), default=0)
    social_security_wages = Column(Numeric(12, 2), default=0)
    medicare_wages = Column(Numeric(12, 2), default=0)
    state_wages = Column(Numeric(12, 2), default=0)
    additional_data = Column(JSON, default=dict)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="income_records")
    document = relationship("Document")

class DeductionRecord(Base):
    __tablename__ = "deduction_records"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    deduction_type = Column(SQLEnum(DeductionType))
    category = Column(String)
    description = Column(String)
    amount = Column(Numeric(12, 2))
    state_specific = Column(Boolean, default=False)
    state = Column(String, nullable=True)
    additional_data = Column(JSON, default=dict)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="deduction_records")
    document = relationship("Document")

class Document(Base):
    __tablename__ = "documents"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    filename = Column(String, nullable=False)
    original_filename = Column(String, nullable=False)
    document_type = Column(SQLEnum(DocumentType))
    file_path = Column(String, nullable=False)
    file_size = Column(Integer)
    mime_type = Column(String)
    processed = Column(Boolean, default=False)
    extracted_data = Column(JSON, default=dict)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="documents")

class ImportSession(Base):
    __tablename__ = "import_sessions"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    provider = Column(SQLEnum(ImportProvider))
    session_token = Column(String, nullable=True)
    status = Column(String, default="pending")
    imported_data = Column(JSON, default=dict)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    
    user = relationship("User", back_populates="import_sessions")

class KBA(Base):
    __tablename__ = "kba"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    questions = Column(JSON)
    answers = Column(JSON)
    verified = Column(Boolean, default=False)
    
    user = relationship("User", back_populates="kba")

# Create all tables (THIS WAS MOVED TO THE CORRECT LOCATION)
Base.metadata.create_all(bind=engine)

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# PYDANTIC SCHEMAS
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class TaxProfileIn(BaseModel):
    ssn: str = Field(pattern=r'^\d{3}-\d{2}-\d{4}$')
    spouse_ssn: Optional[str] = Field(None, pattern=r'^\d{3}-\d{2}-\d{4}$')
    filing_status: FilingStatus
    state: str = Field(max_length=2)
    address_line1: str
    address_line2: Optional[str] = None
    city: str
    zip_code: str = Field(pattern=r'^\d{5}(-\d{4})?$')
    occupation: Optional[str] = None
    spouse_occupation: Optional[str] = None
    bank_routing: Optional[str] = Field(None, pattern=r'^\d{9}$')
    bank_account: Optional[str] = None
    prior_year_agi: Optional[Decimal] = None

class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    first_name: str
    last_name: str
    date_of_birth: str
    phone: Optional[str] = None
    address: Optional[str] = None

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"

class MFASetupOut(BaseModel):
    message: str
    otp_auth_uri: str
    secret: str

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# FASTAPI APP & DEPENDENCIES
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
app = FastAPI(title="TaxBox.AI - Comprehensive Tax Preparation Service")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception
    return user

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# UTILITY FUNCTIONS
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def hash_password(password: str) -> str:
    return bcrypt.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.verify(plain_password, hashed_password)

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# BASIC ENDPOINTS
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@app.get("/")
def read_root():
    return {"message": "TaxBox.AI API is running", "version": "1.0.0"}

@app.get("/health")
def health_check():
    return {
        "status": "healthy", 
        "timestamp": datetime.utcnow(),
        "version": "1.0.0"
    }

@app.post("/register", response_model=MFASetupOut, status_code=201)
def register(data: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter_by(email=data.email.lower()).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    mfa_secret = pyotp.random_base32()
    user = User(
        email=data.email.lower(),
        password_hash=hash_password(data.password),
        mfa_secret=mfa_secret,
    )
    
    profile = Profile(
        first_name=data.first_name,
        last_name=data.last_name,
        date_of_birth=data.date_of_birth,
        phone=data.phone,
        address=data.address,
    )
    user.profile = profile
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    otp_uri = pyotp.totp.TOTP(mfa_secret).provisioning_uri(
        name=user.email, issuer_name="TaxBox.AI"
    )
    
    return MFASetupOut(
        message="Registration successful. Set up MFA with your authenticator app.",
        otp_auth_uri=otp_uri,
        secret=mfa_secret,
    )

@app.post("/token", response_model=TokenOut)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    mfa_code = form.scopes[0] if form.scopes else None
    user = db.query(User).filter_by(email=form.username.lower()).first()
    
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    if not mfa_code or not pyotp.TOTP(user.mfa_secret).verify(mfa_code):
        raise HTTPException(status_code=401, detail="Invalid MFA code")
    
    access_token = create_access_token(
        data={"sub": user.id}, 
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MIN)
    )
    
    return TokenOut(access_token=access_token)

@app.get("/me")
def get_current_user_info(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "email": current_user.email,
        "identity_verified": current_user.identity_verified,
        "created_at": current_user.created_at,
    }

# ────────────────────────────────────────────────────────────
# MAIN - FORCE CORRECT PORT
# ────────────────────────────────────────────────────────────
import os
port = int(os.getenv("PORT", 8000))
print(f"🚀 Railway PORT env: {os.getenv('PORT', 'NOT SET')}")
print(f"🚀 Using port: {port}")

# Force uvicorn to run regardless of __name__ check
uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)