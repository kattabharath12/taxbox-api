"""
FastAPI – Secure Tax Preparation Service with Data Collection
-----------------------------------------------------------
Enhanced with comprehensive tax data collection, document processing,
and third-party integrations for payroll/bank/tax software imports.
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
from jose import JWTError, jwt
from passlib.hash import bcrypt
from pydantic import BaseModel, EmailStr, Field
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
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
try:
    import PyPDF2
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
import requests

# ────────────────────────────────────────────────────────────
# CONFIGURATION
# ────────────────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./taxbox.db")
SECRET_KEY = os.getenv("SECRET_KEY", "INSECURE_DEMO_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MIN = 60 * 24

UPLOAD_DIR = "./uploads"
PROCESSED_DIR = "./processed"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(PROCESSED_DIR, exist_ok=True)

# Database setup
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# ────────────────────────────────────────────────────────────
# ENUMS
# ────────────────────────────────────────────────────────────
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

# ────────────────────────────────────────────────────────────
# DATABASE MODELS
# ────────────────────────────────────────────────────────────
Base = declarative_base()

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
    ssn = Column(String)  # Encrypted in production
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
    additional_data = Column(JSON, default=dict)  # For form-specific fields
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    user = relationship("User", back_populates="income_records")
    document = relationship("Document")

class DeductionRecord(Base):
    __tablename__ = "deduction_records"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    deduction_type = Column(SQLEnum(DeductionType))
    category = Column(String)  # mortgage_interest, charitable, medical, etc.
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
    status = Column(String, default="pending")  # pending, success, failed
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

# Create tables AFTER all models are defined
Base.metadata.create_all(bind=engine)

# ────────────────────────────────────────────────────────────
# PYDANTIC SCHEMAS
# ────────────────────────────────────────────────────────────
class Dependent(BaseModel):
    name: str
    relationship: str
    ssn: Optional[str] = None
    dob: Optional[str] = None
    months_lived_with_you: Optional[int] = None
    student: Optional[bool] = False
    disabled: Optional[bool] = False

class TaxProfileIn(BaseModel):
    ssn: str = Field(regex=r'^\d{3}-\d{2}-\d{4}$')
    spouse_ssn: Optional[str] = Field(None, regex=r'^\d{3}-\d{2}-\d{4}$')
    filing_status: FilingStatus
    state: str = Field(max_length=2)
    address_line1: str
    address_line2: Optional[str] = None
    city: str
    zip_code: str = Field(regex=r'^\d{5}(-\d{4})?$')
    occupation: Optional[str] = None
    spouse_occupation: Optional[str] = None
    bank_routing: Optional[str] = Field(None, regex=r'^\d{9}$')
    bank_account: Optional[str] = None
    prior_year_agi: Optional[Decimal] = None

class W2IncomeIn(BaseModel):
    employer_name: str
    employer_ein: str = Field(regex=r'^\d{2}-\d{7}$')
    gross_income: Decimal = Field(ge=0)
    federal_withholding: Decimal = Field(ge=0, default=0)
    state_withholding: Decimal = Field(ge=0, default=0)
    social_security_wages: Decimal = Field(ge=0, default=0)
    medicare_wages: Decimal = Field(ge=0, default=0)
    state_wages: Decimal = Field(ge=0, default=0)
    retirement_plan: Optional[bool] = False
    statutory_employee: Optional[bool] = False

class Form1099In(BaseModel):
    payer_name: str
    payer_tin: str = Field(regex=r'^\d{2}-\d{7}$')
    income_type: IncomeType
    amount: Decimal = Field(ge=0)
    federal_withholding: Optional[Decimal] = Field(ge=0, default=0)
    state_withholding: Optional[Decimal] = Field(ge=0, default=0)
    additional_info: Optional[Dict[str, Any]] = {}

class SelfEmploymentIn(BaseModel):
    business_name: Optional[str] = None
    business_type: str
    gross_receipts: Decimal = Field(ge=0)
    total_expenses: Decimal = Field(ge=0, default=0)
    net_profit: Decimal
    schedule_c_expenses: Optional[Dict[str, Decimal]] = {}

class ItemizedDeductionIn(BaseModel):
    category: str  # mortgage_interest, property_tax, charitable, medical, etc.
    description: str
    amount: Decimal = Field(ge=0)
    state_specific: bool = False
    state: Optional[str] = None
    supporting_documents: Optional[List[str]] = []

class EducationCreditIn(BaseModel):
    student_name: str
    student_ssn: str = Field(regex=r'^\d{3}-\d{2}-\d{4}$')
    institution_name: str
    institution_ein: str = Field(regex=r'^\d{2}-\d{7}$')
    tuition_paid: Decimal = Field(ge=0)
    qualified_expenses: Decimal = Field(ge=0)
    form_1098t_received: bool = False

class ChildTaxCreditIn(BaseModel):
    child_name: str
    child_ssn: str = Field(regex=r'^\d{3}-\d{2}-\d{4}$')
    relationship: str
    months_lived_with_you: int = Field(ge=0, le=12)
    under_age_17: bool
    us_citizen: bool = True

class StateSpecificIn(BaseModel):
    state: str = Field(max_length=2)
    deduction_type: str
    amount: Decimal = Field(ge=0)
    description: str
    additional_data: Optional[Dict[str, Any]] = {}

class ImportRequestIn(BaseModel):
    provider: ImportProvider
    credentials: Dict[str, str]  # username, password, account_id, etc.
    data_types: List[str] = ["income", "deductions", "documents"]

# Response Models
class TaxProfileOut(BaseModel):
    filing_status: FilingStatus
    state: str
    address_line1: str
    city: str
    zip_code: str
    occupation: Optional[str]
    
    class Config:
        orm_mode = True

class IncomeRecordOut(BaseModel):
    id: int
    income_type: IncomeType
    employer_name: Optional[str]
    gross_income: Decimal
    federal_withholding: Decimal
    created_at: datetime
    
    class Config:
        orm_mode = True

class DeductionRecordOut(BaseModel):
    id: int
    deduction_type: DeductionType
    category: str
    description: str
    amount: Decimal
    state_specific: bool
    created_at: datetime
    
    class Config:
        orm_mode = True

class DocumentOut(BaseModel):
    id: int
    filename: str
    document_type: DocumentType
    file_size: int
    processed: bool
    uploaded_at: datetime
    
    class Config:
        orm_mode = True

# ────────────────────────────────────────────────────────────
# FASTAPI APP & DEPENDENCIES
# ────────────────────────────────────────────────────────────
app = FastAPI(
    title="TaxBox.AI - Comprehensive Tax Preparation Service",
    description="Secure tax preparation API with document processing and third-party integrations",
    version="1.0.0"
)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure properly for production
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

# ────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
# ────────────────────────────────────────────────────────────
def process_document(file_path: str, document_type: DocumentType) -> Dict[str, Any]:
    """Extract data from uploaded documents using OCR/parsing"""
    extracted_data = {"message": "Document processing available in production"}
    
    try:
        if PDF_AVAILABLE and file_path.endswith('.pdf'):
            extracted_data = extract_pdf_data(file_path, document_type)
        elif PIL_AVAILABLE and any(file_path.endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.tiff']):
            extracted_data = extract_image_data(file_path, document_type)
        else:
            extracted_data = {"message": "File type processed successfully", "type": str(document_type)}
    except Exception as e:
        extracted_data = {"error": str(e)}
    
    return extracted_data

def extract_pdf_data(file_path: str, document_type: DocumentType) -> Dict[str, Any]:
    """Extract text and structured data from PDF documents"""
    extracted_data = {"text": "", "structured_data": {}}
    
    if not PDF_AVAILABLE:
        return {"message": "PDF processing not available in this environment"}
    
    try:
        with open(file_path, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            text = ""
            for page in pdf_reader.pages:
                text += page.extract_text()
            
            extracted_data["text"] = text[:500]  # Limit text for demo
            
            # Basic pattern matching for common tax forms
            if document_type == DocumentType.W2:
                extracted_data["structured_data"] = parse_w2_text(text)
            elif document_type == DocumentType.FORM_1099:
                extracted_data["structured_data"] = parse_1099_text(text)
                
    except Exception as e:
        extracted_data["error"] = str(e)
    
    return extracted_data

def extract_image_data(file_path: str, document_type: DocumentType) -> Dict[str, Any]:
    """Extract data from image documents using OCR"""
    extracted_data = {
        "message": "Image processed successfully",
        "file_type": "image",
        "document_type": str(document_type),
        "note": "OCR integration available in production"
    }
    return extracted_data

def parse_w2_text(text: str) -> Dict[str, Any]:
    """Parse W-2 form text for structured data"""
    w2_data = {}
    
    # Basic regex patterns for W-2 fields
    patterns = {
        "wages": r"Wages, tips, other compensation\s*[\$]?([\d,]+\.?\d*)",
        "federal_withholding": r"Federal income tax withheld\s*[\$]?([\d,]+\.?\d*)",
        "social_security_wages": r"Social security wages\s*[\$]?([\d,]+\.?\d*)",
        "employer_ein": r"Employer identification number\s*(\d{2}-\d{7})"
    }
    
    for field, pattern in patterns.items():
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            w2_data[field] = match.group(1).replace(',', '')
    
    return w2_data

def parse_1099_text(text: str) -> Dict[str, Any]:
    """Parse 1099 form text for structured data"""
    form_1099_data = {}
    
    patterns = {
        "nonemployee_compensation": r"Nonemployee compensation\s*[\$]?([\d,]+\.?\d*)",
        "federal_withholding": r"Federal income tax withheld\s*[\$]?([\d,]+\.?\d*)",
        "payer_tin": r"PAYER'S TIN\s*(\d{2}-\d{7})"
    }
    
    for field, pattern in patterns.items():
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            form_1099_data[field] = match.group(1).replace(',', '')
    
    return form_1099_data

# ────────────────────────────────────────────────────────────
# HEALTH CHECK AND ROOT
# ────────────────────────────────────────────────────────────
@app.get("/health")
def health_check():
    """Health check endpoint for load balancers"""
    return {
        "status": "healthy", 
        "timestamp": datetime.utcnow(),
        "service": "TaxBox API",
        "version": "1.0.0"
    }

@app.get("/")
def root():
    """Root endpoint with API information"""
    return {
        "message": "TaxBox.AI - Comprehensive Tax Preparation API",
        "version": "1.0.0",
        "status": "operational",
        "docs": "/docs",
        "health": "/health",
        "features": [
            "User registration and authentication",
            "Tax profile management", 
            "Income record tracking",
            "Deduction management",
            "Document upload and processing",
            "Third-party data imports"
        ]
    }

# ────────────────────────────────────────────────────────────
# AUTH ENDPOINTS
# ────────────────────────────────────────────────────────────
def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def hash_password(password: str) -> str:
    return bcrypt.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.verify(plain_password, hashed_password)

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

@app.post("/register", response_model=MFASetupOut, status_code=201)
def register(data: RegisterIn, db: Session = Depends(get_db)):
    """Register a new user with MFA setup"""
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
    """Login with email, password, and MFA code"""
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
    """Get current user information"""
    return {
        "id": current_user.id,
        "email": current_user.email,
        "identity_verified": current_user.identity_verified,
        "created_at": current_user.created_at,
    }

# ────────────────────────────────────────────────────────────
# TAX PROFILE ENDPOINTS
# ────────────────────────────────────────────────────────────
@app.post("/tax-profile", response_model=TaxProfileOut)
def create_tax_profile(
    profile_data: TaxProfileIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Create or update tax profile with personal information"""
    existing_profile = db.query(TaxProfile).filter_by(user_id=current_user.id).first()
    
    if existing_profile:
        # Update existing profile
        for field, value in profile_data.dict().items():
            setattr(existing_profile, field, value)
        tax_profile = existing_profile
    else:
        # Create new profile
        tax_profile = TaxProfile(user_id=current_user.id, **profile_data.dict())
        db.add(tax_profile)
    
    db.commit()
    db.refresh(tax_profile)
    return tax_profile

@app.get("/tax-profile", response_model=TaxProfileOut)
def get_tax_profile(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get current user's tax profile"""
    tax_profile = db.query(TaxProfile).filter_by(user_id=current_user.id).first()
    if not tax_profile:
        raise HTTPException(status_code=404, detail="Tax profile not found")
    return tax_profile

# ────────────────────────────────────────────────────────────
# INCOME ENDPOINTS
# ────────────────────────────────────────────────────────────
@app.post("/income/w2", response_model=IncomeRecordOut)
def add_w2_income(
    w2_data: W2IncomeIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Add W-2 income record"""
    income_record = IncomeRecord(
        user_id=current_user.id,
        income_type=IncomeType.W2,
        employer_name=w2_data.employer_name,
        employer_ein=w2_data.employer_ein,
        gross_income=w2_data.gross_income,
        federal_withholding=w2_data.federal_withholding,
        state_withholding=w2_data.state_withholding,
        social_security_wages=w2_data.social_security_wages,
        medicare_wages=w2_data.medicare_wages,
        state_wages=w2_data.state_wages,
        additional_data={
            "retirement_plan": w2_data.retirement_plan,
            "statutory_employee": w2_data.statutory_employee
        }
    )
    
    db.add(income_record)
    db.commit()
    db.refresh(income_record)
    return income_record

@app.post("/income/1099", response_model=IncomeRecordOut)
def add_1099_income(
    form_1099_data: Form1099In,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Add 1099 income record"""
    income_record = IncomeRecord(
        user_id=current_user.id,
        income_type=form_1099_data.income_type,
        employer_name=form_1099_data.payer_name,
        employer_ein=form_1099_data.payer_tin,
        gross_income=form_1099_data.amount,
        federal_withholding=form_1099_data.federal_withholding,
        state_withholding=form_1099_data.state_withholding,
        additional_data=form_1099_data.additional_info
    )
    
    db.add(income_record)
    db.commit()
    db.refresh(income_record)
    return income_record

@app.post("/income/self-employment", response_model=IncomeRecordOut)
def add_self_employment_income(
    se_data: SelfEmploymentIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Add self-employment income record"""
    income_record = IncomeRecord(
        user_id=current_user.id,
        income_type=IncomeType.SELF_EMPLOYMENT,
        employer_name=se_data.business_name,
        gross_income=se_data.gross_receipts,
        additional_data={
            "business_type": se_data.business_type,
            "total_expenses": str(se_data.total_expenses),
            "net_profit": str(se_data.net_profit),
            "schedule_c_expenses": {k: str(v) for k, v in se_data.schedule_c_expenses.items()}
        }
    )
    
    db.add(income_record)
    db.commit()
    db.refresh(income_record)
    return income_record

@app.get("/income", response_model=List[IncomeRecordOut])
def get_income_records(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all income records for current user"""
    return db.query(IncomeRecord).filter_by(user_id=current_user.id).all()

# ────────────────────────────────────────────────────────────
# DEDUCTION ENDPOINTS
# ────────────────────────────────────────────────────────────
@app.post("/deductions/itemized", response_model=DeductionRecordOut)
def add_itemized_deduction(
    deduction_data: ItemizedDeductionIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Add itemized deduction record"""
    deduction_record = DeductionRecord(
        user_id=current_user.id,
        deduction_type=DeductionType.ITEMIZED,
        category=deduction_data.category,
        description=deduction_data.description,
        amount=deduction_data.amount,
        state_specific=deduction_data.state_specific,
        state=deduction_data.state,
        additional_data={"supporting_documents": deduction_data.supporting_documents}
    )
    
    db.add(deduction_record)
    db.commit()
    db.refresh(deduction_record)
    return deduction_record

@app.post("/credits/education", response_model=DeductionRecordOut)
def add_education_credit(
    education_data: EducationCreditIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Add education credit record"""
    deduction_record = DeductionRecord(
        user_id=current_user.id,
        deduction_type=DeductionType.ITEMIZED,
        category="education_credit",
        description=f"Education credit for {education_data.student_name}",
        amount=education_data.tuition_paid,
        additional_data={
            "student_name": education_data.student_name,
            "student_ssn": education_data.student_ssn,
            "institution_name": education_data.institution_name,
            "institution_ein": education_data.institution_ein,
            "qualified_expenses": str(education_data.qualified_expenses),
            "form_1098t_received": education_data.form_1098t_received
        }
    )
    
    db.add(deduction_record)
    db.commit()
    db.refresh(deduction_record)
    return deduction_record

@app.post("/credits/child-tax", response_model=DeductionRecordOut)
def add_child_tax_credit(
    child_data: ChildTaxCreditIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Add child tax credit record"""
    # Calculate credit amount based on 2023 rules
    credit_amount = 2000 if child_data.under_age_17 else 500
    
    deduction_record = DeductionRecord(
        user_id=current_user.id,
        deduction_type=DeductionType.ITEMIZED,
        category="child_tax_credit",
        description=f"Child tax credit for {child_data.child_name}",
        amount=credit_amount,
        additional_data={
            "child_name": child_data.child_name,
            "child_ssn": child_data.child_ssn,
            "relationship": child_data.relationship,
            "months_lived_with_you": child_data.months_lived_with_you,
            "under_age_17": child_data.under_age_17,
            "us_citizen": child_data.us_citizen
        }
    )
    
    db.add(deduction_record)
    db.commit()
    db.refresh(deduction_record)
    return deduction_record

@app.post("/deductions/state-specific", response_model=DeductionRecordOut)
def add_state_specific_deduction(
    state_data: StateSpecificIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Add state-specific deduction"""
    deduction_record = DeductionRecord(
        user_id=current_user.id,
        deduction_type=DeductionType.ITEMIZED,
        category=state_data.deduction_type,
        description=state_data.description,
        amount=state_data.amount,
        state_specific=True,
        state=state_data.state,
        additional_data=state_data.additional_data
    )
    
    db.add(deduction_record)
    db.commit()
    db.refresh(deduction_record)
    return deduction_record

@app.get("/deductions", response_model=List[DeductionRecordOut])
def get_deduction_records(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all deduction records for current user"""
    return db.query(DeductionRecord).filter_by(user_id=current_user.id).all()

# ────────────────────────────────────────────────────────────
# DOCUMENT UPLOAD ENDPOINTS
# ────────────────────────────────────────────────────────────
@app.post("/documents/upload", response_model=DocumentOut)
def upload_tax_document(
    file: UploadFile = File(...),
    document_type: DocumentType = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Upload and process tax documents (PDF, images)"""
    
    # Validate file type
    allowed_types = ['application/pdf', 'image/jpeg', 'image/png', 'image/tiff']
    if file.content_type not in allowed_types:
        raise HTTPException(
            status_code=400, 
            detail=f"File type {file.content_type} not allowed. Use PDF or image files."
        )
    
    # Generate unique filename
    file_extension = os.path.splitext(file.filename)[1]
    unique_filename = f"{current_user.id}_{uuid.uuid4()}{file_extension}"
    file_path = os.path.join(UPLOAD_DIR, unique_filename)
    
    # Save file
    with open(file_path, "wb") as buffer:
        content = file.file.read()
        buffer.write(content)
    
    # Create document record
    document = Document(
        user_id=current_user.id,
        filename=unique_filename,
        original_filename=file.filename,
        document_type=document_type,
        file_path=file_path,
        file_size=len(content),
        mime_type=file.content_type
    )
    
    db.add(document)
    db.commit()
    db.refresh(document)
    
    # Process document
    extracted_data = process_document(file_path, document_type)
    document.extracted_data = extracted_data
    document.processed = True
    db.commit()
    
    return document

@app.get("/documents", response_model=List[DocumentOut])
def get_documents(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all uploaded documents for current user"""
    return db.query(Document).filter_by(user_id=current_user.id).all()

@app.get("/documents/{document_id}/extracted-data")
def get_extracted_data(
    document_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get extracted data from processed document"""
    document = db.query(Document).filter_by(
        id=document_id, 
        user_id=current_user.id
    ).first()
    
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    return {
        "document_id": document.id,
        "processed": document.processed,
        "extracted_data": document.extracted_data
    }

# ────────────────────────────────────────────────────────────
# THIRD-PARTY IMPORT ENDPOINTS (Simplified for demo)
# ────────────────────────────────────────────────────────────
@app.post("/import/payroll")
def import_from_payroll(
    import_request: ImportRequestIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Import data from payroll providers (ADP, Paychex, etc.)"""
    
    # Create import session
    import_session = ImportSession(
        user_id=current_user.id,
        provider=import_request.provider,
        status="success",
        imported_data={
            "provider": import_request.provider.value,
            "records_imported": 1,
            "data_types": import_request.data_types,
            "message": "Demo import completed successfully"
        },
        completed_at=datetime.utcnow()
    )
    db.add(import_session)
    db.commit()
    db.refresh(import_session)
    
    return {
        "message": f"Import from {import_request.provider} completed",
        "session_id": import_session.id,
        "status": "success"
    }

@app.get("/import/status/{session_id}")
def get_import_status(
    session_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get status of import session"""
    import_session = db.query(ImportSession).filter_by(
        id=session_id,
        user_id=current_user.id
    ).first()
    
    if not import_session:
        raise HTTPException(status_code=404, detail="Import session not found")
    
    return {
        "session_id": import_session.id,
        "provider": import_session.provider,
        "status": import_session.status,
        "created_at": import_session.created_at,
        "completed_at": import_session.completed_at,
        "error_message": import_session.error_message,
        "imported_records": len(import_session.imported_data.get("records", []))
    }

# ────────────────────────────────────────────────────────────
# MAIN
# ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
