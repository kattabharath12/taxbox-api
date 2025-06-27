# Create the complete AWS-deployable tax form system
import os

# Create the main application file
app_code = '''
import hashlib
import secrets
import sqlite3
import os
import uuid
import json
from datetime import datetime, timedelta, date
import re
import io
import mimetypes
from pathlib import Path
from enum import Enum
from flask import Flask, request, jsonify, render_template_string, send_from_directory
import threading
import time
import logging
from werkzeug.utils import secure_filename

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FormType(Enum):
    W2 = "W-2"
    FORM_1099_MISC = "1099-MISC"
    FORM_1099_NEC = "1099-NEC"
    FORM_1099_INT = "1099-INT"
    FORM_1099_DIV = "1099-DIV"

class StepStatus(Enum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    REQUIRES_REVIEW = "requires_review"
    ERROR = "error"
    AUTO_FILLED = "auto_filled"

class AutoFillSource(Enum):
    OCR_EXTRACTION = "ocr_extraction"
    PREVIOUS_FORM = "previous_form"
    USER_PROFILE = "user_profile"
    EMPLOYER_DATABASE = "employer_database"
    MANUAL_ENTRY = "manual_entry"

class PaymentStatus(Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    REFUNDED = "refunded"

class SubmissionStatus(Enum):
    IN_PROGRESS = "in_progress"
    SUBMITTED = "submitted"
    PROCESSING = "processing"
    APPROVED = "approved"
    REJECTED = "rejected"

class CompleteTaxFormSystem:
    def __init__(self, db_path=None, upload_dir=None):
        # AWS-compatible paths
        self.db_path = db_path or os.environ.get('DB_PATH', '/tmp/complete_tax_system.db')
        self.upload_dir = upload_dir or os.environ.get('UPLOAD_DIR', '/tmp/uploads')
        
        self.valid_states = ["Texas", "New York", "California", "Florida", "Illinois", "Washington", "Oregon"]
        self.allowed_extensions = {'.jpg', '.jpeg', '.png', '.pdf', '.tiff', '.tif'}
        self.max_file_size = 10 * 1024 * 1024  # 10MB
        
        # Create directories
        try:
            os.makedirs(self.upload_dir, exist_ok=True)
            os.makedirs(os.path.join(self.upload_dir, "processed"), exist_ok=True)
        except Exception as e:
            logger.error(f"Failed to create directories: {e}")
        
        # Initialize configurations
        self.form_wizards = self.initialize_form_wizards()
        self.ocr_field_mappings = self.initialize_ocr_mappings()
        self.payment_config = self.initialize_payment_config()
        
        # Initialize database
        self.init_database()
        
        # Start background status updater
        self.start_background_status_updater()
    
    def initialize_form_wizards(self):
        """Initialize complete form wizard configurations"""
        return {
            FormType.W2.value: {
                "title": "W-2 Wage and Tax Statement",
                "description": "Complete your W-2 form step by step with auto-fill and payment",
                "estimated_time": "10-15 minutes",
                "auto_fill_sources": ["user_profile", "previous_form", "ocr_extraction"],
                "processing_fee": 9.99,
                "steps": [
                    {
                        "id": "employer_info",
                        "title": "Employer Information",
                        "description": "Enter your employer's details",
                        "auto_fill_enabled": True,
                        "fields": [
                            {
                                "name": "employer_name", 
                                "type": "text", 
                                "label": "Employer Name", 
                                "required": True, 
                                "validation": "text",
                                "auto_fill_sources": ["ocr_extraction", "previous_form"],
                                "confidence_threshold": 0.8
                            },
                            {
                                "name": "employer_ein", 
                                "type": "text", 
                                "label": "Employer EIN", 
                                "required": True, 
                                "validation": "ein", 
                                "placeholder": "XX-XXXXXXX",
                                "auto_fill_sources": ["ocr_extraction", "previous_form"],
                                "confidence_threshold": 0.9
                            },
                            {
                                "name": "employer_address", 
                                "type": "textarea", 
                                "label": "Employer Address", 
                                "required": True,
                                "auto_fill_sources": ["ocr_extraction", "previous_form"],
                                "confidence_threshold": 0.7
                            },
                            {
                                "name": "employer_city", 
                                "type": "text", 
                                "label": "City", 
                                "required": True,
                                "auto_fill_sources": ["ocr_extraction", "previous_form"],
                                "confidence_threshold": 0.8
                            },
                            {
                                "name": "employer_state", 
                                "type": "select", 
                                "label": "State", 
                                "required": True, 
                                "options": self.valid_states,
                                "auto_fill_sources": ["ocr_extraction", "previous_form"],
                                "confidence_threshold": 0.8
                            },
                            {
                                "name": "employer_zip", 
                                "type": "text", 
                                "label": "ZIP Code", 
                                "required": True, 
                                "validation": "zip",
                                "auto_fill_sources": ["ocr_extraction", "previous_form"],
                                "confidence_threshold": 0.9
                            }
                        ]
                    },
                    {
                        "id": "employee_info",
                        "title": "Employee Information",
                        "description": "Verify your personal information",
                        "auto_fill_enabled": True,
                        "fields": [
                            {
                                "name": "employee_ssn", 
                                "type": "text", 
                                "label": "Your SSN", 
                                "required": True, 
                                "validation": "ssn", 
                                "placeholder": "XXX-XX-XXXX",
                                "auto_fill_sources": ["user_profile", "ocr_extraction"],
                                "confidence_threshold": 0.95
                            },
                            {
                                "name": "employee_name", 
                                "type": "text", 
                                "label": "Your Full Name", 
                                "required": True,
                                "auto_fill_sources": ["user_profile", "ocr_extraction"],
                                "confidence_threshold": 0.8
                            },
                            {
                                "name": "employee_address", 
                                "type": "textarea", 
                                "label": "Your Address", 
                                "required": True,
                                "auto_fill_sources": ["user_profile", "ocr_extraction"],
                                "confidence_threshold": 0.7
                            },
                            {
                                "name": "employee_city", 
                                "type": "text", 
                                "label": "City", 
                                "required": True,
                                "auto_fill_sources": ["user_profile", "ocr_extraction"],
                                "confidence_threshold": 0.8
                            },
                            {
                                "name": "employee_state", 
                                "type": "select", 
                                "label": "State", 
                                "required": True, 
                                "options": self.valid_states,
                                "auto_fill_sources": ["user_profile", "ocr_extraction"],
                                "confidence_threshold": 0.8
                            },
                            {
                                "name": "employee_zip", 
                                "type": "text", 
                                "label": "ZIP Code", 
                                "required": True, 
                                "validation": "zip",
                                "auto_fill_sources": ["user_profile", "ocr_extraction"],
                                "confidence_threshold": 0.9
                            }
                        ]
                    },
                    {
                        "id": "wage_info",
                        "title": "Wage and Tax Information",
                        "description": "Enter wage and tax withholding amounts",
                        "auto_fill_enabled": True,
                        "fields": [
                            {
                                "name": "wages", 
                                "type": "currency", 
                                "label": "Wages, tips, other compensation (Box 1)", 
                                "required": True, 
                                "validation": "currency",
                                "auto_fill_sources": ["ocr_extraction"],
                                "confidence_threshold": 0.85
                            },
                            {
                                "name": "federal_tax", 
                                "type": "currency", 
                                "label": "Federal income tax withheld (Box 2)", 
                                "required": True, 
                                "validation": "currency",
                                "auto_fill_sources": ["ocr_extraction"],
                                "confidence_threshold": 0.85
                            },
                            {
                                "name": "social_security_wages", 
                                "type": "currency", 
                                "label": "Social security wages (Box 3)", 
                                "required": False, 
                                "validation": "currency",
                                "auto_fill_sources": ["ocr_extraction"],
                                "confidence_threshold": 0.85
                            },
                            {
                                "name": "social_security_tax", 
                                "type": "currency", 
                                "label": "Social security tax withheld (Box 4)", 
                                "required": False, 
                                "validation": "currency",
                                "auto_fill_sources": ["ocr_extraction"],
                                "confidence_threshold": 0.85
                            },
                            {
                                "name": "medicare_wages", 
                                "type": "currency", 
                                "label": "Medicare wages and tips (Box 5)", 
                                "required": False, 
                                "validation": "currency",
                                "auto_fill_sources": ["ocr_extraction"],
                                "confidence_threshold": 0.85
                            },
                            {
                                "name": "medicare_tax", 
                                "type": "currency", 
                                "label": "Medicare tax withheld (Box 6)", 
                                "required": False, 
                                "validation": "currency",
                                "auto_fill_sources": ["ocr_extraction"],
                                "confidence_threshold": 0.85
                            }
                        ]
                    },
                    {
                        "id": "document_upload",
                        "title": "Document Upload",
                        "description": "Upload your W-2 document for auto-fill and verification",
                        "auto_fill_enabled": False,
                        "fields": [
                            {
                                "name": "document_file", 
                                "type": "file", 
                                "label": "Upload W-2 Document", 
                                "required": True, 
                                "accept": ".jpg,.jpeg,.png,.pdf,.tiff,.tif"
                            }
                        ]
                    },
                    {
                        "id": "payment",
                        "title": "Payment Information",
                        "description": "Complete payment for form processing",
                        "auto_fill_enabled": False,
                        "fields": [
                            {
                                "name": "payment_type",
                                "type": "select",
                                "label": "Payment Type",
                                "required": True,
                                "options": ["Processing Fee", "Tax Payment", "Refund Request"]
                            },
                            {
                                "name": "amount",
                                "type": "currency",
                                "label": "Amount",
                                "required": True,
                                "validation": "currency"
                            },
                            {
                                "name": "payment_method",
                                "type": "select",
                                "label": "Payment Method",
                                "required": True,
                                "options": ["Stripe", "PayPal"]
                            }
                        ]
                    },
                    {
                        "id": "review",
                        "title": "Review and Edit",
                        "description": "Review all auto-filled data, make edits, and confirm payment",
                        "auto_fill_enabled": False,
                        "review_step": True,
                        "fields": [
                            {
                                "name": "data_confirmation", 
                                "type": "checkbox", 
                                "label": "I confirm that all information is accurate after review", 
                                "required": True
                            },
                            {
                                "name": "payment_confirmation", 
                                "type": "checkbox", 
                                "label": "I authorize the payment for form processing", 
                                "required": True
                            }
                        ]
                    }
                ]
            }
        }
    
    def initialize_ocr_mappings(self):
        """Initialize OCR field mapping configurations"""
        return {
            FormType.W2.value: {
                "box_mappings": {
                    "1": "wages",
                    "2": "federal_tax",
                    "3": "social_security_wages",
                    "4": "social_security_tax",
                    "5": "medicare_wages",
                    "6": "medicare_tax"
                },
                "text_patterns": {
                    "employer_ein": r'\\b\\d{2}-\\d{7}\\b',
                    "employee_ssn": r'\\b\\d{3}-\\d{2}-\\d{4}\\b',
                    "zip_code": r'\\b\\d{5}(-\\d{4})?\\b',
                    "currency": r'\\$?[\\d,]+\\.?\\d{0,2}'
                }
            }
        }
    
    def initialize_payment_config(self):
        """Initialize payment configuration"""
        return {
            "stripe": {
                "publishable_key": os.environ.get('STRIPE_PUBLISHABLE_KEY', 'pk_test_51234567890abcdef'),
                "secret_key": os.environ.get('STRIPE_SECRET_KEY', 'sk_test_51234567890abcdef'),
                "webhook_secret": os.environ.get('STRIPE_WEBHOOK_SECRET', 'whsec_test_123456789')
            },
            "paypal": {
                "client_id": os.environ.get('PAYPAL_CLIENT_ID', 'sb'),
                "client_secret": os.environ.get('PAYPAL_CLIENT_SECRET', 'test_secret'),
                "mode": os.environ.get('PAYPAL_MODE', 'sandbox')
            },
            "processing_fees": {
                FormType.W2.value: 9.99,
                FormType.FORM_1099_MISC.value: 7.99
            }
        }
    
    def init_database(self):
        """Initialize complete database with all required tables"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    is_verified BOOLEAN DEFAULT FALSE,
                    verification_token TEXT,
                    mfa_enabled BOOLEAN DEFAULT FALSE,
                    mfa_secret TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            ''')
            
            # User profiles table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER UNIQUE NOT NULL,
                    first_name TEXT,
                    last_name TEXT,
                    ssn_encrypted TEXT,
                    date_of_birth DATE,
                    address_line1 TEXT,
                    address_line2 TEXT,
                    city TEXT,
                    state TEXT,
                    zip_code TEXT,
                    profile_completed BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')
            
            # Form wizard sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS form_wizard_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    form_type TEXT NOT NULL,
                    session_id TEXT UNIQUE NOT NULL,
                    current_step_id TEXT NOT NULL,
                    current_step_index INTEGER DEFAULT 0,
                    total_steps INTEGER NOT NULL,
                    form_data TEXT,
                    step_statuses TEXT,
                    auto_fill_data TEXT,
                    manual_overrides TEXT,
                    payment_data TEXT,
                    progress_percentage INTEGER DEFAULT 0,
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    is_completed BOOLEAN DEFAULT FALSE,
                    payment_required BOOLEAN DEFAULT TRUE,
                    payment_completed BOOLEAN DEFAULT FALSE,
                    submission_status TEXT DEFAULT 'in_progress',
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')
            
            # Payments table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS payments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    session_id TEXT NOT NULL,
                    payment_intent_id TEXT UNIQUE,
                    paypal_order_id TEXT,
                    amount REAL NOT NULL,
                    currency TEXT DEFAULT 'USD',
                    payment_method TEXT NOT NULL,
                    payment_type TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    stripe_payment_method_id TEXT,
                    paypal_capture_id TEXT,
                    failure_reason TEXT,
                    refund_id TEXT,
                    refund_amount REAL,
                    refund_reason TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    completed_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')
            
            # Auto-fill audit table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS auto_fill_audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    field_name TEXT NOT NULL,
                    auto_fill_source TEXT NOT NULL,
                    original_value TEXT,
                    confidence_score REAL,
                    user_accepted BOOLEAN DEFAULT NULL,
                    user_modified_value TEXT,
                    modification_timestamp TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Document uploads table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS document_uploads (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    session_id TEXT,
                    document_type TEXT NOT NULL,
                    original_filename TEXT NOT NULL,
                    stored_filename TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    mime_type TEXT NOT NULL,
                    upload_method TEXT NOT NULL,
                    processing_status TEXT DEFAULT 'pending',
                    ocr_extracted_data TEXT,
                    ocr_confidence_scores TEXT,
                    auto_fill_applied BOOLEAN DEFAULT FALSE,
                    extracted_data TEXT,
                    verification_status TEXT DEFAULT 'unverified',
                    upload_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    processed_timestamp TIMESTAMP,
                    notes TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')
            
            # Form submissions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS form_submissions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    session_id TEXT NOT NULL,
                    form_type TEXT NOT NULL,
                    form_data TEXT NOT NULL,
                    document_ids TEXT,
                    payment_id INTEGER,
                    auto_fill_summary TEXT,
                    manual_override_summary TEXT,
                    submission_status TEXT DEFAULT 'submitted',
                    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    processed_at TIMESTAMP,
                    notes TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                    FOREIGN KEY (payment_id) REFERENCES payments (id)
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
    
    def start_background_status_updater(self):
        """Start background thread to simulate status updates"""
        def update_statuses():
            while True:
                try:
                    time.sleep(30)  # Check every 30 seconds
                    self.simulate_status_updates()
                except Exception as e:
                    logger.error(f"Status update error: {e}")
        
        thread = threading.Thread(target=update_statuses, daemon=True)
        thread.start()
    
    def simulate_status_updates(self):
        """Simulate realistic status updates for demo purposes"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Update submitted forms to processing after 1 minute
            cursor.execute('''
                UPDATE form_submissions 
                SET submission_status = 'processing', processed_at = CURRENT_TIMESTAMP
                WHERE submission_status = 'submitted' 
                AND datetime(submitted_at, '+1 minute') <= datetime('now')
            ''')
            
            # Update processing forms to approved after 2 minutes
            cursor.execute('''
                UPDATE form_submissions 
                SET submission_status = 'approved'
                WHERE submission_status = 'processing' 
                AND datetime(processed_at, '+2 minutes') <= datetime('now')
            ''')
            
            # Update wizard sessions status to match submissions
            cursor.execute('''
                UPDATE form_wizard_sessions 
                SET submission_status = (
                    SELECT submission_status FROM form_submissions 
                    WHERE form_submissions.session_id = form_wizard_sessions.session_id
                )
                WHERE session_id IN (
                    SELECT session_id FROM form_submissions
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"Status update simulation error: {e}")
    
    # Authentication methods
    def validate_email(self, email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def hash_password(self, password, salt=None):
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(32)
        
        password_hash = hashlib.pbkdf2_hmac('sha256', 
                                          password.encode('utf-8'), 
                                          salt.encode('utf-8'), 
                                          100000)
        return password_hash.hex(), salt
    
    def register_user(self, email, password):
        """Register a new user"""
        try:
            if not self.validate_email(email):
                return {"success": False, "message": "Invalid email format"}
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
            if cursor.fetchone():
                return {"success": False, "message": "Email already registered"}
            
            password_hash, salt = self.hash_password(password)
            verification_token = secrets.token_urlsafe(32)
            
            cursor.execute('''
                INSERT INTO users (email, password_hash, salt, verification_token)
                VALUES (?, ?, ?, ?)
            ''', (email, password_hash, salt, verification_token))
            
            user_id = cursor.lastrowid
            
            cursor.execute('''
                INSERT INTO user_profiles (user_id) VALUES (?)
            ''', (user_id,))
            
            conn.commit()
            conn.close()
            
            return {
                "success": True, 
                "message": "Registration successful",
                "user_id": user_id
            }
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return {"success": False, "message": f"Registration failed: {str(e)}"}
    
    def login_user(self, email, password):
        """Login user"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT id, password_hash, salt FROM users WHERE email = ?", (email,))
            result = cursor.fetchone()
            
            if not result:
                return {"success": False, "message": "Invalid email or password"}
            
            user_id, stored_hash, salt = result
            password_hash, _ = self.hash_password(password, salt)
            
            if password_hash == stored_hash:
                cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
                conn.commit()
                conn.close()
                return {"success": True, "user_id": user_id, "message": "Login successful"}
            else:
                conn.close()
                return {"success": False, "message": "Invalid email or password"}
                
        except Exception as e:
            logger.error(f"Login error: {e}")
            return {"success": False, "message": f"Login failed: {str(e)}"}
    
    # Form wizard methods
    def start_form_wizard(self, user_id, form_type):
        """Start a new form wizard session"""
        try:
            if form_type not in self.form_wizards:
                return {"success": False, "message": "Invalid form type"}
            
            wizard_config = self.form_wizards[form_type]
            session_id = str(uuid.uuid4())
            
            # Initialize step statuses
            step_statuses = {}
            for i, step in enumerate(wizard_config["steps"]):
                step_statuses[step["id"]] = {
                    "status": StepStatus.NOT_STARTED.value if i > 0 else StepStatus.IN_PROGRESS.value,
                    "completed_at": None,
                    "validation_errors": []
                }
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
            if not cursor.fetchone():
                return {"success": False, "message": "User not found"}
            
            processing_fee = self.payment_config["processing_fees"].get(form_type, 0.00)
            
            cursor.execute('''
                INSERT INTO form_wizard_sessions (
                    user_id, form_type, session_id, current_step_id, 
                    current_step_index, total_steps, form_data, step_statuses,
                    payment_required, payment_completed, submission_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id, form_type, session_id, wizard_config["steps"][0]["id"],
                0, len(wizard_config["steps"]), '{}', json.dumps(step_statuses),
                True, False, 'in_progress'
            ))
            
            conn.commit()
            conn.close()
            
            return {
                "success": True,
                "session_id": session_id,
                "wizard_config": wizard_config,
                "current_step": wizard_config["steps"][0],
                "processing_fee": processing_fee,
                "progress": {
                    "current_step": 1,
                    "total_steps": len(wizard_config["steps"]),
                    "percentage": 0
                }
            }
            
        except Exception as e:
            logger.error(f"Start wizard error: {e}")
            return {"success": False, "message": f"Failed to start wizard: {str(e)}"}
    
    def get_session_data(self, user_id, session_id):
        """Get session data for resuming"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT form_type, current_step_index, form_data, auto_fill_data, 
                       payment_completed, submission_status
                FROM form_wizard_sessions
                WHERE user_id = ? AND session_id = ?
            ''', (user_id, session_id))
            
            result = cursor.fetchone()
            if not result:
                return {"success": False, "message": "Session not found"}
            
            form_type, current_step_index, form_data_str, auto_fill_str, payment_completed, submission_status = result
            
            wizard_config = self.form_wizards[form_type]
            
            conn.close()
            
            return {
                "success": True,
                "wizard_config": wizard_config,
                "current_step_index": current_step_index,
                "current_step": wizard_config["steps"][current_step_index],
                "form_data": json.loads(form_data_str) if form_data_str else {},
                "auto_fill_data": json.loads(auto_fill_str) if auto_fill_str else {},
                "payment_completed": payment_completed,
                "submission_status": submission_status
            }
            
        except Exception as e:
            logger.error(f"Get session error: {e}")
            return {"success": False, "message": f"Failed to get session: {str(e)}"}
    
    # OCR and Auto-fill methods
    def extract_data_from_document(self, file_path, form_type):
        """Extract data from uploaded document using OCR (mock implementation)"""
        try:
            # Mock OCR extraction with realistic data
            mock_extracted_data = {
                "employer_name": "ABC Corporation Inc.",
                "employer_ein": "12-3456789",
                "employer_address": "123 Business Ave",
                "employer_city": "Austin",
                "employer_state": "Texas",
                "employer_zip": "78701",
                "employee_name": "John Doe",
                "employee_ssn": "123-45-6789",
                "employee_address": "456 Main St",
                "employee_city": "Austin",
                "employee_state": "Texas",
                "employee_zip": "78702",
                "wages": "50000.00",
                "federal_tax": "7500.00",
                "social_security_wages": "50000.00",
                "social_security_tax": "3100.00",
                "medicare_wages": "50000.00",
                "medicare_tax": "725.00"
            }
            
            confidence_scores = {field: 0.85 + (hash(field) % 15) / 100 for field in mock_extracted_data.keys()}
            
            return {
                "success": True,
                "extracted_data": mock_extracted_data,
                "confidence_scores": confidence_scores
            }
            
        except Exception as e:
            logger.error(f"OCR extraction error: {e}")
            return {
                "success": False,
                "error": f"OCR extraction failed: {str(e)}"
            }
    
    def apply_auto_fill_to_session(self, user_id, session_id, extracted_data):
        """Apply auto-fill data to session"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT form_type, auto_fill_data FROM form_wizard_sessions
                WHERE user_id = ? AND session_id = ?
            ''', (user_id, session_id))
            
            result = cursor.fetchone()
            if not result:
                return {"success": False, "message": "Session not found"}
            
            form_type, existing_auto_fill = result
            auto_fill_data = json.loads(existing_auto_fill) if existing_auto_fill else {}
            
            wizard_config = self.form_wizards[form_type]
            
            # Apply auto-fill to each step
            for step in wizard_config["steps"]:
                if step.get("auto_fill_enabled", False):
                    step_id = step["id"]
                    if step_id not in auto_fill_data:
                        auto_fill_data[step_id] = {}
                    
                    for field in step["fields"]:
                        field_name = field["name"]
                        if field_name in extracted_data:
                            auto_fill_data[step_id][field_name] = extracted_data[field_name]
                            auto_fill_data[step_id][f"_auto_fill_source_{field_name}"] = AutoFillSource.OCR_EXTRACTION.value
                            auto_fill_data[step_id][f"_confidence_{field_name}"] = 0.85
            
            cursor.execute('''
                UPDATE form_wizard_sessions SET
                    auto_fill_data = ?,
                    last_updated = CURRENT_TIMESTAMP
                WHERE user_id = ? AND session_id = ?
            ''', (json.dumps(auto_fill_data), user_id, session_id))
            
            conn.commit()
            conn.close()
            
            return {
                "success": True,
                "auto_fill_data": auto_fill_data,
                "fields_auto_filled": len(extracted_data)
            }
            
        except Exception as e:
            logger.error(f"Auto-fill error: {e}")
            return {"success": False, "message": f"Auto-fill failed: {str(e)}"}
    
    # Payment methods (mock implementations for AWS deployment)
    def create_stripe_payment_intent(self, user_id, session_id, amount, payment_type):
        """Create Stripe payment intent (mock for demo)"""
        try:
            payment_intent_id = f"pi_mock_{uuid.uuid4().hex[:16]}"
            client_secret = f"{payment_intent_id}_secret_mock"
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO payments (
                    user_id, session_id, payment_intent_id, amount, 
                    payment_method, payment_type, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id, session_id, payment_intent_id, amount,
                'Stripe', payment_type, 'pending'
            ))
            
            conn.commit()
            conn.close()
            
            return {
                "success": True,
                "client_secret": client_secret,
                "payment_intent_id": payment_intent_id
            }
            
        except Exception as e:
            logger.error(f"Stripe payment error: {e}")
            return {"success": False, "error": str(e)}
    
    def confirm_stripe_payment(self, payment_intent_id, payment_method_id):
        """Confirm Stripe payment (mock for demo)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE payments SET
                    status = 'completed',
                    stripe_payment_method_id = ?,
                    completed_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE payment_intent_id = ?
            ''', (payment_method_id, payment_intent_id))
            
            cursor.execute('''
                UPDATE form_wizard_sessions SET
                    payment_completed = 1
                WHERE session_id = (
                    SELECT session_id FROM payments WHERE payment_intent_id = ?
                )
            ''', (payment_intent_id,))
            
            conn.commit()
            conn.close()
            
            return {
                "success": True,
                "status": "completed"
            }
            
        except Exception as e:
            logger.error(f"Stripe confirm error: {e}")
            return {"success": False, "error": str(e)}
    
    def create_paypal_order(self, user_id, session_id, amount, payment_type):
        """Create PayPal order (mock for demo)"""
        try:
            order_id = f"PAYPAL_{uuid.uuid4().hex[:8].upper()}"
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO payments (
                    user_id, session_id, paypal_order_id, amount, 
                    payment_method, payment_type, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id, session_id, order_id, amount,
                'PayPal', payment_type, 'pending'
            ))
            
            conn.commit()
            conn.close()
            
            return {
                "success": True,
                "order_id": order_id,
                "approval_url": f"https://www.sandbox.paypal.com/checkoutnow?token={order_id}"
            }
            
        except Exception as e:
            logger.error(f"PayPal order error: {e}")
            return {"success": False, "error": str(e)}
    
    def capture_paypal_payment(self, order_id):
        """Capture PayPal payment (mock for demo)"""
        try:
            capture_id = f"CAPTURE_{uuid.uuid4().hex[:8].upper()}"
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE payments SET
                    status = 'completed',
                    paypal_capture_id = ?,
                    completed_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE paypal_order_id = ?
            ''', (capture_id, order_id))
            
            cursor.execute('''
                UPDATE form_wizard_sessions SET
                    payment_completed = 1
                WHERE session_id = (
                    SELECT session_id FROM payments WHERE paypal_order_id = ?
                )
            ''', (order_id,))
            
            conn.commit()
            conn.close()
            
            return {
                "success": True,
                "capture_id": capture_id,
                "status": "completed"
            }
            
        except Exception as e:
            logger.error(f"PayPal capture error: {e}")
            return {"success": False, "error": str(e)}
    
    # Dashboard and tracking methods
    def get_dashboard_data(self, user_id):
        """Get comprehensive dashboard data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get in-progress sessions
            cursor.execute('''
                SELECT session_id, form_type, started_at, last_updated, 
                       progress_percentage, submission_status, payment_completed
                FROM form_wizard_sessions
                WHERE user_id = ? AND is_completed = 0
                ORDER BY last_updated DESC
            ''', (user_id,))
            
            in_progress = []
            for row in cursor.fetchall():
                session_id, form_type, started_at, last_updated, progress, status, payment_completed = row
                in_progress.append({
                    "session_id": session_id,
                    "form_type": form_type,
                    "started_at": started_at,
                    "last_updated": last_updated,
                    "progress_percentage": progress or 0,
                    "status": "In Progress",
                    "payment_completed": bool(payment_completed),
                    "can_resume": True
                })
            
            # Get submitted forms
            cursor.execute('''
                SELECT fs.session_id, fs.form_type, fs.submitted_at, fs.submission_status,
                       p.amount, p.payment_method, p.status as payment_status
                FROM form_submissions fs
                LEFT JOIN payments p ON fs.payment_id = p.id
                WHERE fs.user_id = ?
                ORDER BY fs.submitted_at DESC
            ''', (user_id,))
            
            submissions = []
            for row in cursor.fetchall():
                session_id, form_type, submitted_at, status, amount, payment_method, payment_status = row
                
                display_status = {
                    "submitted": "Submitted",
                    "processing": "Processing", 
                    "approved": "Accepted",
                    "rejected": "Rejected"
                }.get(status, status.capitalize() if status else "Unknown")
                
                submissions.append({
                    "session_id": session_id,
                    "form_type": form_type,
                    "submitted_at": submitted_at,
                    "status": display_status,
                    "status_color": {
                        "Submitted": "#007bff",
                        "Processing": "#ffc107",
                        "Accepted": "#28a745",
                        "Rejected": "#dc3545"
                    }.get(display_status, "#6c757d"),
                    "payment_amount": amount,
                    "payment_method": payment_method,
                    "payment_status": payment_status
                })
            
            # Get summary statistics
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_forms,
                    SUM(CASE WHEN is_completed = 1 THEN 1 ELSE 0 END) as completed_forms,
                    SUM(CASE WHEN payment_completed = 1 THEN 1 ELSE 0 END) as paid_forms
                FROM form_wizard_sessions
                WHERE user_id = ?
            ''', (user_id,))
            
            stats = cursor.fetchone()
            total_forms, completed_forms, paid_forms = stats if stats else (0, 0, 0)
            
            conn.close()
            
            return {
                "success": True,
                "dashboard_data": {
                    "in_progress": in_progress,
                    "submissions": submissions,
                    "summary": {
                        "total_forms": total_forms,
                        "completed_forms": completed_forms,
                        "in_progress_forms": len(in_progress),
                        "paid_forms": paid_forms
                    }
                }
            }
            
        except Exception as e:
            logger.error(f"Dashboard error: {e}")
            return {"success": False, "message": f"Failed to get dashboard data: {str(e)}"}
    
    # Review and submission methods
    def get_comprehensive_review_data(self, user_id, session_id):
        """Get complete review data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT form_type, form_data, auto_fill_data, manual_overrides, 
                       payment_completed, payment_data
                FROM form_wizard_sessions
                WHERE user_id = ? AND session_id = ?
            ''', (user_id, session_id))
            
            result = cursor.fetchone()
            if not result:
                return {"success": False, "message": "Session not found"}
            
            form_type, form_data_str, auto_fill_str, overrides_str, payment_completed, payment_data_str = result
            
            form_data = json.loads(form_data_str) if form_data_str else {}
            auto_fill_data = json.loads(auto_fill_str) if auto_fill_str else {}
            manual_overrides = json.loads(overrides_str) if overrides_str else {}
            
            # Get payment information
            cursor.execute('''
                SELECT amount, payment_method, payment_type, status, created_at
                FROM payments
                WHERE session_id = ?
                ORDER BY created_at DESC
                LIMIT 1
            ''', (session_id,))
            
            payment_info = cursor.fetchone()
            
            wizard_config = self.form_wizards[form_type]
            
            review_data = {
                "form_info": {
                    "title": wizard_config["title"],
                    "form_type": form_type,
                    "processing_fee": wizard_config.get("processing_fee", 0.00)
                },
                "steps": {},
                "payment_info": {
                    "required": True,
                    "completed": bool(payment_completed),
                    "amount": payment_info[0] if payment_info else 0.00,
                    "method": payment_info[1] if payment_info else None,
                    "type": payment_info[2] if payment_info else None,
                    "status": payment_info[3] if payment_info else "pending"
                },
                "summary": {
                    "total_fields": 0,
                    "auto_filled_fields": 0,
                    "overridden_fields": 0,
                    "manual_fields": 0
                }
            }
            
            # Process each step
            for step in wizard_config["steps"]:
                if step["id"] in ["review", "payment"]:
                    continue
                
                step_id = step["id"]
                step_form_data = form_data.get(step_id, {})
                step_auto_fill = auto_fill_data.get(step_id, {})
                step_overrides = manual_overrides.get(step_id, {})
                
                review_data["steps"][step_id] = {
                    "title": step["title"],
                    "fields": {}
                }
                
                for field in step["fields"]:
                    field_name = field["name"]
                    
                    if field_name in step_form_data:
                        is_auto_filled = field_name in step_auto_fill
                        is_overridden = field_name in step_overrides
                        
                        field_info = {
                            "label": field["label"],
                            "value": step_form_data[field_name],
                            "type": field["type"],
                            "is_auto_filled": is_auto_filled,
                            "auto_fill_source": step_auto_fill.get(f"_auto_fill_source_{field_name}"),
                            "confidence": step_auto_fill.get(f"_confidence_{field_name}"),
                            "is_overridden": is_overridden,
                            "original_auto_fill_value": step_overrides.get(field_name, {}).get("auto_fill_value"),
                            "editable": True
                        }
                        
                        review_data["steps"][step_id]["fields"][field_name] = field_info
                        
                        # Update summary
                        review_data["summary"]["total_fields"] += 1
                        if is_auto_filled:
                            review_data["summary"]["auto_filled_fields"] += 1
                        if is_overridden:
                            review_data["summary"]["overridden_fields"] += 1
                        if not is_auto_filled:
                            review_data["summary"]["manual_fields"] += 1
            
            conn.close()
            
            return {
                "success": True,
                "review_data": review_data
            }
            
        except Exception as e:
            logger.error(f"Review data error: {e}")
            return {"success": False, "message": f"Failed to get review data: {str(e)}"}
    
    def submit_complete_form(self, user_id, session_id):
        """Submit complete form with all validations"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get session data
            cursor.execute('''
                SELECT form_type, form_data, step_statuses, total_steps, 
                       payment_completed, auto_fill_data, manual_overrides
                FROM form_wizard_sessions
                WHERE user_id = ? AND session_id = ?
            ''', (user_id, session_id))
            
            result = cursor.fetchone()
            if not result:
                return {"success": False, "message": "Session not found"}
            
            form_type, form_data_str, step_statuses_str, total_steps, payment_completed, auto_fill_str, overrides_str = result
            
            # Validate payment completion
            if not payment_completed:
                return {"success": False, "message": "Payment must be completed before submission"}
            
            form_data = json.loads(form_data_str) if form_data_str else {}
            auto_fill_data = json.loads(auto_fill_str) if auto_fill_str else {}
            manual_overrides = json.loads(overrides_str) if overrides_str else {}
            
            # Get associated documents and payment
            cursor.execute('''
                SELECT id FROM document_uploads WHERE session_id = ?
            ''', (session_id,))
            document_ids = [row[0] for row in cursor.fetchall()]
            
            cursor.execute('''
                SELECT id FROM payments WHERE session_id = ? AND status = 'completed'
                ORDER BY created_at DESC LIMIT 1
            ''', (session_id,))
            payment_result = cursor.fetchone()
            payment_id = payment_result[0] if payment_result else None
            
            # Create submission summary
            auto_fill_summary = {
                "total_auto_filled": sum(len([f for f in step.keys() if not f.startswith('_')]) 
                                       for step in auto_fill_data.values()),
                "sources_used": list(set([
                    v for step in auto_fill_data.values() 
                    for k, v in step.items() 
                    if k.startswith('_auto_fill_source_')
                ])),
                "average_confidence": 0.85
            }
            
            override_summary = {
                "total_overridden": sum(len(step.keys()) for step in manual_overrides.values()),
                "override_details": manual_overrides
            }
            
            # Create form submission
            cursor.execute('''
                INSERT INTO form_submissions (
                    user_id, session_id, form_type, form_data, document_ids,
                    payment_id, auto_fill_summary, manual_override_summary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_id, session_id, form_type, 
                json.dumps(form_data), json.dumps(document_ids),
                payment_id, json.dumps(auto_fill_summary), json.dumps(override_summary)
            ))
            
            submission_id = cursor.lastrowid
            
            # Mark wizard session as completed
            cursor.execute('''
                UPDATE form_wizard_sessions SET
                    is_completed = 1,
                    completed_at = CURRENT_TIMESTAMP,
                    progress_percentage = 100,
                    submission_status = 'submitted'
                WHERE user_id = ? AND session_id = ?
            ''', (user_id, session_id))
            
            conn.commit()
            conn.close()
            
            return {
                "success": True,
                "submission_id": submission_id,
                "message": "Form submitted successfully",
                "summary": {
                    "auto_fill_summary": auto_fill_summary,
                    "override_summary": override_summary,
                    "payment_completed": True,
                    "documents_uploaded": len(document_ids)
                }
            }
            
        except Exception as e:
            logger.error(f"Submission error: {e}")
            return {"success": False, "message": f"Submission failed: {str(e)}"}

# Flask Application
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize the tax system
tax_system = CompleteTaxFormSystem()

# Health check endpoint for AWS
@app.route('/health')
def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

# API Routes
@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.json
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({"success": False, "message": "Email and password required"})
        return jsonify(tax_system.register_user(data['email'], data['password']))
    except Exception as e:
        logger.error(f"Register endpoint error: {e}")
        return jsonify({"success": False, "message": "Registration failed"})

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.json
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({"success": False, "message": "Email and password required"})
        return jsonify(tax_system.login_user(data['email'], data['password']))
    except Exception as e:
        logger.error(f"Login endpoint error: {e}")
        return jsonify({"success": False, "message": "Login failed"})

@app.route('/api/dashboard', methods=['POST'])
def dashboard():
    try:
        data = request.json
        if not data or 'user_id' not in data:
            return jsonify({"success": False, "message": "User ID required"})
        return jsonify(tax_system.get_dashboard_data(data['user_id']))
    except Exception as e:
        logger.error(f"Dashboard endpoint error: {e}")
        return jsonify({"success": False, "message": "Dashboard failed"})

@app.route('/api/start_wizard', methods=['POST'])
def start_wizard():
    try:
        data = request.json
        if not data or 'user_id' not in data or 'form_type' not in data:
            return jsonify({"success": False, "message": "User ID and form type required"})
        return jsonify(tax_system.start_form_wizard(data['user_id'], data['form_type']))
    except Exception as e:
        logger.error(f"Start wizard endpoint error: {e}")
        return jsonify({"success": False, "message": "Failed to start wizard"})

@app.route('/api/resume_session', methods=['POST'])
def resume_session():
    try:
        data = request.json
        if not data or 'user_id' not in data or 'session_id' not in data:
            return jsonify({"success": False, "message": "User ID and session ID required"})
        return jsonify(tax_system.get_session_data(data['user_id'], data['session_id']))
    except Exception as e:
        logger.error(f"Resume session endpoint error: {e}")
        return jsonify({"success": False, "message": "Failed to resume session"})

@app.route('/api/upload_document', methods=['POST'])
def upload_document():
    try:
        user_id = request.form.get('user_id')
        session_id = request.form.get('session_id')
        form_type = request.form.get('form_type')
        
        if not all([user_id, session_id, form_type]):
            return jsonify({"success": False, "message": "Missing required parameters"})
        
        if 'file' not in request.files:
            return jsonify({"success": False, "message": "No file uploaded"})
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({"success": False, "message": "No file selected"})
        
        # Save file
        filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
        file_path = os.path.join(tax_system.upload_dir, filename)
        file.save(file_path)
        
        # Extract data and apply auto-fill
        extraction_result = tax_system.extract_data_from_document(file_path, form_type)
        if extraction_result["success"]:
            auto_fill_result = tax_system.apply_auto_fill_to_session(
                user_id, session_id, extraction_result["extracted_data"]
            )
            return jsonify({
                "success": True,
                "extraction_result": extraction_result,
                "auto_fill_result": auto_fill_result
            })
        
        return jsonify(extraction_result)
    except Exception as e:
        logger.error(f"Upload document endpoint error: {e}")
        return jsonify({"success": False, "message": "Upload failed"})

@app.route('/api/create_stripe_payment', methods=['POST'])
def create_stripe_payment():
    try:
        data = request.json
        if not data or not all(k in data for k in ['user_id', 'session_id', 'amount', 'payment_type']):
            return jsonify({"success": False, "message": "Missing required parameters"})
        return jsonify(tax_system.create_stripe_payment_intent(
            data['user_id'], data['session_id'], data['amount'], data['payment_type']
        ))
    except Exception as e:
        logger.error(f"Stripe payment endpoint error: {e}")
        return jsonify({"success": False, "message": "Payment creation failed"})

@app.route('/api/confirm_stripe_payment', methods=['POST'])
def confirm_stripe_payment():
    try:
        data = request.json
        if not data or not all(k in data for k in ['payment_intent_id', 'payment_method_id']):
            return jsonify({"success": False, "message": "Missing required parameters"})
        return jsonify(tax_system.confirm_stripe_payment(
            data['payment_intent_id'], data['payment_method_id']
        ))
    except Exception as e:
        logger.error(f"Stripe confirm endpoint error: {e}")
        return jsonify({"success": False, "message": "Payment confirmation failed"})

@app.route('/api/create_paypal_order', methods=['POST'])
def create_paypal_order():
    try:
        data = request.json
        if not data or not all(k in data for k in ['user_id', 'session_id', 'amount', 'payment_type']):
            return jsonify({"success": False, "message": "Missing required parameters"})
        return jsonify(tax_system.create_paypal_order(
            data['user_id'], data['session_id'], data['amount'], data['payment_type']
        ))
    except Exception as e:
        logger.error(f"PayPal order endpoint error: {e}")
        return jsonify({"success": False, "message": "PayPal order creation failed"})

@app.route('/api/capture_paypal_payment', methods=['POST'])
def capture_paypal_payment():
    try:
        data = request.json
        if not data or 'order_id' not in data:
            return jsonify({"success": False, "message": "Order ID required"})
        return jsonify(tax_system.capture_paypal_payment(data['order_id']))
    except Exception as e:
        logger.error(f"PayPal capture endpoint error: {e}")
        return jsonify({"success": False, "message": "PayPal capture failed"})

@app.route('/api/get_review_data', methods=['POST'])
def get_review_data():
    try:
        data = request.json
        if not data or not all(k in data for k in ['user_id', 'session_id']):
            return jsonify({"success": False, "message": "User ID and session ID required"})
        return jsonify(tax_system.get_comprehensive_review_data(data['user_id'], data['session_id']))
    except Exception as e:
        logger.error(f"Review data endpoint error: {e}")
        return jsonify({"success": False, "message": "Failed to get review data"})

@app.route('/api/submit_form', methods=['POST'])
def submit_form():
    try:
        data = request.json
        if not data or not all(k in data for k in ['user_id', 'session_id']):
            return jsonify({"success": False, "message": "User ID and session ID required"})
        return jsonify(tax_system.submit_complete_form(data['user_id'], data['session_id']))
    except Exception as e:
        logger.error(f"Submit form endpoint error: {e}")
        return jsonify({"success": False, "message": "Form submission failed"})

@app.route('/')
def index():
    return render_template_string(COMPLETE_FRONTEND_HTML)

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

# Complete Frontend HTML
COMPLETE_FRONTEND_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
