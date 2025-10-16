from application import db
from flask_login import UserMixin
from datetime import datetime

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_hospital = db.Column(db.Boolean, default=False)
    is_ambulance_driver = db.Column(db.Boolean, default=False)
    
    # Relationships
    patient = db.relationship('Patient', backref='user', uselist=False, lazy=True)
    hospital = db.relationship('Hospital', backref='user', uselist=False, lazy=True)
    ambulance_driver = db.relationship('AmbulanceDriver', backref='user', uselist=False, lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Patient(db.Model):
    __tablename__ = 'patients'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    address = db.Column(db.String(300))
    city = db.Column(db.String(100))
    state = db.Column(db.String(50))
    pincode = db.Column(db.String(10))
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    
    # Relationships
    requests = db.relationship('BookingRequest', backref='patient', lazy=True)

class Hospital(db.Model):
    __tablename__ = 'hospitals'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    hospital_code = db.Column(db.String(10), unique=True, nullable=False)
    name = db.Column(db.String(150), nullable=False)
    address = db.Column(db.String(300))
    city = db.Column(db.String(100))
    state = db.Column(db.String(50), nullable=False)
    pincode = db.Column(db.String(10))
    lat = db.Column(db.Float)
    lng = db.Column(db.Float)
    total_beds = db.Column(db.Integer, default=0)
    booked_beds = db.Column(db.Integer, default=0)
    available_beds = db.Column(db.Integer, default=0)
    ambulances_total = db.Column(db.Integer, default=0)
    ambulances_busy = db.Column(db.Integer, default=0)
    doctors_total = db.Column(db.Integer, default=0)
    doctors_available = db.Column(db.Integer, default=0)
    specialists = db.Column(db.JSON, default=dict)
    
    # Relationships
    requests = db.relationship('BookingRequest', backref='hospital_requests', lazy=True)
    ambulance_drivers = db.relationship('AmbulanceDriver', backref='hospital', lazy=True)

class AmbulanceDriver(db.Model):
    __tablename__ = 'ambulance_drivers'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    license_number = db.Column(db.String(50), unique=True, nullable=False)
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospitals.id'))
    is_available = db.Column(db.Boolean, default=True)
    current_lat = db.Column(db.Float)
    current_lng = db.Column(db.Float)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    assigned_requests = db.relationship('BookingRequest', backref='ambulance_driver', lazy=True)

class BookingRequest(db.Model):
    __tablename__ = 'booking_requests'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospitals.id'), nullable=False)
    driver_id = db.Column(db.Integer, db.ForeignKey('ambulance_drivers.id'))
    status = db.Column(db.String(20), default='pending')
    symptoms = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    accepted_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    cancelled_at = db.Column(db.DateTime)
    cancelled_reason = db.Column(db.Text)
    distance_covered = db.Column(db.Float, default=0.0)
    estimated_time = db.Column(db.Integer)
    notes = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Location fields
    driver_lat = db.Column(db.Float)
    driver_lng = db.Column(db.Float)
    distance = db.Column(db.Float)
    pickup_lat = db.Column(db.Float)
    pickup_lng = db.Column(db.Float)
    destination_lat = db.Column(db.Float)
    destination_lng = db.Column(db.Float)
    current_lat = db.Column(db.Float)
    current_lng = db.Column(db.Float)
    
    # Additional fields
    specialty = db.Column(db.String(100))
    needs_ambulance = db.Column(db.Boolean, default=False)

# Import here to avoid circular imports
from werkzeug.security import generate_password_hash, check_password_hash
