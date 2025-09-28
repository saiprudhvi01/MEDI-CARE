from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hospital.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# DB and Login manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ==================
# Models
# ==================
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_hospital = db.Column(db.Boolean, default=False)

    patient = db.relationship('Patient', backref='user', uselist=False)
    hospital = db.relationship('Hospital', backref='user', uselist=False)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Patient(db.Model):
    __tablename__ = 'patients'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20), nullable=True)

    requests = db.relationship('BookingRequest', backref='patient', lazy=True)


class Hospital(db.Model):
    __tablename__ = 'hospitals'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    hospital_code = db.Column(db.String(10), nullable=False, unique=True)
    name = db.Column(db.String(150), nullable=False)
    state = db.Column(db.String(50), nullable=False)
    total_beds = db.Column(db.Integer, nullable=False, default=0)
    booked_beds = db.Column(db.Integer, nullable=False, default=0)
    available_beds = db.Column(db.Integer, nullable=False, default=0)
    ambulances_total = db.Column(db.Integer, nullable=False, default=0)
    ambulances_busy = db.Column(db.Integer, nullable=False, default=0)
    
    # Doctor availability
    doctors_total = db.Column(db.Integer, nullable=False, default=0)
    doctors_available = db.Column(db.Integer, nullable=False, default=0)
    specialists = db.Column(db.JSON, nullable=False, default=dict)  # e.g., {'Cardiologist': 3, 'Neurologist': 2}

    requests = db.relationship('BookingRequest', backref='hospital', lazy=True)


class BookingRequest(db.Model):
    __tablename__ = 'booking_requests'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    hospital_id = db.Column(db.Integer, db.ForeignKey('hospitals.id'), nullable=False)
    symptoms = db.Column(db.String(300), nullable=False)
    specialty = db.Column(db.String(100), nullable=False)
    needs_ambulance = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ==================
# Utilities
# ==================
SPECIALTY_RULES = {
    'General Medicine': ['fever', 'cough', 'cold', 'fatigue', 'headache'],
}

# Multiple Disease Prediction with per-symptom severity weights (1-3)
DISEASE_WEIGHTS: dict[str, dict[str, int]] = {
    'Coronary Artery Disease (Heart)': {
        'chest pain': 3,
        'shortness of breath': 3,
        'jaw pain': 2,
        'left arm pain': 2,
        'sweating': 1,
        'nausea': 1,
    },
    'Chronic Obstructive Pulmonary Disease (COPD) (Lungs)': {
        'chronic cough': 3,
        'wheezing': 2,
        'breathlessness': 3,
        'phlegm': 1,
        'fatigue': 1,
    },
    'Chronic Kidney Disease (CKD) (Kidneys)': {
        'swollen ankles': 2,
        'reduced urine': 3,
        'nausea': 1,
        'fatigue': 1,
        'itching': 1,
        'loss of appetite': 2,
    },
    'Stroke (Brain)': {
        'sudden weakness': 3,
        'face drooping': 3,
        'speech difficulty': 3,
        'vision problems': 2,
        'severe headache': 2,
    },
    'Liver Cirrhosis (Liver)': {
        'jaundice': 3,
        'abdominal swelling': 3,
        'easy bruising': 2,
        'fatigue': 1,
        'itching': 1,
    },
}


def predict_disease(disease_name: str, selected_symptoms: list[str]):
    """
    Weighted rule-based prediction.
    Returns dict with: yes_no ('Yes'/'No'), severity ('None'|'Low'|'Medium'|'High'),
    score (matched_weight), total (total_weight), ratio (0..1), matched ([(symptom, weight), ...]).
    """
    weights = DISEASE_WEIGHTS.get(disease_name, {})
    if not weights:
        return {
            'yes_no': 'No', 'severity': 'None', 'score': 0, 'total': 0, 'ratio': 0.0, 'matched': []
        }

    # normalize
    lookup = {k.lower(): v for k, v in weights.items()}
    total_weight = sum(lookup.values())
    chosen = [s.lower() for s in selected_symptoms]
    matched = []
    score = 0
    for s in chosen:
        if s in lookup:
            w = lookup[s]
            score += w
            matched.append((s, w))

    ratio = (score / total_weight) if total_weight else 0.0

    # Decision thresholds
    if ratio >= 0.7:
        yes_no = 'Yes'
        severity = 'High'
    elif ratio >= 0.5:
        yes_no = 'Yes'
        severity = 'Medium'
    elif ratio >= 0.3:
        yes_no = 'No'
        severity = 'Low'
    else:
        yes_no = 'No'
        severity = 'None'

    return {
        'yes_no': yes_no,
        'severity': severity,
        'score': score,
        'total': total_weight,
        'ratio': ratio,
        'matched': matched,
    }


# ==================
# Routes - Auth
# ==================
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/register/patient', methods=['GET', 'POST'])
def register_patient():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()
        password = request.form.get('password')
        name = request.form.get('name').strip()
        phone = request.form.get('phone', '').strip()

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists', 'danger')
            return redirect(url_for('register_patient'))

        user = User(username=username, email=email, is_hospital=False)
        user.set_password(password)
        db.session.add(user)
        db.session.flush()

        patient = Patient(user_id=user.id, name=name, phone=phone)
        db.session.add(patient)
        db.session.commit()
        flash('Patient registered. Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('auth/register_patient.html')


@app.route('/register/hospital', methods=['GET', 'POST'])
def register_hospital():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        email = request.form.get('email').strip()
        password = request.form.get('password')
        hospital_code = request.form.get('hospital_code').strip()

        hosp = Hospital.query.filter_by(hospital_code=hospital_code).first()
        if not hosp:
            flash('Invalid hospital code. Please contact admin.', 'danger')
            return redirect(url_for('register_hospital'))
        if hosp.user_id:
            flash('This hospital already has an admin account.', 'warning')
            return redirect(url_for('login'))

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists', 'danger')
            return redirect(url_for('register_hospital'))

        user = User(username=username, email=email, is_hospital=True)
        user.set_password(password)
        db.session.add(user)
        db.session.flush()

        hosp.user_id = user.id
        db.session.commit()
        flash('Hospital admin registered. Please login.', 'success')
        return redirect(url_for('login'))

    hospitals = Hospital.query.order_by(Hospital.state, Hospital.name).all()
    return render_template('auth/register_hospital.html', hospitals=hospitals)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            if user.is_hospital:
                return redirect(url_for('hospital_dashboard'))
            return redirect(url_for('patient_dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('auth/login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.', 'info')
    return redirect(url_for('home'))


# ==================
# Routes - Patient
# ==================
@app.route('/patient/dashboard', methods=['GET', 'POST'])
@login_required
def patient_dashboard():
    if current_user.is_hospital:
        return redirect(url_for('hospital_dashboard'))

    # Common specialties for the filter dropdown
    common_specialties = [
        'Cardiology', 'Neurology', 'Orthopedics', 'Pediatrics', 
        'General Medicine', 'General Surgery', 'Ophthalmology', 'Dentistry',
        'Dermatology', 'ENT', 'Gastroenterology', 'Nephrology', 'Oncology'
    ]

    if request.method == 'POST':
        notes = request.form.get('notes', '')
        state = request.form.get('state', '')
        predicted_disease = request.form.get('predicted_disease', 'N/A')
        
        # Map predicted diseases to specialties for auto-filtering
        disease_to_specialty = {
            'heart': 'Cardiology',
            'chest pain': 'Cardiology',
            'headache': 'Neurology',
            'migraine': 'Neurology',
            'fracture': 'Orthopedics',
            'bone': 'Orthopedics',
            'fever': 'General Medicine',
            'cold': 'General Medicine',
            'cough': 'General Medicine',
            'eye': 'Ophthalmology',
            'tooth': 'Dentistry',
            'dental': 'Dentistry',
            'skin': 'Dermatology',
            'ear': 'ENT',
            'nose': 'ENT',
            'throat': 'ENT',
            'stomach': 'Gastroenterology',
            'kidney': 'Nephrology',
            'cancer': 'Oncology'
        }

        # Auto-detect specialty from predicted disease
        auto_specialty = None
        if predicted_disease and predicted_disease != 'N/A':
            for keyword, spec in disease_to_specialty.items():
                if keyword.lower() in predicted_disease.lower():
                    auto_specialty = spec
                    break
        
        # Get the selected specialty from the form or use the auto-detected one
        selected_specialty = request.form.get('specialty', auto_specialty or '')
        
        # Build the query
        query = Hospital.query
        
        # Apply filters
        if state:
            query = query.filter_by(state=state)
            
        if selected_specialty:
            # Filter hospitals that have the selected specialty
            query = query.filter(Hospital.specialists[selected_specialty].isnot(None))
        
        # Order by available beds (descending)
        hospitals = query.order_by(Hospital.available_beds.desc()).all()
        
        # Get unique states for the filter dropdown
        states = db.session.query(Hospital.state).distinct().all()
        state_list = [s[0] for s in states]
        
        return render_template(
            'patient/hospitals.html',
            notes=notes,
            predicted_disease=predicted_disease,
            state=state,
            hospitals=hospitals,
            specialties=common_specialties,
            selected_specialty=selected_specialty,
            auto_specialty=auto_specialty,
            states=state_list,
            selected_state=state
        )

    # For GET requests, just show the dashboard with state filter
    states = db.session.query(Hospital.state).distinct().all()
    state_list = [s[0] for s in states]
    return render_template('patient/dashboard.html', states=state_list)


@app.route('/patient/request/<int:hospital_id>', methods=['POST'])
@login_required
def create_request(hospital_id: int):
    if current_user.is_hospital:
        flash('Hospital users cannot create patient requests.', 'warning')
        return redirect(url_for('hospital_dashboard'))

    patient = current_user.patient
    hospital = Hospital.query.get_or_404(hospital_id)
    # Store patient notes in 'symptoms' column; use provided disease if present, else 'N/A'
    notes = request.form.get('notes', '')
    predicted_disease = request.form.get('predicted_disease', 'N/A')
    needs_ambulance = request.form.get('needs_ambulance') == 'on'

    br = BookingRequest(
        patient_id=patient.id,
        hospital_id=hospital.id,
        symptoms=notes,
        specialty=predicted_disease,
        needs_ambulance=needs_ambulance,
        status='pending',
    )
    db.session.add(br)
    db.session.commit()
    flash('Request sent to hospital.', 'success')
    return redirect(url_for('patient_requests'))


# ==================
# Routes - Multiple Disease Prediction
# ==================
@app.route('/patient/predict', methods=['GET', 'POST'])
@login_required
def patient_predict():
    if current_user.is_hospital:
        return redirect(url_for('hospital_dashboard'))

    disease = request.values.get('disease')
    selected = []
    outcome = None

    if request.method == 'POST' and disease:
        selected = request.form.getlist('symptoms')
        outcome = predict_disease(disease, selected)

    diseases = list(DISEASE_WEIGHTS.keys())
    options = list(DISEASE_WEIGHTS.get(disease, {}).keys()) if disease else []
    return render_template(
        'patient/predict.html',
        diseases=diseases,
        disease=disease,
        options=options,
        selected=selected,
        outcome=outcome,
    )


@app.route('/patient/requests')
@login_required
def patient_requests():
    if current_user.is_hospital:
        return redirect(url_for('hospital_dashboard'))
    reqs = (
        BookingRequest.query.filter_by(patient_id=current_user.patient.id)
        .order_by(BookingRequest.created_at.desc())
        .all()
    )
    return render_template('patient/requests.html', requests=reqs)


# ==================
# Routes - Hospital
# ==================
@app.route('/hospital/dashboard')
@login_required
def hospital_dashboard():
    if not current_user.is_hospital:
        return redirect(url_for('patient_dashboard'))
    hosp = current_user.hospital
    pending = BookingRequest.query.filter_by(hospital_id=hosp.id, status='pending').order_by(BookingRequest.created_at.asc()).all()
    recent = BookingRequest.query.filter(BookingRequest.hospital_id == hosp.id, BookingRequest.status != 'pending').order_by(BookingRequest.created_at.desc()).limit(10).all()
    return render_template('hospital/dashboard.html', hospital=hosp, pending=pending, recent=recent)


@app.route('/hospital/accept/<int:req_id>', methods=['POST'])
@login_required
def hospital_accept(req_id: int):
    if not current_user.is_hospital:
        return redirect(url_for('patient_dashboard'))
    hosp = current_user.hospital
    req = BookingRequest.query.get_or_404(req_id)
    if req.hospital_id != hosp.id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('hospital_dashboard'))
    if req.status != 'pending':
        flash('Request already processed.', 'info')
        return redirect(url_for('hospital_dashboard'))

    if hosp.available_beds <= 0:
        flash('No available beds to accept the request.', 'warning')
        return redirect(url_for('hospital_dashboard'))

    # Update beds
    hosp.booked_beds += 1
    hosp.available_beds -= 1

    # Update ambulance if required
    if req.needs_ambulance and hosp.ambulances_busy < hosp.ambulances_total:
        hosp.ambulances_busy += 1

    req.status = 'accepted'
    db.session.commit()
    flash('Request accepted and resources updated.', 'success')
    return redirect(url_for('hospital_dashboard'))


@app.route('/hospital/reject/<int:req_id>', methods=['POST'])
@login_required
def hospital_reject(req_id: int):
    if not current_user.is_hospital:
        return redirect(url_for('patient_dashboard'))
    hosp = current_user.hospital
    req = BookingRequest.query.get_or_404(req_id)
    if req.hospital_id != hosp.id:
        flash('Unauthorized action.', 'danger')
        return redirect(url_for('hospital_dashboard'))
    if req.status != 'pending':
        flash('Request already processed.', 'info')
        return redirect(url_for('hospital_dashboard'))

    req.status = 'rejected'
    db.session.commit()
    flash('Request rejected.', 'info')
    return redirect(url_for('hospital_dashboard'))


# ==================
# DB seeding
# ==================

def seed_hospitals():
    if Hospital.query.count() > 0:
        return

    # Common specialties for hospitals
    common_specialties = {
        'General Medicine': 5,
        'General Surgery': 4,
        'Pediatrics': 3,
        'Obstetrics & Gynecology': 3,
        'Orthopedics': 2,
        'Cardiology': 2,
        'Neurology': 2,
        'Dermatology': 1,
        'Ophthalmology': 1,
        'ENT': 1
    }
    
    # Specialties for larger hospitals
    additional_specialties = {
        'Cardiothoracic Surgery': 1,
        'Neurosurgery': 1,
        'Urology': 1,
        'Nephrology': 1,
        'Gastroenterology': 1,
        'Pulmonology': 1,
        'Oncology': 1,
        'Rheumatology': 1,
        'Endocrinology': 1
    }
    
    # Hospital data: (code, name, state, total_beds, booked_beds, available_beds, ambulances_total, doctors_total, doctors_available, specialties)
    data = [
        # Andhra Pradesh (AP) - 15 hospitals
        ('AP01', 'Apollo Hospitals, Visakhapatnam', 'Andhra Pradesh', 500, 320, 180, 15, 50, 30, {**common_specialties, 'Cardiology': 4, 'Neurology': 3, 'Nephrology': 2}),
        ('AP02', 'KIMS Hospital, Vijayawada', 'Andhra Pradesh', 400, 250, 150, 10, 45, 28, {**common_specialties, 'Cardiology': 3, 'Neurology': 2, 'Nephrology': 1}),
        ('AP03', 'Manipal Hospital, Guntur', 'Andhra Pradesh', 300, 180, 120, 8, 35, 22, {**common_specialties, 'Cardiology': 2, 'Neurology': 2}),
        ('AP04', 'Ramesh Hospitals, Guntur', 'Andhra Pradesh', 250, 150, 100, 6, 30, 18, {**common_specialties, 'Cardiology': 2, 'Nephrology': 1}),
        ('AP05', 'Care Hospitals, Vizag', 'Andhra Pradesh', 350, 220, 130, 12, 40, 25, {**common_specialties, 'Cardiology': 3, 'Neurology': 2, 'Nephrology': 1}),
        ('AP06', "Queen's NRI Hospital, Vizag", 'Andhra Pradesh', 200, 120, 80, 5, 25, 15, {**common_specialties, 'Cardiology': 1}),
        ('AP07', 'Vijaya Super Speciality, Vijayawada', 'Andhra Pradesh', 150, 70, 80, 4, 20, 12, {**{k: v for k, v in common_specialties.items() if k != 'Neurology'}}),
        ('AP08', 'GSL Medical College, Rajahmundry', 'Andhra Pradesh', 400, 280, 120, 7, 45, 28, {**common_specialties, 'Cardiology': 2, 'Nephrology': 1}),
        ('AP09', 'Seven Hills Hospital, Vizag', 'Andhra Pradesh', 250, 100, 150, 6, 30, 20, common_specialties),
        ('AP10', 'Sai Super Speciality, Tirupati', 'Andhra Pradesh', 300, 150, 150, 9, 35, 22, {**common_specialties, 'Cardiology': 2}),
        ('AP11', 'NRI Medical College, Guntur', 'Andhra Pradesh', 400, 250, 150, 10, 42, 25, {**common_specialties, 'Cardiology': 2, 'Neurology': 1}),
        ('AP12', 'Rainbow Children Hospital, Vizag', 'Andhra Pradesh', 200, 100, 100, 5, 25, 15, {
            'Pediatrics': 8, 'Neonatology': 3, 'Pediatric Surgery': 2, 'Pediatric Cardiology': 1, 'General Medicine': 2
        }),
        ('AP13', 'Narayana Hrudayalaya, Vijayawada', 'Andhra Pradesh', 350, 200, 150, 8, 40, 25, {
            'Cardiology': 5, 'Cardiothoracic Surgery': 3, 'Cardiac Anesthesia': 2, 'General Medicine': 3, 'General Surgery': 2
        }),
        ('AP14', 'KIMS-ICON Hospital, Vizag', 'Andhra Pradesh', 250, 120, 130, 6, 30, 18, {**common_specialties, 'Cardiology': 2}),
        ('AP15', 'Gandhi Medical College, Secunderabad', 'Andhra Pradesh', 500, 350, 150, 12, 60, 35, {
            **common_specialties, 
            **{k: 2 for k in additional_specialties},
            'General Medicine': 8,
            'General Surgery': 6,
            'Orthopedics': 4
        }),
        
        # Tamil Nadu (TN) - 25 hospitals with focus on Madurai
        ('TN01', 'Apollo Hospitals, Chennai', 'Tamil Nadu', 700, 500, 200, 20, 80, 50, {
            **common_specialties,
            **{k: 3 for k in additional_specialties},
            'Cardiology': 6,
            'Neurology': 4,
            'Nephrology': 3,
            'Oncology': 3
        }),
        ('TN02', 'Stanley Medical College, Chennai', 'Tamil Nadu', 600, 400, 200, 15, 70, 45, {
            **common_specialties,
            **{k: 2 for k in additional_specialties},
            'General Medicine': 10,
            'General Surgery': 8,
            'Orthopedics': 5
        }),
        ('TN03', 'Kauvery Hospital, Trichy', 'Tamil Nadu', 300, 180, 120, 7, 35, 22, {
            **common_specialties,
            'Cardiology': 3,
            'Neurology': 2,
            'Nephrology': 2
        }),
        ('TN04', 'PSG Hospitals, Coimbatore', 'Tamil Nadu', 400, 220, 180, 9, 45, 28, {
            **common_specialties,
            'Cardiology': 3,
            'Neurology': 2,
            'Nephrology': 2,
            'Gastroenterology': 2
        }),
        ('TN05', 'SRM Medical College, Kanchipuram', 'Tamil Nadu', 350, 150, 200, 6, 40, 25, {
            **common_specialties,
            'Cardiology': 2,
            'Neurology': 2,
            'General Medicine': 5,
            'General Surgery': 4
        }),
        ('TN06', 'CMC Vellore', 'Tamil Nadu', 800, 600, 200, 25, 100, 65, {
            **common_specialties,
            **{k: 4 for k in additional_specialties},
            'Cardiology': 8,
            'Neurology': 6,
            'Nephrology': 5,
            'General Medicine': 12,
            'General Surgery': 10
        }),
        ('TN07', 'Meenakshi Mission, Madurai', 'Tamil Nadu', 500, 300, 200, 15, 55, 35, {
            **common_specialties,
            **{k: 2 for k in additional_specialties},
            'Cardiology': 4,
            'Neurology': 3,
            'Nephrology': 2
        }),
        ('TN08', 'Government Rajaji Hospital, Madurai', 'Tamil Nadu', 600, 400, 200, 18, 65, 42, {
            **common_specialties,
            **{k: 3 for k in additional_specialties},
            'General Medicine': 15,
            'General Surgery': 12,
            'Orthopedics': 6
        }),
        ('TN09', 'MIOT International, Chennai', 'Tamil Nadu', 600, 400, 200, 10, 60, 38, {
            **common_specialties,
            **{k: 2 for k in additional_specialties},
            'Orthopedics': 6,
            'Cardiology': 4,
            'Neurology': 3
        }),
        ('TN10', 'SIMS Hospital, Chennai', 'Tamil Nadu', 300, 120, 180, 8, 35, 22, {
            **common_specialties,
            'Cardiology': 3,
            'Neurology': 2,
            'Gastroenterology': 2
        }),
        ('TN11', 'Velammal Medical College, Madurai', 'Tamil Nadu', 450, 200, 250, 10, 48, 30, {
            **common_specialties,
            'General Medicine': 6,
            'General Surgery': 5,
            'Pediatrics': 4,
            'Obstetrics & Gynecology': 4
        }),
        ('TN12', 'Aravind Eye Hospital, Madurai', 'Tamil Nadu', 400, 250, 150, 8, 40, 25, {
            'Ophthalmology': 30,
            'Retina': 8,
            'Cornea': 6,
            'Glaucoma': 4,
            'Oculoplasty': 3,
            'Pediatric Ophthalmology': 3
        }),
        ('TN13', 'Vadamalayan Hospitals, Madurai', 'Tamil Nadu', 300, 150, 150, 7, 32, 20, {
            **common_specialties,
            'Cardiology': 2,
            'Neurology': 2,
            'Gastroenterology': 2
        }),
        ('TN14', 'Vijaya Hospital, Chennai', 'Tamil Nadu', 350, 200, 150, 9, 38, 24, {
            **common_specialties,
            'Cardiology': 3,
            'Neurology': 2,
            'Orthopedics': 3
        }),
        ('TN15', 'Madras Medical Mission, Chennai', 'Tamil Nadu', 400, 250, 150, 10, 42, 26, {
            **common_specialties,
            'Cardiology': 4,
            'Cardiothoracic Surgery': 3,
            'Cardiac Anesthesia': 2
        }),
        ('TN16', 'Billroth Hospitals, Chennai', 'Tamil Nadu', 300, 150, 150, 7, 32, 20, {
            **common_specialties,
            'Gastroenterology': 3,
            'General Surgery': 4,
            'General Medicine': 4
        }),
        ('TN17', 'Kauvery Hospital, Chennai', 'Tamil Nadu', 350, 200, 150, 8, 38, 24, {
            **common_specialties,
            'Cardiology': 3,
            'Neurology': 2,
            'Nephrology': 2,
            'Gastroenterology': 2
        }),
        ('TN18', 'Global Hospitals, Chennai', 'Tamil Nadu', 500, 300, 200, 12, 55, 35, {
            **common_specialties,
            **{k: 2 for k in additional_specialties},
            'Gastroenterology': 4,
            'Hepatology': 3,
            'Liver Transplant': 2
        }),
        ('TN19', 'Fortis Malar Hospital, Chennai', 'Tamil Nadu', 400, 250, 150, 10, 45, 28, {
            **common_specialties,
            'Cardiology': 4,
            'Cardiac Surgery': 3,
            'Neurology': 3,
            'Neurosurgery': 2
        }),
        ('TN20', 'Sri Ramachandra Medical Centre, Chennai', 'Tamil Nadu', 600, 400, 200, 15, 70, 45, {
            **common_specialties,
            **{k: 3 for k in additional_specialties},
            'Cardiology': 5,
            'Neurology': 4,
            'Nephrology': 3,
            'General Medicine': 10
        }),
        ('TN21', 'Apollo Speciality Hospital, Madurai', 'Tamil Nadu', 400, 200, 200, 10, 42, 26, {
            **common_specialties,
            'Orthopedics': 4,
            'Cardiology': 3,
            'Neurology': 2,
            'General Surgery': 4
        }),
        ('TN22', 'Vijaya Health Centre, Chennai', 'Tamil Nadu', 250, 100, 150, 6, 28, 18, {
            **common_specialties,
            'Cardiology': 2,
            'General Medicine': 4,
            'General Surgery': 3
        }),
        ('TN23', 'Kovai Medical Center, Coimbatore', 'Tamil Nadu', 500, 300, 200, 12, 52, 33, {
            **common_specialties,
            **{k: 2 for k in additional_specialties},
            'Cardiology': 4,
            'Neurology': 3,
            'Nephrology': 3
        }),
        ('TN24', 'Sri Ramakrishna Hospital, Coimbatore', 'Tamil Nadu', 400, 200, 200, 9, 42, 26, {
            **common_specialties,
            'Cardiology': 3,
            'Neurology': 2,
            'Nephrology': 2,
            'Gastroenterology': 2
        }),
        ('TN25', 'Ganga Medical Centre, Coimbatore', 'Tamil Nadu', 350, 150, 200, 8, 38, 24, {
            **common_specialties,
            'Orthopedics': 5,
            'Spine Surgery': 2,
            'Sports Medicine': 2,
            'Pain Management': 2
        }),
        # Karnataka (KA) - 15 hospitals
        ('KA01', 'Manipal Hospital, Bengaluru', 'Karnataka', 700, 500, 200, 20, 85, 55, {
            **common_specialties,
            **{k: 4 for k in additional_specialties},
            'Cardiology': 6,
            'Neurology': 5,
            'Nephrology': 4,
            'Oncology': 4,
            'General Medicine': 12,
            'General Surgery': 10
        }),
        ('KA02', 'Narayana Health, Bengaluru', 'Karnataka', 800, 600, 200, 25, 95, 62, {
            **common_specialties,
            **{k: 5 for k in additional_specialties},
            'Cardiology': 8,
            'Cardiac Surgery': 6,
            'Neurology': 5,
            'Neurosurgery': 4,
            'Pediatric Cardiology': 3,
            'Pediatric Cardiac Surgery': 2
        }),
        ('KA03', 'Fortis Hospital, Bengaluru', 'Karnataka', 500, 300, 200, 15, 55, 35, {
            **common_specialties,
            **{k: 2 for k in additional_specialties},
            'Cardiology': 4,
            'Neurology': 3,
            'Orthopedics': 4,
            'Gastroenterology': 3
        }),
        ('KA04', 'Apollo Hospitals, Mysuru', 'Karnataka', 400, 180, 220, 10, 45, 28, {
            **common_specialties,
            'Cardiology': 3,
            'Neurology': 2,
            'Nephrology': 2,
            'General Medicine': 5,
            'General Surgery': 4
        }),
        ('KA05', 'Columbia Asia, Bengaluru', 'Karnataka', 300, 200, 100, 8, 32, 20, {
            **common_specialties,
            'Cardiology': 2,
            'Neurology': 2,
            'General Medicine': 4,
            'General Surgery': 3,
            'Orthopedics': 2
        }),
        ('KA06', "St. John's Medical College, Bengaluru", 'Karnataka', 600, 400, 200, 18, 70, 45, {
            **common_specialties,
            **{k: 3 for k in additional_specialties},
            'General Medicine': 15,
            'General Surgery': 12,
            'Pediatrics': 8,
            'Obstetrics & Gynecology': 8
        }),
        ('KA07', 'BGS Global Hospital, Bengaluru', 'Karnataka', 450, 250, 200, 12, 48, 30, {
            **common_specialties,
            'Cardiology': 3,
            'Neurology': 3,
            'Nephrology': 2,
            'Gastroenterology': 2,
            'Orthopedics': 3
        }),
        ('KA08', 'MS Ramaiah Hospital, Bengaluru', 'Karnataka', 500, 300, 200, 14, 52, 33, {
            **common_specialties,
            **{k: 2 for k in additional_specialties},
            'Cardiology': 4,
            'Neurology': 3,
            'Nephrology': 2,
            'General Medicine': 8
        }),
        ('KA09', 'KLE Hospital, Belagavi', 'Karnataka', 400, 250, 150, 8, 42, 26, {
            **common_specialties,
            'General Medicine': 6,
            'General Surgery': 5,
            'Pediatrics': 3,
            'Obstetrics & Gynecology': 3,
            'Orthopedics': 3
        }),
        ('KA10', 'JSS Hospital, Mysuru', 'Karnataka', 350, 200, 150, 9, 38, 24, {
            **common_specialties,
            'Cardiology': 3,
            'Neurology': 2,
            'Nephrology': 2,
            'General Medicine': 5
        }),
        ('KA11', 'Vydehi Hospital, Bengaluru', 'Karnataka', 450, 250, 200, 10, 45, 28, {
            **common_specialties,
            'Cardiology': 3,
            'Neurology': 3,
            'Orthopedics': 4,
            'General Surgery': 4
        }),
        ('KA12', 'Sagar Hospitals, Bengaluru', 'Karnataka', 300, 150, 150, 7, 32, 20, {
            **common_specialties,
            'Cardiology': 2,
            'Neurology': 2,
            'General Medicine': 4,
            'General Surgery': 3
        }),
        ('KA13', 'Sparsh Hospital, Bengaluru', 'Karnataka', 350, 200, 150, 8, 35, 22, {
            **common_specialties,
            'Orthopedics': 5,
            'Spine Surgery': 2,
            'Sports Medicine': 2,
            'Pain Management': 2
        }),
        ('KA14', 'Apollo BGS, Mysuru', 'Karnataka', 400, 200, 200, 9, 42, 26, {
            **common_specialties,
            'Cardiology': 3,
            'Neurology': 2,
            'Nephrology': 2,
            'Gastroenterology': 2
        }),
        ('KA15', 'KMC Hospital, Manipal', 'Karnataka', 500, 300, 200, 12, 52, 33, {
        
            **common_specialties,
            **{k: 2 for k in additional_specialties},
            'Cardiology': 4,
            'Neurology': 3,
            'Nephrology': 2,
            'General Medicine': 8
        }),
        
        # Telangana (TS) - 15 hospitals
        ('TS01', 'Apollo Hospitals, Hyderabad', 'Telangana', 700, 450, 250, 18, 80, 52, {
            **common_specialties,
            **{k: 4 for k in additional_specialties},
            'Cardiology': 6,
            'Neurology': 5,
            'Nephrology': 4,
            'Oncology': 4,
            'General Medicine': 12,
            'General Surgery': 10
        }),
        ('TS02', 'KIMS Hospitals, Hyderabad', 'Telangana', 650, 400, 250, 16, 75, 49, {
            **common_specialties,
            **{k: 4 for k in additional_specialties},
            'Cardiology': 5,
            'Cardiac Surgery': 4,
            'Neurology': 4,
            'Neurosurgery': 3,
            'General Medicine': 10,
            'General Surgery': 8
        }),
        ('TS03', 'NIMS, Hyderabad', 'Telangana', 500, 300, 200, 12, 58, 38, {
            **common_specialties,
            **{k: 3 for k in additional_specialties},
            'Cardiology': 4,
            'Neurology': 3,
            'Nephrology': 3,
            'General Medicine': 10,
            'General Surgery': 8
        }),
        ('TS04', 'Yashoda Hospitals, Secunderabad', 'Telangana', 600, 350, 250, 15, 65, 42, {
            **common_specialties,
            **{k: 3 for k in additional_specialties},
            'Cardiology': 5,
            'Neurology': 4,
            'Nephrology': 3,
            'Oncology': 3,
            'General Medicine': 8
        }),
        ('TS05', 'Care Hospitals, Hyderabad', 'Telangana', 400, 180, 220, 10, 45, 28, {
            **common_specialties,
            'Cardiology': 4,
            'Neurology': 3,
            'Nephrology': 2,
            'General Medicine': 6,
            'General Surgery': 5
        }),
        ('TS06', 'Gandhi Hospital, Hyderabad', 'Telangana', 550, 300, 250, 14, 60, 39, {
            **common_specialties,
            **{k: 2 for k in additional_specialties},
            'General Medicine': 15,
            'General Surgery': 10,
            'Orthopedics': 6,
            'Pediatrics': 5
        }),
        ('TS07', 'Osmania General Hospital, Hyderabad', 'Telangana', 450, 250, 200, 9, 48, 30, {
            **common_specialties,
            'General Medicine': 10,
            'General Surgery': 8,
            'Pediatrics': 5,
            'Obstetrics & Gynecology': 5,
            'Orthopedics': 4
        }),
        ('TS08', 'Continental Hospitals, Hyderabad', 'Telangana', 400, 230, 170, 8, 42, 26, {
            **common_specialties,
            'Cardiology': 3,
            'Neurology': 2,
            'Nephrology': 2,
            'Gastroenterology': 2,
            'General Medicine': 5
        }),
        ('TS09', 'Sunshine Hospitals, Hyderabad', 'Telangana', 350, 150, 200, 9, 38, 24, {
            **common_specialties,
            'Orthopedics': 5,
            'Spine Surgery': 2,
            'Sports Medicine': 2,
            'Pain Management': 2,
            'General Medicine': 4
        }),
        ('TS10', 'Basavatarakam Cancer Hospital, Hyd', 'Telangana', 300, 170, 130, 7, 32, 20, {
            'Medical Oncology': 8,
            'Surgical Oncology': 5,
            'Radiation Oncology': 4,
            'Hemato Oncology': 3,
            'Palliative Care': 2,
            'Pathology': 3
        }),
        ('TS11', 'Kamineni Hospitals, Hyderabad', 'Telangana', 450, 250, 200, 10, 48, 30, {
            **common_specialties,
            'Cardiology': 3,
            'Neurology': 3,
            'Nephrology': 2,
            'Gastroenterology': 2,
            'General Surgery': 4
        }),
        ('TS12', 'Medicover Hospitals, Hyderabad', 'Telangana', 350, 150, 200, 8, 35, 22, {
            **common_specialties,
            'Cardiology': 2,
            'Neurology': 2,
            'General Medicine': 4,
            'General Surgery': 3,
            'Orthopedics': 2
        }),
        ('TS13', 'Rainbow Children Hospital, Hyderabad', 'Telangana', 250, 100, 150, 6, 25, 16, {
            'Pediatrics': 8,
            'Neonatology': 3,
            'Pediatric Surgery': 2,
            'Pediatric Cardiology': 1,
            'Pediatric Neurology': 1
        }),
        ('TS14', 'KIMS-ICON Hospital, Hyderabad', 'Telangana', 400, 200, 200, 9, 42, 26, {
            **common_specialties,
            'Cardiology': 3,
            'Neurology': 2,
            'Nephrology': 2,
            'General Medicine': 5
        }),
        ('TS15', 'Medanta Hospital, Hyderabad', 'Telangana', 500, 300, 200, 12, 55, 36, {
        
            **common_specialties,
            **{k: 3 for k in additional_specialties},
            'Cardiology': 5,
            'Neurology': 4,
            'Nephrology': 3,
            'Gastroenterology': 3,
            'General Medicine': 8
        }),
        
        # Maharashtra (MH) - 15 hospitals
        ('MH01', 'Tata Memorial Hospital, Mumbai', 'Maharashtra', 800, 600, 200, 25, 90, 59, {
            'Medical Oncology': 15,
            'Surgical Oncology': 10,
            'Radiation Oncology': 8,
            'Hemato Oncology': 6,
            'Palliative Care': 4,
            'Pathology': 8,
            'Radiology': 6,
            'Nuclear Medicine': 4
        }),
        ('MH02', 'Lilavati Hospital, Mumbai', 'Maharashtra', 600, 350, 250, 18, 75, 49, {
            **common_specialties,
            **{k: 4 for k in additional_specialties},
            'Cardiology': 6,
            'Neurology': 5,
            'Nephrology': 4,
            'General Medicine': 12,
            'General Surgery': 10
        }),
        ('MH03', 'Hinduja Hospital, Mumbai', 'Maharashtra', 500, 300, 200, 15, 65, 42, {
            **common_specialties,
            **{k: 3 for k in additional_specialties},
            'Cardiology': 5,
            'Neurology': 4,
            'Nephrology': 3,
            'General Medicine': 10,
            'General Surgery': 8
        }),
        ('MH04', 'Kokilaben Dhirubhai Ambani Hospital', 'Maharashtra', 650, 400, 250, 20, 80, 52, {
            **common_specialties,
            **{k: 5 for k in additional_specialties},
            'Cardiology': 7,
            'Cardiac Surgery': 5,
            'Neurology': 5,
            'Neurosurgery': 4,
            'General Medicine': 12
        }),
        ('MH05', 'Breach Candy Hospital, Mumbai', 'Maharashtra', 300, 120, 180, 10, 35, 23, {
            **common_specialties,
            'Cardiology': 3,
            'Neurology': 2,
            'General Medicine': 5,
            'General Surgery': 4,
            'Obstetrics & Gynecology': 3
        }),
        ('MH06', 'Nanavati Super Speciality, Mumbai', 'Maharashtra', 450, 250, 200, 12, 48, 30, {
            **common_specialties,
            **{k: 2 for k in additional_specialties},
            'Cardiology': 4,
            'Neurology': 3,
            'Nephrology': 2,
            'General Medicine': 6
        }),
        ('MH07', 'Ruby Hall Clinic, Pune', 'Maharashtra', 400, 180, 220, 9, 42, 26, {
            **common_specialties,
            'Cardiology': 3,
            'Neurology': 2,
            'Nephrology': 2,
            'General Medicine': 5,
            'General Surgery': 4
        }),
        ('MH08', 'Deenanath Mangeshkar Hospital, Pune', 'Maharashtra', 350, 200, 150, 8, 38, 24, {
            **common_specialties,
            'Cardiology': 3,
            'Neurology': 2,
            'General Medicine': 5,
            'General Surgery': 4,
            'Orthopedics': 3
        }),
        ('MH09', 'BJ Medical College, Pune', 'Maharashtra', 500, 350, 150, 14, 55, 36, {
            **common_specialties,
            **{k: 2 for k in additional_specialties},
            'General Medicine': 12,
            'General Surgery': 10,
            'Pediatrics': 6,
            'Obstetrics & Gynecology': 6
        }),
        ('MH10', 'Sahyadri Hospitals, Pune', 'Maharashtra', 300, 100, 200, 6, 32, 20, {
            **common_specialties,
            'Cardiology': 2,
            'Neurology': 2,
            'General Medicine': 4,
            'General Surgery': 3
        }),
        ('MH11', 'Jupiter Hospital, Mumbai', 'Maharashtra', 400, 200, 200, 10, 42, 26, {
            **common_specialties,
            'Cardiology': 3,
            'Neurology': 2,
            'Nephrology': 2,
            'General Medicine': 5,
            'General Surgery': 4
        }),
        ('MH12', 'Fortis Hospital, Mulund', 'Maharashtra', 450, 250, 200, 12, 48, 30, {
            **common_specialties,
            **{k: 2 for k in additional_specialties},
            'Cardiology': 4,
            'Neurology': 3,
            'Nephrology': 2,
            'General Medicine': 6
        }),
        ('MH13', 'Sahyadri Hospital, Nagpur', 'Maharashtra', 350, 150, 200, 8, 36, 22, {
            **common_specialties,
            'Cardiology': 2,
            'Neurology': 2,
            'General Medicine': 5,
            'General Surgery': 4,
            'Orthopedics': 3
        }),
        ('MH14', 'Sahyadri Hospital, Nashik', 'Maharashtra', 300, 100, 200, 7, 32, 20, {
            **common_specialties,
            'General Medicine': 5,
            'General Surgery': 4,
            'Pediatrics': 3,
            'Obstetrics & Gynecology': 3,
            'Orthopedics': 2
        }),
        ('MH15', 'KEM Hospital, Mumbai', 'Maharashtra', 700, 500, 200, 20, 85, 55, {
            **common_specialties,
            **{k: 4 for k in additional_specialties},
            'General Medicine': 15,
            'General Surgery': 12,
            'Pediatrics': 8,
            'Obstetrics & Gynecology': 8,
            'Orthopedics': 6
        })
    ]

    for item in data:
        if len(item) == 10:  # New format with doctor info
            code, name, state, total, booked, avail, amb, docs_total, docs_avail, specs = item
        else:  # Old format without doctor info
            code, name, state, total, booked, avail, amb = item
            docs_total = int(total * 0.1)  # Default to 10% of bed capacity
            docs_avail = int(docs_total * 0.7)  # 70% of doctors available by default
            specs = common_specialties
        hosp = Hospital(
            hospital_code=code,
            name=name,
            state=state,
            total_beds=total,
            booked_beds=booked,
            available_beds=avail,
            ambulances_total=amb,
            ambulances_busy=0,
            doctors_total=docs_total,
            doctors_available=docs_avail,
            specialists=specs,
        )
        db.session.add(hosp)
    db.session.commit()


# ==================
# App factory-like init
# ==================
with app.app_context():
    db.create_all()
    seed_hospitals()


# ==================
# Pages
# ==================
@app.route('/about')
def about():
    return render_template('about.html')


if __name__ == '__main__':
    app.run(debug=True)
