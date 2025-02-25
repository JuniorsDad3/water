from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import URLSafeTimedSerializer
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from forms import RegistrationForm, LoginForm, MeterReadingForm, FaultReportForm
from flask_mail import Mail, Message
from prophet import Prophet
from sklearn.ensemble import IsolationForest
from datetime import datetime, timedelta
import cv2
import pytesseract
import pandas as pd
import json
import os

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024
app.config['SECURITY_PASSWORD_SALT'] = os.getenv('SECURITY_PASSWORD_SALT')

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Email configuration for Gmail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.getenv('EMAIL_PASS')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('EMAIL_USER')

mail = Mail(app)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    phone = db.Column(db.String(15))
    password = db.Column(db.String(150), nullable=False)
    email_confirmed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    readings = db.relationship('MeterReading', backref='user', lazy=True)
    reports = db.relationship('FaultReport', backref='user', lazy=True)

class MeterReading(db.Model):
    __tablename__ = 'meter_readings'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reading = db.Column(db.Float, nullable=False)
    image = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    is_anomaly = db.Column(db.Boolean, default=False)

class FaultReport(db.Model):
    __tablename__ = 'fault_reports'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(200))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    address = db.Column(db.String(255))  # Added address field
    status = db.Column(db.String(50), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    image = db.Column(db.String(255))

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create default user on startup
def create_default_user():
    default_email = "admin@popsoda.co.za"
    default_password = "Test@1234"
    hashed_password = bcrypt.generate_password_hash(default_password).decode('utf-8')
    user = User.query.filter_by(email=default_email).first()
    if not user:
        default_user = User(
            username="admin",
            email=default_email,
            phone="1234567890",
            password=hashed_password
        )
        db.session.add(default_user)
        db.session.commit()
        print("Default user created: admin@popsoda.co.za with password Test@1234")
    else:
        print("Default user already exists.")

def generate_confirmation_token(email):
    return serializer.dumps(email, salt=app.config['SECURITY_PASSWORD_SALT'])

def confirm_token(token, expiration=3600):
    try:
        return serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
    except Exception:
        return None

def check_anomalies(user_id):
    readings = MeterReading.query.filter_by(user_id=user_id).all()
    df = pd.DataFrame([{'reading': r.reading} for r in readings])
    if len(df) > 10:
        model = IsolationForest()
        anomalies = model.fit_predict(df.values)
        for i, reading in enumerate(readings):
            reading.is_anomaly = (anomalies[i] == -1)
        db.session.commit()

def analyze_fault_location(report_id):
    report = FaultReport.query.get(report_id)
    similar = FaultReport.query.filter(
        FaultReport.latitude.between(report.latitude - 0.01, report.latitude + 0.01),
        FaultReport.longitude.between(report.longitude - 0.01, report.longitude + 0.01),
        FaultReport.category == report.category
    ).count()
    if similar > 3:
        send_email(
            os.getenv('ADMIN_EMAIL'),
            'Fault Cluster Detected',
            f'Cluster of {similar} {report.category} reports detected at {report.address}'
        )

def send_meter_confirmation_email(reading):
    """
    Sends an email to the user to confirm a meter reading.
    Note: Ensure that you have a route to handle 'confirm_reading'.
    """
    body = f"""
    <h3>Confirm Meter Reading</h3>
    <p>Value: {reading.reading}</p>
    <p>Date: {reading.timestamp.strftime('%Y-%m-%d %H:%M')}</p>
    <a href="{url_for('confirm_reading', reading_id=reading.id, _external=True)}">
        Confirm Reading
    </a>
    """
    send_email(reading.user.email, 'Confirm Meter Reading', body)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'png', 'jpg', 'jpeg', 'gif'}

# Routes
@app.route("/")
def home():
    return render_template("home.html")

@app.route('/contact-us')
def contact_us():
    return render_template('contact.html')

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password", "danger")
    return render_template("login.html", form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            user = User(
                username=form.username.data,
                email=form.email.data,
                phone=form.phone.data,
                password=hashed_password
            )
            db.session.add(user)
            db.session.commit()

            # Send confirmation email
            token = generate_confirmation_token(user.email)
            confirm_url = url_for('confirm_email', token=token, _external=True)
            send_email(user.email, "Confirm Your Email", f"Please confirm your email by clicking the link: {confirm_url}")

            flash('Registration successful! Please check your email to confirm your account.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'danger')
    return render_template('register.html', form=form)

def send_email(to, subject, template):
    try:
        msg = Message(
            subject,
            recipients=[to],
            html=template,
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        mail.send(msg)
        return True
    except Exception as e:
        app.logger.error(f"Email failed to send: {str(e)}")
        return False

@app.route('/confirm/<token>')
def confirm_email(token):
    email = confirm_token(token)
    if not email:
        flash('Confirmation link is invalid or expired.', 'danger')
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('login'))
    if user.email_confirmed:
        flash('Account already confirmed. Please log in.', 'info')
    else:
        user.email_confirmed = True
        db.session.commit()
        flash('Account confirmed! You can now log in.', 'success')
    return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/forgot_password')
def forgot_password():
    return "Forgot Password Page (To Be Implemented)"

@app.route("/dashboard")
@login_required
def dashboard():
    try:
        # Explicit conversion to ensure no methods are passed.
        user_data = {
            "id": current_user.id,
            "email": str(current_user.email),
            "username": str(current_user.username)
        }

        # Fetch meter readings and convert to dictionaries.
        readings = [
            {
                "id": reading.id,
                "reading": reading.reading,
                "timestamp": reading.timestamp.strftime('%Y-%m-%d %H:%M') if reading.timestamp else "Unknown"
            }
            for reading in MeterReading.query.filter_by(user_id=current_user.id)
            .order_by(MeterReading.timestamp.desc()).all()
        ]

        # Fetch fault reports and convert to dictionaries.
        reports = [
            {
                "id": report.id,
                "description": report.description,
                "status": report.status,
                "created_at": report.created_at.strftime('%Y-%m-%d %H:%M') if report.created_at else "Unknown",
                "address": report.address
            }
            for report in FaultReport.query.filter_by(user_id=current_user.id)
            .order_by(FaultReport.created_at.desc()).all()
        ]

        # Generate chart data.
        chart_labels = [reading["timestamp"] for reading in readings]
        chart_values = [float(reading["reading"]) for reading in readings]

        chart_data = {
            "labels": chart_labels if chart_labels else ["No data available"],
            "values": chart_values if chart_values else [0]
        }

        # Water conservation tips.
        tips = [
            {"icon": "shower", "text": "Shorter Showers", "details": "Save 20 liters per minute"},
            {"icon": "droplet", "text": "Fix Leaks", "details": "A dripping tap wastes 15 liters/day"}
        ]

        # Optional: Debug log each field type.
        import json
        for lbl in chart_labels:
            app.logger.debug("Label: %s (type: %s)", lbl, type(lbl))
        for val in chart_values:
            app.logger.debug("Value: %s (type: %s)", val, type(val))
        app.logger.debug("Chart Data JSON: %s", json.dumps(chart_data))

        context = {
            "user_data": user_data,
            "chart_data": chart_data,
            "readings": readings,
            "reports": reports,
            "tips": tips
        }

        return render_template("dashboard.html", **context)

    except Exception as e:
        app.logger.error(f"Dashboard error: {str(e)}")
        flash("Error loading dashboard data", "danger")
        return redirect(url_for("home"))

@app.route('/meter_reading', methods=['GET', 'POST'])
@login_required
def meter_reading():
    form = MeterReadingForm()
    if form.validate_on_submit():
        try:
            image_path = None
            if 'images' in request.files:
                files = request.files.getlist('images')
                for file in files:
                    if file and allowed_file(file.filename):
                        filename = secure_filename(f"{current_user.id}_{datetime.now().timestamp()}.{file.filename.rsplit('.', 1)[1].lower()}")
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(filepath)
                        image_path = filename

                        # Extract reading from image using OCR
                        img = cv2.imread(filepath)
                        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                        reading_text = pytesseract.image_to_string(gray)
                        form.reading.data = reading_text.strip()

            # Validate reading with AI
            if image_path:
                is_valid, confidence = validate_reading_with_ai(filepath)
                if not is_valid or confidence < 0.7:
                    flash(f"⚠️ AI detected possible invalid meter photo (confidence: {confidence:.0%})", "warning")

            # Save the reading
            new_reading = MeterReading(
                user_id=current_user.id,
                reading=float(form.reading.data),
                image=image_path
            )
            db.session.add(new_reading)
            db.session.commit()

            # Optionally, send a meter confirmation email
            # send_meter_confirmation_email(new_reading)

            # Check for anomalies
            check_anomalies(current_user.id)

            flash("Reading submitted successfully!", "success")
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f"Error submitting reading: {str(e)}", "danger")
    return render_template('meter_reading.html', form=form)

def validate_reading_with_ai(image_path):
    from transformers import ViTForImageClassification, ViTImageProcessor
    processor = ViTImageProcessor.from_pretrained('google/vit-base-patch16-224')
    model = ViTForImageClassification.from_pretrained('nateraw/vit-meter-classifier')
    from PIL import Image
    image = Image.open(image_path).convert("RGB")
    inputs = processor(images=image, return_tensors="pt")
    outputs = model(**inputs)
    predicted_class = model.config.id2label[outputs.logits.argmax(-1).item()]
    return "meter" in predicted_class.lower(), outputs.logits.softmax(dim=1)[0].max().item()

@app.route('/process_image', methods=['POST'])
def process_image():
    file = request.files['image']
    import numpy as np
    image = cv2.imdecode(np.frombuffer(file.read(), np.uint8), cv2.IMREAD_COLOR)
    text = pytesseract.image_to_string(image)
    return jsonify({'reading': text})

@app.route('/predict_usage', methods=['GET'])
@login_required
def predict_usage():
    readings = MeterReading.query.filter_by(user_id=current_user.id).all()
    data = [{'ds': reading.timestamp, 'y': float(reading.reading)} for reading in readings]
    df = pd.DataFrame(data)
    model = Prophet()
    model.fit(df)
    future = model.make_future_dataframe(periods=30)
    forecast = model.predict(future)
    # Convert datetime field to string to avoid JSON serialization errors
    predictions_df = forecast[['ds', 'yhat']].tail(30).copy()
    predictions_df['ds'] = predictions_df['ds'].dt.strftime('%Y-%m-%d %H:%M:%S')
    predictions = predictions_df.to_dict('records')
    return jsonify(predictions)

def generate_water_art(usage_data):
    from dalle import Dalle
    dalle = Dalle()
    prompt = f"""
    Watercolor painting showing {usage_data['avg_usage']} liters usage as:
    - Blue tones for conservation
    - Flowing shapes for daily patterns
    - Golden accents for milestones
    Soft natural lighting, paper texture
    """
    return dalle.generate(prompt)

@app.route('/report_fault', methods=['GET', 'POST'])
@login_required
def report_fault():
    form = FaultReportForm()
    
    # If form is submitted but fails validation, flash the errors.
    if form.is_submitted() and not form.validate():
        flash(f"Form errors: {form.errors}", "danger")
        app.logger.debug(f"FaultReportForm errors: {form.errors}")
    
    if form.validate_on_submit():
        try:
            # Create a new fault report with data from the form
            new_fault = FaultReport(
                user_id=current_user.id,
                category=form.category.data,
                description=form.description.data,
                location=form.location.data,
                latitude=form.latitude.data,
                longitude=form.longitude.data,
                address=form.address.data,  # Matches the model field
            )

            # Handle image uploads
            images = request.files.getlist('fault_images')
            image_paths = []
            for img in images:
                if img and allowed_file(img.filename):
                    filename = f"fault_{current_user.id}_{datetime.now().timestamp()}_{secure_filename(img.filename)}"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    img.save(filepath)
                    image_paths.append(filename)

            new_fault.image = ','.join(image_paths) if image_paths else None
            db.session.add(new_fault)
            db.session.commit()

            # Analyze fault location for clustering (if applicable)
            analyze_fault_location(new_fault.id)

            flash("Fault report submitted successfully!", "success")
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error: {str(e)}', 'danger')
            app.logger.error(f"Error in report_fault: {str(e)}")
    
    return render_template('report_fault.html', form=form)


@app.route('/check_leaks', methods=['GET'])
@login_required
def check_leaks():
    readings = MeterReading.query.filter_by(user_id=current_user.id).all()
    leaks = detect_leak(readings)
    return jsonify([{'id': leak.id, 'reading': leak.reading, 'timestamp': leak.timestamp.strftime('%Y-%m-%d %H:%M')} for leak in leaks])

def detect_leak(readings):
    X = [[float(reading.reading)] for reading in readings]
    model = IsolationForest(contamination=0.1)
    model.fit(X)
    anomalies = model.predict(X)
    return [readings[i] for i in range(len(readings)) if anomalies[i] == -1]

@app.route('/api/geocode', methods=['POST'])
@login_required
def geocode_address():
    data = request.get_json()
    import requests
    response = requests.get(
        f"https://nominatim.openstreetmap.org/search?q={data['address']}&format=json"
    )
    if response.status_code == 200 and response.json():
        return jsonify(response.json()[0])
    return jsonify({'error': 'Geocoding failed'}), 400

@app.context_processor
def inject_user():
    if current_user.is_authenticated:
        return {
            "user_data": {
                "id": current_user.id,
                "email": current_user.email,
                "username": current_user.username
            }
        }
    return {}

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(error):
    return render_template('500.html'), 500

@app.template_filter('datetimeformat')
def datetimeformat(value, format='%Y-%m-%d %H:%M'):
    if value is None:
        return "Unknown"
    if isinstance(value, str):
        return value
    if isinstance(value, datetime):
        return value.strftime(format)
    return "Unknown"

# Route to confirm a meter reading (if using email confirmation for readings)
@app.route('/confirm_reading/<int:reading_id>')
@login_required
def confirm_reading(reading_id):
    reading = MeterReading.query.get(reading_id)
    if reading and reading.user_id == current_user.id:
        # Here you can set a flag or handle the confirmed reading as needed
        flash("Meter reading confirmed!", "success")
    else:
        flash("Invalid reading confirmation request", "danger")
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_user()
    app.run(debug=True)
