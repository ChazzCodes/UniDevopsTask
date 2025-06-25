from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, date
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or 'fallbacksecret'

# --- Database Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- Flask-Login Setup ---
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Redirect to login if not authenticated

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)
    assets = db.relationship('Asset', backref='owner', lazy=True)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    assets = db.relationship('Asset', backref='category', lazy=True)

class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    serial_number = db.Column(db.String(100), unique=True, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- Routes ---
@app.route('/')
def home():
    return render_template("home.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        site = request.form['site']  # this replaces 'username'
        email = request.form['email']
        password = request.form['password']

        # Check if user already exists
        if User.query.filter((User.username == site) | (User.email == email)).first():
            flash('Site location or email already exists.')
            return redirect(url_for('register'))

        # Hash password and create user
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=site, email=email, password_hash=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username, role=current_user.role)

@app.route('/assets')
@login_required
def assets():
    return render_template('assets.html')

@app.route('/assets/new', methods=['GET', 'POST'])
@login_required
def new_asset():
    today = date.today().isoformat()

    if request.method == 'POST':
        name = request.form['name']
        asset_type = request.form['type']
        status = request.form['status']
        assigned_date = request.form['date']

        print("New Asset Submitted:", name, asset_type, status, assigned_date)

        return redirect(url_for('assets'))

    return render_template('new_asset.html', today=today)

@app.route('/users')
@login_required
def users():
    return render_template('users.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

# Required for Vercel: expose 'app' as 'application' for WSGI
application = app  # Vercel uses this if your file ends in .py and uses Flask