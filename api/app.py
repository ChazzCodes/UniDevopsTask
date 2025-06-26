from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from datetime import datetime, date
import os
from dotenv import load_dotenv

# Load environment variables from .env file (DB url, secret key, etc)
load_dotenv()

app = Flask(__name__)
# Secret key is required for session management and flash messages
app.secret_key = os.environ.get('SECRET_KEY') or 'fallbacksecret'

# --- Database Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL_NEW')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- Flask-Login Setup ---
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Unauthenticated users get redirected to /login

@login_manager.user_loader
def load_user(user_id):
    """Load a user from the database by their ID (required for Flask-Login)."""
    return User.query.get(int(user_id))


# --- Models ---
class User(db.Model, UserMixin):
    """User model for login system, with admin/user roles and activity flag."""
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    site = db.Column(db.String(120), nullable=True)  # Site/office/etc
    role = db.Column(db.String(20), default='user', nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    assets = db.relationship('Asset', backref='owner', lazy=True)  # User's assets

class Category(db.Model):
    """Asset category/type model (e.g., Laptop, Monitor, etc)."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    assets = db.relationship('Asset', backref='category', lazy=True)

class Asset(db.Model):
    """Individual asset/device assigned to users."""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(50), nullable=False)  # e.g., Active, Inactive, Repair
    serial_number = db.Column(db.String(100), unique=True, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# --- Routes ---

@app.route('/')
def home():
    """Landing page (public)."""
    return render_template("home.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login screen and authentication logic."""
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        # Validate credentials
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
    """User registration page (anyone can create an account)."""
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        site = request.form.get('site')  # Optional site/office/etc

        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash('Email already exists.')
            return redirect(url_for('register'))

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password_hash=hashed_pw,
            site=site
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard shown after login."""
    return render_template(
        'dashboard.html',
        full_name=f"{current_user.first_name} {current_user.last_name}",
        role=current_user.role
    )

@app.route('/assets')
@login_required
def assets():
    """List the logged-in user's assets."""
    assets = Asset.query.filter_by(user_id=current_user.id).all()
    return render_template('assets.html', assets=assets)

@app.route('/assets/new', methods=['GET', 'POST'])
@login_required
def new_asset():
    """Form for adding a new asset (user's own only)."""
    today = date.today().isoformat()

    if request.method == 'POST':
        name = request.form['name']
        asset_type = request.form['type']
        status = request.form['status']
        assigned_date = request.form['date']

        # Get or create the asset category
        category = Category.query.filter_by(name=asset_type).first()
        if not category:
            category = Category(name=asset_type)
            db.session.add(category)
            db.session.commit()

        # Create new asset, assign to current user
        asset = Asset(
            name=name,
            status=status,
            user_id=current_user.id,
            category_id=category.id,
            created_at=datetime.strptime(assigned_date, '%Y-%m-%d')
        )
        db.session.add(asset)
        db.session.commit()

        flash("Asset added successfully!", "success")
        return redirect(url_for('assets'))

    return render_template('new_asset.html', today=today)

@app.route('/users')
@login_required
def users():
    """Admin view of all users (manage activity, view assets)."""
    if current_user.role != "admin":
        flash("You do not have permission to view this page.")
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/admin/user/<int:user_id>/toggle_active', methods=['POST'])
@login_required
def toggle_user_active(user_id):
    """Admin: Toggle user's active/inactive status."""
    if current_user.role != 'admin':
        flash('Access denied.')
        return redirect(url_for('users'))
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    flash(f'User {user.first_name} {user.last_name} has been {"activated" if user.is_active else "deactivated"}.')
    return redirect(url_for('users'))

@app.route('/admin/user/<int:user_id>/assets')
@login_required
def admin_view_user_assets(user_id):
    """Admin: View assets for a specific user."""
    if current_user.role != 'admin':
        flash('Access denied.')
        return redirect(url_for('users'))
    user = User.query.get_or_404(user_id)
    assets = user.assets  # Get all assets for this user
    return render_template('assets.html', assets=assets, user=user)

@app.route('/logout')
@login_required
def logout():
    """Log out the current user."""
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

# --- WSGI App for Deployment (e.g. Vercel) ---
application = app  # Vercel looks for 'application' by default