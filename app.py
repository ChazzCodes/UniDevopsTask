from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date
import os
from dotenv import load_dotenv  

load_dotenv()  

app = Flask(__name__)

# --- Database Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Models ---
class User(db.Model):
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

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    username = "Charlie"
    role = "user"  # Change to "admin" to test admin view
    return render_template('dashboard.html', username=username, role=role)

@app.route('/assets')
def assets():
    return render_template('assets.html')

@app.route('/assets/new', methods=['GET', 'POST'])
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
def users():
    return render_template('users.html')

@app.route('/logout')
def logout():
    return render_template('logout.html')
