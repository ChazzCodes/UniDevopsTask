from flask import Flask, render_template, request, redirect, url_for
from datetime import date

app = Flask(__name__)

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
    # For now, use fake values. We'll replace this with session data later.
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
        # Get form data (we'll save to DB later)
        name = request.form['name']
        asset_type = request.form['type']
        status = request.form['status']
        assigned_date = request.form['date']

        # Debug print (temporary)
        print("New Asset Submitted:", name, asset_type, status, assigned_date)

        return redirect(url_for('assets'))

    return render_template('new_asset.html', today=today)

@app.route('/users')
def users():
    return render_template('users.html')

@app.route('/logout')
def logout():
    return render_template('logout.html')