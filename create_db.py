from app import app, db

# Create all tables in the database
with app.app_context():
    db.create_all()
    print("✅ Tables created successfully in your Neon DB!")