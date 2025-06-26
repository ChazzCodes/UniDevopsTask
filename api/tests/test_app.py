import unittest
from flask import session
from api.app import app, db, User, Category, Asset
from flask_bcrypt import generate_password_hash

class FlaskAppTestCase(unittest.TestCase):
    def setUp(self):
        # Set up an in-memory test database and Flask test client
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        with app.app_context():
            db.create_all()
            # Create a test admin user
            hashed_pw = generate_password_hash('testadmin123').decode('utf-8')
            admin = User(
                first_name='Admin',
                last_name='User',
                email='admin@test.com',
                password_hash=hashed_pw,
                role='admin',
                is_active=True
            )
            db.session.add(admin)
            db.session.commit()
            self.admin_email = admin.email
            self.admin_password = 'testadmin123'
            self.admin_id = admin.id

    def tearDown(self):
        # Drop all tables after each test
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def register_user(self, email='user@test.com', password='testuser123'):
        return self.app.post('/register', data={
            'first_name': 'Test',
            'last_name': 'User',
            'email': email,
            'password': password,
            'site': 'HQ'
        }, follow_redirects=True)

    def login_user(self, email, password):
        return self.app.post('/login', data={
            'email': email,
            'password': password
        }, follow_redirects=True)

    def login_admin(self):
        return self.login_user(self.admin_email, self.admin_password)

    def test_register_and_login(self):
        # Test registration
        resp = self.register_user()
        self.assertIn(b'Registration successful', resp.data)
        # Test login
        resp = self.login_user('user@test.com', 'testuser123')
        self.assertIn(b'Login successful', resp.data)
        # Test wrong login
        resp = self.login_user('user@test.com', 'wrongpass')
        self.assertIn(b'Invalid email or password', resp.data)

    def test_dashboard_access_requires_login(self):
        resp = self.app.get('/dashboard', follow_redirects=True)
        self.assertIn(b'Login', resp.data)

    def test_assets_access_requires_login(self):
        resp = self.app.get('/assets', follow_redirects=True)
        self.assertIn(b'Login', resp.data)

    def test_create_asset_as_user(self):
        self.register_user('user2@test.com', 'testpass')
        self.login_user('user2@test.com', 'testpass')
        # Add asset
        resp = self.app.post('/assets/new', data={
            'name': 'Dell Laptop',
            'type': 'Laptop',
            'status': 'Active',
            'date': '2024-01-01'
        }, follow_redirects=True)
        self.assertIn(b'Asset added successfully', resp.data)
        with app.app_context():
            asset = Asset.query.filter_by(name='Dell Laptop').first()
            self.assertIsNotNone(asset)
            self.assertEqual(asset.status, 'Active')
            self.assertEqual(asset.owner.email, 'user2@test.com')

    def test_admin_user_access(self):
        # Admin should see users page
        self.login_admin()
        resp = self.app.get('/users')
        self.assertIn(b'Registered Users', resp.data)
        # Regular user can't access /users
        self.register_user('normal@user.com', 'norm123')
        self.login_user('normal@user.com', 'norm123')
        resp = self.app.get('/users', follow_redirects=True)
        self.assertIn(b'You do not have permission', resp.data)

    def test_admin_toggle_user_active(self):
        self.register_user('toggle@user.com', 'togglepass')
        with app.app_context():
            user = User.query.filter_by(email='toggle@user.com').first()
            self.assertTrue(user.is_active)
        # Admin toggles to inactive
        self.login_admin()
        resp = self.app.post(f'/admin/user/{user.id}/toggle_active', follow_redirects=True)
        self.assertIn(b'deactivated', resp.data)
        with app.app_context():
            user = User.query.get(user.id)
            self.assertFalse(user.is_active)
        # Toggle back to active
        resp = self.app.post(f'/admin/user/{user.id}/toggle_active', follow_redirects=True)
        self.assertIn(b'activated', resp.data)
        with app.app_context():
            user = User.query.get(user.id)
            self.assertTrue(user.is_active)

    def test_admin_view_user_assets(self):
        # Register normal user, add asset
        self.register_user('assetuser@user.com', 'assetpass')
        self.login_user('assetuser@user.com', 'assetpass')
        self.app.post('/assets/new', data={
            'name': 'Monitor',
            'type': 'Monitor',
            'status': 'Active',
            'date': '2024-06-01'
        })
        with app.app_context():
            user = User.query.filter_by(email='assetuser@user.com').first()
        self.login_admin()
        resp = self.app.get(f'/admin/user/{user.id}/assets')
        self.assertIn(b'Monitor', resp.data)
        self.assertIn(bytes(user.first_name, 'utf-8'), resp.data)

    def test_logout(self):
        self.register_user('logout@user.com', 'logoutpass')
        self.login_user('logout@user.com', 'logoutpass')
        resp = self.app.get('/logout', follow_redirects=True)
        self.assertIn(b'You have been logged out', resp.data)

if __name__ == '__main__':
    unittest.main()