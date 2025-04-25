from flask import Flask
from models import db, Admin, Service
import os
from datetime import datetime, timedelta

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///homeease.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Initialize extensions
db.init_app(app)

# Create all tables and initial data
with app.app_context():
    
    
    # Create initial admin
    if not Admin.query.filter_by(email='admin@gmail.com').first():
        admin = Admin(
            email='admin@gmail.com',
            full_name='Admin User',
            is_super_admin=True
        )
        admin.set_password('admin')
        db.session.add(admin)
        
    # Create initial services
    if not Service.query.first():
        services = [
            {
                'service_name': 'House Cleaning',
                'description': 'Complete house cleaning service',
                'base_price': 1000.00,
                'category': 'Cleaning'
            },
            {
                'service_name': 'Plumbing',
                'description': 'Professional plumbing services',
                'base_price': 800.00,
                'category': 'Maintenance'
            },
            {
                'service_name': 'Electrical Work',
                'description': 'Electrical repair and installation',
                'base_price': 1200.00,
                'category': 'Maintenance'
            },
            {
                'service_name': 'Painting',
                'description': 'Interior and exterior painting services',
                'base_price': 1500.00,
                'category': 'Renovation'
            },
            {
                'service_name': 'Gardening',
                'description': 'Garden maintenance and landscaping',
                'base_price': 600.00,
                'category': 'Outdoor'
            }
        ]
        
        for service_data in services:
            service = Service(**service_data)
            db.session.add(service)
    
    try:
        db.session.commit()
        print("Database initialized successfully!")
    except Exception as e:
        db.session.rollback()
        print(f"Error initializing database: {e}")

# Import routes after db initialization
from routes import *

if __name__ == '__main__':
    app.run(debug=True)
 
