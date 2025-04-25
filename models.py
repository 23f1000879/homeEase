from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class Service(db.Model):
    __tablename__ = 'services'
    
    service_id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    base_price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    service_requests = db.relationship('ServiceRequest', backref='service', lazy=True)
    professional_services = db.relationship('ProfessionalService', backref='service', lazy=True)

    def __repr__(self):
        return f'<Service {self.service_name}>'

class Professional(db.Model):
    __tablename__ = 'professionals'
    
    professional_id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    experience_years = db.Column(db.Integer, nullable=False)
    password_hash = db.Column(db.String(128))
    is_verified = db.Column(db.Boolean, default=False)
    avg_rating = db.Column(db.Float, default=0.0)
    total_ratings = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    service_requests = db.relationship('ServiceRequest', backref='professional', lazy=True)
    ratings = db.relationship('ProfessionalRating', backref='professional', lazy=True)
    professional_services = db.relationship('ProfessionalService', backref='professional', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def update_rating(self):
        ratings = ProfessionalRating.query.filter_by(professional_id=self.professional_id).all()
        if ratings:
            self.avg_rating = sum(r.rating for r in ratings) / len(ratings)
            self.total_ratings = len(ratings)
        else:
            self.avg_rating = 0.0
            self.total_ratings = 0

    def __repr__(self):
        return f'<Professional {self.full_name}>'

class Customer(db.Model):
    __tablename__ = 'customers'
    
    customer_id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    address = db.Column(db.Text, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    service_requests = db.relationship('ServiceRequest', backref='customer', lazy=True)
    ratings = db.relationship('ProfessionalRating', backref='customer', lazy=True)
    
    def set_password(self, password):
        self.password = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def __repr__(self):
        return f'<Customer {self.email}>'

class ServiceRequest(db.Model):
    __tablename__ = 'service_requests'
    
    request_id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.customer_id'), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey('professionals.professional_id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('services.service_id'), nullable=False)
    request_date = db.Column(db.Date, nullable=False)
    request_time = db.Column(db.Time, nullable=False)
    status = db.Column(db.String(20), default='Pending')  # Pending, Accepted, Completed, Rejected
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    accepted_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    rejected_at = db.Column(db.DateTime)
    
    # Relationship for ratings
    professional_rating = db.relationship('ProfessionalRating', backref='service_request', lazy=True)

    def __repr__(self):
        return f'<ServiceRequest {self.request_id}>'

class ProfessionalRating(db.Model):
    __tablename__ = 'professional_ratings'
    
    rating_id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey('service_requests.request_id'), nullable=False)
    professional_id = db.Column(db.Integer, db.ForeignKey('professionals.professional_id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('customers.customer_id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 stars
    review = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ProfessionalRating {self.rating_id}>'

class Admin(db.Model):
    __tablename__ = 'admins'
    
    admin_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    is_super_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def __repr__(self):
        return f'<Admin {self.email}>'

def create_default_admin():
    if not Admin.query.first():
        admin = Admin(email="admin@gmail.com")
        admin.password = "admin"  # Automatically hashes the password
        db.session.add(admin)
        db.session.commit()

class ProfessionalService(db.Model):
    __tablename__ = 'professional_services'
    
    id = db.Column(db.Integer, primary_key=True)
    professional_id = db.Column(db.Integer, db.ForeignKey('professionals.professional_id'), nullable=False)
    service_id = db.Column(db.Integer, db.ForeignKey('services.service_id'), nullable=False)
    price = db.Column(db.Float, nullable=False)
    is_available = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<ProfessionalService {self.id}>'
