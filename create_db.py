from app import app
from models import db, Admin, create_default_admin

def init_db():
    with app.app_context():
        # Drop all existing tables
        print("Dropping all tables...")
        db.drop_all()
        
        # Create all tables
        print("Creating new tables...")
        db.create_all()
        
        # Create default admin
        print("Creating default admin...")
        create_default_admin()
        
        print("Database created successfully!")

if __name__ == "__main__":
    init_db() 