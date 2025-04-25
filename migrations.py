from models import db
from sqlalchemy import text

def modify_professionals_table():
    with db.engine.connect() as connection:
        try:
            # Drop the temporary table if it exists
            connection.execute(text("DROP TABLE IF EXISTS professionals_new"))
            
            # Create a new temporary table with the desired schema
            connection.execute(text("""
                CREATE TABLE professionals_new (
                    professional_id INTEGER PRIMARY KEY,
                    full_name VARCHAR(100) NOT NULL,
                    email VARCHAR(120) NOT NULL UNIQUE,
                    phone VARCHAR(20) NOT NULL,
                    experience_years INTEGER NOT NULL,
                    password_hash VARCHAR(128),
                    is_verified INTEGER DEFAULT 0,
                    avg_rating REAL DEFAULT 0.0,
                    total_ratings INTEGER DEFAULT 0,
                    created_at TEXT,
                    specialization VARCHAR(100) DEFAULT NULL
                )
            """))
            
            # Copy data from the old table to the new one, setting NULL for specialization
            connection.execute(text("""
                INSERT INTO professionals_new 
                SELECT professional_id, full_name, email, phone, experience_years, 
                       password_hash, is_verified, avg_rating, total_ratings, 
                       datetime(created_at), NULL as specialization
                FROM professionals
            """))
            
            # Drop the old table
            connection.execute(text("DROP TABLE professionals"))
            
            # Rename the new table to the original name
            connection.execute(text("ALTER TABLE professionals_new RENAME TO professionals"))
            
            print("Modified professionals table successfully")
            
        except Exception as e:
            print(f"Error modifying professionals table: {e}")
            raise

def add_password_hash_column():
    with db.engine.connect() as connection:
        # Check if column exists first
        result = connection.execute(text("""
            SELECT COUNT(*) as count 
            FROM pragma_table_info('professionals') 
            WHERE name='password_hash'
        """))
        if result.fetchone()[0] == 0:
            # Add the column if it doesn't exist
            connection.execute(text("""
                ALTER TABLE professionals 
                ADD COLUMN password_hash VARCHAR(128)
            """))
            print("Added password_hash column to professionals table")
        else:
            print("password_hash column already exists")

if __name__ == "__main__":
    from app import app
    with app.app_context():
        add_password_hash_column()
        modify_professionals_table() 