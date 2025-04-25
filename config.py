from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Configuration settings for the Flask app
SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI')
SQLALCHEMY_TRACK_MODIFICATIONS = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS', 'False') == 'True'
SECRET_KEY = os.getenv('SECRET_KEY')
