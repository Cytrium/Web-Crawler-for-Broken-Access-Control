# app/__init__.py

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

db = SQLAlchemy()
migrate = Migrate()
oauth = OAuth()

def create_app():
    print("🧩 Flask is initializing...")
    app = Flask(__name__)
    
    # Load secret key from environment or use default for development
    app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key')

    # MySQL Database Configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/perimeter'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    try:
        # Initialize the database
        db.init_app(app)
        migrate.init_app(app, db)

        print("----------------------")
        
        print("Database initialized")

        # Initialize OAuth
        oauth.init_app(app)
        
        # Register Google OAuth
        oauth.register(
            name='google',
            client_id=os.getenv('GOOGLE_CLIENT_ID'),
            client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
            server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
            client_kwargs={
                'scope': 'openid email profile'
            }
        )
        
        # Register GitHub OAuth
        oauth.register(
            name='github',
            client_id=os.getenv('GITHUB_CLIENT_ID'),
            client_secret=os.getenv('GITHUB_CLIENT_SECRET'),
            access_token_url='https://github.com/login/oauth/access_token',
            access_token_params=None,
            authorize_url='https://github.com/login/oauth/authorize',
            authorize_params=None,
            api_base_url='https://api.github.com/',
            client_kwargs={'scope': 'user:email'},
        )
        
        print("OAuth providers registered (Google, GitHub)")

        # Import models so they register with SQLAlchemy
        from app import models
        print("Models imported")

        # Register routes (blueprints)
        from app.routes import main
        app.register_blueprint(main)
        print("Routes registered")

        # Register admin routes
        from app.admin_routes import admin
        app.register_blueprint(admin)
        print("Admin routes registered")

        # Create tables if they don't exist
        with app.app_context():
            db.create_all()
        print("Tables created")

        print("----------------------")

    except Exception as e:
        print("ERROR during app initialization:", e)
        raise e

    return app
