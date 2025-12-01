# app/__init__.py

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

db = SQLAlchemy()
migrate = Migrate()

def create_app():
    print("🧩 Flask is initializing...")
    app = Flask(__name__)
    app.secret_key = 'your_secret_key'

    # MySQL Database Configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/perimeter'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    try:
        # Initialize the database
        db.init_app(app)
        migrate.init_app(app, db)

        print("✅ Database initialized")

        # Import models so they register with SQLAlchemy
        from app import models
        print("✅ Models imported")

        # Register routes (blueprints)
        from app.routes import main
        app.register_blueprint(main)
        print("✅ Routes registered")

        # Create tables if they don't exist
        with app.app_context():
            db.create_all()
        print("✅ Tables created")

    except Exception as e:
        print("❌ ERROR during app initialization:", e)
        raise e

    return app
