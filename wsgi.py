"""
WSGI entrypoint for production servers (e.g., Render + Gunicorn).

Render start command:
  gunicorn wsgi:app
"""

from app import create_app

app = create_app()

