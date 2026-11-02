"""
app/__init__.py
---------------
This file turns the 'app' folder into a Python package and
creates the Flask application instance.

The create_app() function is a common Flask pattern called
the "Application Factory". It lets us create the app
cleanly and makes testing easier later.
"""

from flask import Flask


def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)

    # Import and register the main routes (homepage, etc.)
    from app.routes import main
    app.register_blueprint(main)

    return app
