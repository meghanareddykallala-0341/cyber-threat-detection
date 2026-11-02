"""
run.py
------
The entry point for the Flask development server.

Run this file with:  python run.py

What it does:
  1. Calls create_app() to build the Flask application.
  2. Starts the built-in development web server on port 5000.
  3. debug=True means Flask auto-reloads when you edit a file
     and shows friendly error pages.

⚠️  debug=True is for development only.
     Never use it in production (on a public server).
"""

from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, port=5050)
