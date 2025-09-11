# --------------------------------------------
# PowerShell commands to run this Flask app:
#
# --- Development Mode ---
# $env:FLASK_APP = "app.py"                # Specify the Flask app file
# $env:FLASK_ENV = "development"           # Enable debug mode (auto-reload and debugger)
# flask run                                # Run Flask’s built-in development server
#
# --- Production Mode ---
# $env:FLASK_APP = "app.py"                # Specify the Flask app file (optional)
# $env:FLASK_ENV = "production"            # Disable debug mode for better performance
# pip install waitress                     # Install Waitress WSGI server if not installed
# waitress-serve --port=8000 flaskblog:app # Run the app with Waitress on port 8000
# --------------------------------------------

from flaskblog import app, db                   # Import the Flask app and database instance
 
if __name__ == '__main__':
    with app.app_context():                    # Create an application context for database operations
        db.create_all()                        # Create all tables based on the models if they don’t exist
    app.run()                                  # Run the Flask development server (debug disabled by default)
