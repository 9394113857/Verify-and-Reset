# Import necessary modules
from datetime import datetime  # To handle date and time
from flask import current_app  # For accessing app context (needed for token generation)
from flaskblog import db, login_manager  # Importing the database instance and login manager
from flask_login import UserMixin  # Mixin to add Flask-Login functionalities to User model
from itsdangerous import URLSafeTimedSerializer as Serializer  # For creating time-sensitive tokens

# Define user loader callback for Flask-Login, which loads a user by ID
@login_manager.user_loader
def load_user(user_id):
    # Fetch user based on primary key 'user_id'
    return User.query.get(int(user_id))

# User model to represent users in the database
class User(db.Model, UserMixin):
    # Primary key for User model
    id = db.Column(db.Integer, primary_key=True)
    # Unique username for the user (max 20 characters)
    username = db.Column(db.String(20), unique=True, nullable=False)
    # Unique email for the user (max 120 characters)
    email = db.Column(db.String(120), unique=True, nullable=False)
    # Profile image file path (default to 'default.jpg')
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    # Hashed password (max 60 characters)
    password = db.Column(db.String(60), nullable=False)
    # Boolean flag for email verification status
    verified = db.Column(db.Boolean, default=False)
    
    # Define relationship with Post model (backref creates a reference back to 'author')
    posts = db.relationship('Post', backref='author', lazy=True)

    # Method to generate email verification token
    def get_verification_token(self, expires_sec=1800):
        # Instantiate the serializer with secret key
        s = Serializer(current_app.config['SECRET_KEY'])
        # Create a token with user ID, expires in 'expires_sec' seconds
        return s.dumps({'user_id': self.id}, salt=current_app.config['SECURITY_PASSWORD_SALT'])

    # Static method to verify the email verification token
    @staticmethod
    def verify_verification_token(token, expires_sec=1800):
        # Instantiate the serializer with secret key
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            # Decode token to retrieve user ID, max age enforced
            user_id = s.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=expires_sec)['user_id']
        except:
            # Return None if token is invalid or expired
            return None
        # Retrieve user by ID
        return User.query.get(user_id)

    # Method to generate password reset token
    def get_reset_token(self, expires_sec=1800):
        # Instantiate the serializer with secret key
        s = Serializer(current_app.config['SECRET_KEY'])
        # Create a token with user ID, expires in 'expires_sec' seconds
        return s.dumps({'user_id': self.id}, salt=current_app.config['SECURITY_PASSWORD_SALT'])

    # Static method to verify the password reset token
    @staticmethod
    def verify_reset_token(token, expires_sec=1800):
        # Instantiate the serializer with secret key
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            # Decode token to retrieve user ID, max age enforced
            user_id = s.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=expires_sec)['user_id']
        except:
            # Return None if token is invalid or expired
            return None
        # Retrieve user by ID
        return User.query.get(user_id)

# Post model to represent blog posts in the database
class Post(db.Model):
    # Primary key for Post model
    id = db.Column(db.Integer, primary_key=True)
    # Title of the post (max 100 characters)
    title = db.Column(db.String(100), nullable=False)
    # Date the post was created, defaults to current time
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    # Content of the post
    content = db.Column(db.Text, nullable=False)
    # Foreign key linking to the user's primary key
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
