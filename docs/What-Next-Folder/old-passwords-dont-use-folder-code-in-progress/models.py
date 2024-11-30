from datetime import datetime  # To handle date and time
from werkzeug.security import check_password_hash, generate_password_hash  # Import for password hashing and verification
from flask import current_app  # For accessing app context (needed for token generation)
from flaskblog import db, login_manager  # Importing the database instance and login manager
from flask_login import UserMixin  # Mixin to add Flask-Login functionalities to User model
from itsdangerous import URLSafeTimedSerializer as Serializer  # For creating time-sensitive tokens

# Define user loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    # This function loads a user from the database by their user ID
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

    # Method to add the current password to the password history
    def add_password_to_history(self, new_password):
        # Hash the new password before saving it in history
        hashed_password = generate_password_hash(new_password)
        # Get the current date and time when the password is changed
        timestamp = datetime.utcnow()
        # Create a PasswordHistory record for the new password
        password_history = PasswordHistory(user_id=self.id, password_hash=hashed_password, changed_on=timestamp)
        # Add the record to the session and commit to save it
        db.session.add(password_history)
        db.session.commit()

    # Method to check if the new password is the same as any recent passwords
    def is_password_in_history(self, password):
        # Retrieve passwords history and check if any password matches
        history = PasswordHistory.query.filter_by(user_id=self.id).order_by(PasswordHistory.changed_on.desc()).limit(5).all()
        for record in history:
            # If any record matches the new password, return True (reuse detected)
            if check_password_hash(record.password_hash, password):
                return True
        # Return False if no match found (password is new)
        return False

    # Method to change the user's password
    def change_password(self, new_password):
        # Check if the new password has been used before
        if self.is_password_in_history(new_password):
            return False  # Reject password reuse
        # Hash the new password before saving
        self.password = generate_password_hash(new_password)
        # Store the new password in the password history
        self.add_password_to_history(new_password)
        # Commit the changes to the database
        db.session.commit()
        return True  # Successful password change


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


# PasswordHistory model to store old passwords and timestamps
class PasswordHistory(db.Model):
    # Primary key for PasswordHistory model
    id = db.Column(db.Integer, primary_key=True)
    # Foreign key linking to the user’s primary key
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Hashed password value
    password_hash = db.Column(db.String(60), nullable=False)
    # Timestamp of when the password was changed
    changed_on = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # Define a relationship back to the User model
    user = db.relationship('User', backref=db.backref('password_histories', lazy=True))
