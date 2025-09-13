from functools import wraps  # For decorator functions
import os  # For file and directory operations
import secrets  # For generating secure random tokens
from PIL import Image  # For image processing (profile pictures)
from flask import render_template, url_for, flash, redirect, request, abort, jsonify, make_response  # Flask utilities
from flaskblog import app, db, bcrypt, mail  # Importing app, database, bcrypt, and mail from flaskblog package
from flaskblog.forms import (RegistrationForm, LoginForm, UpdateAccountForm,
                             PostForm, RequestResetForm, ResetPasswordForm)  # Importing forms
from flaskblog.models import User, Post  # Importing database models
from flask_login import login_user, current_user, logout_user, login_required  # Flask-Login utilities
from flask_mail import Message  # For sending emails
import jwt  # For JWT token encoding/decoding
import datetime  # For date and time operations
import logging  # For logging
from logging.handlers import RotatingFileHandler  # For rotating log files
from datetime import date  # For working with dates

# --- ----------------- Logging Setup ----------------- ---
# Logs are stored in logs/YYYY/MM/DD.log with rotation
logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')  # Directory for logs
current_year = date.today().strftime('%Y')  # Current year as string
current_month = date.today().strftime('%m')  # Current month as string
year_month_dir = os.path.join(logs_dir, current_year, current_month)  # Directory for year/month logs
os.makedirs(year_month_dir, exist_ok=True)  # Create directory if it doesn't exist
log_file = os.path.join(year_month_dir, f'{date.today()}.log')  # Log file path for today

# --- ----------------- Logging Handler Setup ----------------- ---
# RotatingFileHandler is used for log rotation (max 1MB per file, 5 backups)
log_handler = RotatingFileHandler(log_file, maxBytes=1024*1024, backupCount=5)  # Create rotating log handler
# --------------------------------------------------------------
log_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s'))  # Log format

logger = logging.getLogger(__name__)  # Get logger for this module
logger.setLevel(logging.INFO)  # Set log level to INFO
logger.addHandler(log_handler)  # Add handler to logger
# --------------------------------------------------------

# --- ----------------- JWT Token Helpers ----------------- ---
def generate_access_token(identity):
    payload = {
        'identity': identity,  # User identity
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)  # Token expires in 30 mins
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')  # Encode JWT

def generate_refresh_token(identity):
    payload = {
        'identity': identity,  # User identity
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)  # Token expires in 7 days
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')  # Encode JWT

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'x-access-token' not in request.cookies:  # Check if token is present
            return jsonify({'message': 'Token is missing'}), 401
        try:
            access_token = request.cookies.get('x-access-token')  # Get token from cookies
            jwt.decode(access_token, app.config['SECRET_KEY'], algorithms=["HS256"])  # Decode JWT
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        return f(*args, **kwargs)  # Call original function
    return decorated_function
# ----------------------------------------------------------

# --- ----------------- Email Alert Helper ----------------- ---
def send_alert_email(subject, body, recipient):
    """
    Developer Note:
    ----------------
    Use this for sending critical alerts like:
      - Registration verification
      - Login notifications
      - Password changes
      - Profile updates
      - Post creation/update/deletion (optional)
    """
    msg = Message(subject=subject, sender='noreply@demo.com', recipients=[recipient])  # Create email message
    msg.body = body  # Set email body
    mail.send(msg)  # Send email
# ----------------------------------------------------------

# ----------------- Routes -----------------

@app.route("/")
@app.route("/home")
def home():
    page = request.args.get('page', 1, type=int)  # Get page number from query string
    posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)  # Paginate posts
    return render_template('home.html', posts=posts)  # Render home page with posts

@app.route("/about")
def about():
    return render_template('about.html', title='About')  # Render about page

# ----------------- Registration -----------------
def send_verification_email(user):
    """Send email verification link with HTML template and logging."""
    token = user.get_verification_token()
    msg = Message(
        subject='Email Verification',
        sender='noreply@demo.com',
        recipients=[user.email]
    )
    
    # Optional: Plain text fallback for better compatibility
    verification_link = url_for('verify_email', token=token, _external=True)
    msg.body = f'''To verify your email, click the link below:
{verification_link}

If you did not create an account, please ignore this email.
'''

    # HTML email using template
    msg.html = render_template('verify_email.html', user=user, token=token)

    try:
        mail.send(msg)
        logger.info(f"Verification email sent to: {user.email}")
    except Exception as e:
        logger.error(f"Failed to send verification email to {user.email}: {e}")


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:  # Redirect if already logged in
        return redirect(url_for('home'))

    form = RegistrationForm()  # Create registration form
    if form.validate_on_submit():  # If form is submitted and valid
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')  # Hash password
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)  # Create user
        db.session.add(user)  # Add user to database
        db.session.commit()  # Commit changes
        user.add_password_to_history(hashed_password)  # Mandatory: store password history

        send_verification_email(user)  # Send verification email
        flash('📧 An email has been sent with instructions to verify your account.', 'info')  # Flash message

        # Logging registration
        logger.info(f"New user registered: {user.username} / {user.email}")

        # Optional alert email for admin or monitoring
        # send_alert_email("New User Registered", f"User {user.username} registered.", "admin@example.com")

        return redirect(url_for('login'))  # Redirect to login

    return render_template('register.html', title='Register', form=form)  # Render registration page

@app.route("/verify_email/<token>", methods=['GET'])
def verify_email(token):
    user = User.verify_verification_token(token)  # Verify token
    if user:
        user.verified = True  # Mark user as verified
        db.session.commit()  # Commit changes
        flash('Your email has been verified. You can now log in.', 'success')  # Flash message

        logger.info(f"User email verified: {user.username} / {user.email}")
        send_alert_email("Email Verified", f"Your email was successfully verified, {user.username}.", user.email)

        return redirect(url_for('login'))  # Redirect to login
    else:
        flash('The verification link is invalid or expired.', 'danger')  # Flash error
        return redirect(url_for('home'))  # Redirect to home

# ----------------- Login / Logout -----------------
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:  # Redirect if already logged in
        return redirect(url_for('home'))
    form = LoginForm()  # Create login form
    if form.validate_on_submit():  # If form is submitted and valid
        user = User.query.filter_by(email=form.email.data).first()  # Find user by email
        if user and bcrypt.check_password_hash(user.password, form.password.data):  # Check password
            if user.verified:  # Check if email is verified
                login_user(user, remember=form.remember.data)  # Log in user

                access_token = generate_access_token(identity=user.id)  # Generate access token
                response = make_response(redirect(url_for('home')))  # Create response
                response.set_cookie('x-access-token', access_token, httponly=True)  # Set token cookie

                # Logging login event
                logger.info(f"User logged in: {user.username} / {user.email}")

                # Optional: email alert for user login
                send_alert_email("Login Alert", f"Hello {user.username}, you logged in successfully.", user.email)

                return response  # Return response
            else:
                flash('Your email is not verified. Please check your email.', 'warning')  # Flash warning
                return redirect(url_for('login'))  # Redirect to login
        else:
            logger.warning(f"Failed login attempt for email: {form.email.data}")  # Log failed login
            flash('Login unsuccessful. Please check email and password', 'danger')  # Flash error
    return render_template('login.html', title='Login', form=form)  # Render login page

@app.route("/logout")
def logout():
    logout_user()  # Log out user
    response = make_response(redirect(url_for('home')))  # Create response
    response.delete_cookie('x-access-token')  # Delete token cookie
    logger.info(f"User logged out: {current_user.username if current_user.is_authenticated else 'Anonymous'}")
    return response  # Return response

# ----------------- Account / Profile -----------------
def save_picture(form_picture):
    random_hex = secrets.token_hex(8)  # Generate random hex for filename
    _, f_ext = os.path.splitext(form_picture.filename)  # Get file extension
    picture_fn = random_hex + f_ext  # Create new filename
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)  # Path to save picture
    output_size = (125, 125)  # Resize to 125x125
    i = Image.open(form_picture)  # Open image
    i.thumbnail(output_size)  # Resize image
    i.save(picture_path)  # Save image
    return picture_fn  # Return filename

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()  # Create update account form
    if form.validate_on_submit():  # If form is submitted and valid
        if form.picture.data:  # If picture uploaded
            picture_file = save_picture(form.picture.data)  # Save picture
            current_user.image_file = picture_file  # Update user image

        current_user.username = form.username.data  # Update username
        current_user.email = form.email.data  # Update email
        db.session.commit()  # Commit changes

        flash('Your account has been updated!', 'success')  # Flash success

        # Logging account update
        logger.info(f"Profile updated: {current_user.username} / {current_user.email}")

        # Optional: send alert to user
        send_alert_email("Profile Updated", f"Hello {current_user.username}, your profile was updated.", current_user.email)

        return redirect(url_for('account'))  # Redirect to account
    elif request.method == 'GET':  # If GET request
        form.username.data = current_user.username  # Pre-fill username
        form.email.data = current_user.email  # Pre-fill email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)  # Get image file URL
    return render_template('account.html', title='Account', image_file=image_file, form=form)  # Render account page

# ----------------- Post CRUD -----------------
@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()  # Create post form
    if form.validate_on_submit():  # If form is submitted and valid
        post = Post(title=form.title.data, content=form.content.data, author=current_user)  # Create post
        db.session.add(post)  # Add post to database
        db.session.commit()  # Commit changes
        flash('Your post has been created!', 'success')  # Flash success

        # Logging post creation
        logger.info(f"Post created: {post.title} by {current_user.username}")

        # Optional alert email
        send_alert_email("Post Created", f"Your post '{post.title}' was successfully created.", current_user.email)

        return redirect(url_for('home'))  # Redirect to home
    return render_template('create_post.html', title='New Post', form=form, legend='New Post')  # Render post form

@app.route("/post/<int:post_id>")
def post(post_id):
    post = Post.query.get_or_404(post_id)  # Get post by ID or 404
    return render_template('post.html', title=post.title, post=post)  # Render post page

@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)  # Get post by ID or 404
    if post.author != current_user:  # Check if current user is author
        abort(403)  # Forbidden
    form = PostForm()  # Create post form
    if form.validate_on_submit():  # If form is submitted and valid
        post.title = form.title.data  # Update title
        post.content = form.content.data  # Update content
        db.session.commit()  # Commit changes
        flash('Your post has been updated!', 'success')  # Flash success

        logger.info(f"Post updated: {post.title} by {current_user.username}")
        send_alert_email("Post Updated", f"Your post '{post.title}' was updated.", current_user.email)

        return redirect(url_for('post', post_id=post.id))  # Redirect to post
    elif request.method == 'GET':  # If GET request
        form.title.data = post.title  # Pre-fill title
        form.content.data = post.content  # Pre-fill content
    return render_template('create_post.html', title='Update Post', form=form, legend='Update Post')  # Render post form

@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)  # Get post by ID or 404
    if post.author != current_user:  # Check if current user is author
        abort(403)  # Forbidden
    db.session.delete(post)  # Delete post
    db.session.commit()  # Commit changes
    flash('Your post has been deleted!', 'success')  # Flash success

    logger.info(f"Post deleted: {post.title} by {current_user.username}")
    send_alert_email("Post Deleted", f"Your post '{post.title}' was deleted.", current_user.email)

    return redirect(url_for('home'))  # Redirect to home

@app.route("/user/<string:username>")
def user_posts(username):
    page = request.args.get('page', 1, type=int)  # Get page number from query string
    user = User.query.filter_by(username=username).first_or_404()  # Get user by username or 404
    posts = Post.query.filter_by(author=user).order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)  # Paginate posts
    return render_template('user_posts.html', posts=posts, user=user)  # Render user posts page

# ----------------- Password Reset -----------------
def send_reset_email(user):
    """Send password reset email with HTML template and logging."""
    token = user.get_reset_token()

    msg = Message(
        subject='Password Reset Request',
        sender='noreply@demo.com',
        recipients=[user.email]
    )

    # Plain text fallback (recommended for compatibility)
    reset_link = url_for('reset_token', token=token, _external=True)
    msg.body = f'''To reset your password, click the link below:
{reset_link}

If you did not request a password reset, please ignore this email.
'''

    # HTML version using a Jinja2 template
    msg.html = render_template('reset_email.html', user=user, token=token)

    try:
        mail.send(msg)
        logger.info(f"Password reset email sent to: {user.email}")
    except Exception as e:
        logger.error(f"Failed to send password reset email to {user.email}: {e}")


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:  # Redirect if already logged in
        return redirect(url_for('home'))

    form = RequestResetForm()  # Create reset request form
    if form.validate_on_submit():  # If form is submitted and valid
        user = User.query.filter_by(email=form.email.data).first()  # Find user by email
        if user:
            send_reset_email(user)  # Send reset email
        else:
            flash('⚠️ No account found with that email.', 'warning')  # Flash warning
            logger.warning(f"Password reset requested for non-existing email: {form.email.data}")
    return render_template('reset_request.html', title='Reset Password', form=form)  # Render reset request page

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:  # Redirect if already logged in
        return redirect(url_for('home'))

    user = User.verify_reset_token(token)  # Verify token
    if user is None:
        flash('❌ That is an invalid or expired token', 'warning')  # Flash warning
        logger.warning(f"Invalid/expired reset token used")
        return redirect(url_for('reset_request'))  # Redirect to reset request

    form = ResetPasswordForm()  # Create reset password form
    if form.validate_on_submit():  # If form is submitted and valid
        if user.is_password_in_history(form.password.data):  # Check password history
            flash('⚠️ You cannot reuse one of your last 5 passwords. Please choose a new one.', 'danger')  # Flash error
            logger.warning(f"User {user.username} tried to reuse an old password")
            return redirect(url_for('reset_token', token=token))  # Redirect to reset token

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')  # Hash password
        user.password = hashed_password  # Update password
        db.session.commit()  # Commit changes
        user.add_password_to_history(hashed_password)  # Add to password history

        logger.info(f"Password updated for user: {user.username}")
        send_alert_email("Password Updated", f"Hello {user.username}, your password was changed successfully.", user.email)

        flash('✅ Your password has been updated! You can now log in.', 'success')  # Flash success
        return redirect(url_for('login'))  # Redirect to login

    return render_template('reset_token.html', title='Reset Password', form=form)  # Render reset password page

# ----------------- Error Handlers -----------------
@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403  # Render 403 error page

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404  # Render 404 error page

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()  # Rollback database session
    return render_template('errors/500.html'), 500  # Render 500 error page
