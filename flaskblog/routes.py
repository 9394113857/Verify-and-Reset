from functools import wraps
import os
import secrets
from PIL import Image
from flask import render_template, url_for, flash, redirect, request, abort, jsonify, make_response
from flaskblog import app, db, bcrypt, mail
from flaskblog.forms import (RegistrationForm, LoginForm, UpdateAccountForm,
                             PostForm, RequestResetForm, ResetPasswordForm)
from flaskblog.models import PasswordHistory, User, Post
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message
import jwt
import datetime

# Helper function to generate access token (valid for 30 minutes)
def generate_access_token(identity):
    payload = {
        'identity': identity,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)  # Token expires in 30 minutes
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

# Helper function to generate refresh token (valid for 7 days)
def generate_refresh_token(identity):
    payload = {
        'identity': identity,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)  # Token expires in 7 days
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

# Decorator to ensure token authentication
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'x-access-token' not in request.cookies:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            access_token = request.cookies.get('x-access-token')
            jwt.decode(access_token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Home route
@app.route("/")
@app.route("/home")
def home():
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    return render_template('home.html', posts=posts)

# About route
@app.route("/about")
def about():
    return render_template('about.html', title='About')

# Function to send verification email after registration
def send_verification_email(user):
    token = user.get_verification_token()
    msg = Message('Email Verification',
                  sender='noreply@demo.com',
                  recipients=[user.email])
    msg.body = f'''To verify your email, visit the following link:
{url_for('verify_email', token=token, _external=True)}

If you did not create an account, please ignore this email.
'''
    mail.send(msg)

# Registration route with email verification
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        send_verification_email(user)  # Send verification email
        flash('An email has been sent with instructions to verify your email.', 'info')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

# Email verification route
@app.route("/verify_email/<token>", methods=['GET'])
def verify_email(token):
    user = User.verify_verification_token(token)
    if user:
        user.verified = True  # Mark the user as verified
        db.session.commit()   # Commit the changes to the database
        flash('Your email has been verified. You can now log in.', 'success')
        return redirect(url_for('login'))
    else:
        flash('The verification link is invalid or expired.', 'danger')
        return redirect(url_for('home'))

# Login route with JWT token generation
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if user.verified:  # Check if user is verified
                login_user(user, remember=form.remember.data)
                access_token = generate_access_token(identity=user.id)
                response = make_response(redirect(url_for('home')))
                response.set_cookie('x-access-token', access_token, httponly=True)
                next_page = request.args.get('next')
                return response if next_page else response
            else:
                flash('Your email is not verified. Please check your email.', 'warning')
                return redirect(url_for('login'))
        else:
            flash('Login unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

# Logout route with JWT token removal
@app.route("/logout")
def logout():
    logout_user()
    response = make_response(redirect(url_for('home')))
    response.delete_cookie('x-access-token')
    return response

# Save profile picture
def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)
    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn

# Account route to update user info and profile picture
@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account',
                           image_file=image_file, form=form)

# Post routes (create, update, delete, view)
@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        post = Post(title=form.title.data, content=form.content.data, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Your post has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('create_post.html', title='New Post', form=form, legend='New Post')

@app.route("/post/<int:post_id>")
def post(post_id):
    post = Post.query.get_or_404(post_id)
    return render_template('post.html', title=post.title, post=post)

@app.route("/post/<int:post_id>/update", methods=['GET', 'POST'])
@login_required
def update_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()
        flash('Your post has been updated!', 'success')
        return redirect(url_for('post', post_id=post.id))
    elif request.method == 'GET':
        form.title.data = post.title
        form.content.data = post.content
    return render_template('create_post.html', title='Update Post', form=form, legend='Update Post')

@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Your post has been deleted!', 'success')
    return redirect(url_for('home'))

# User posts page
@app.route("/user/<string:username>")
def user_posts(username):
    page = request.args.get('page', 1, type=int)
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(author=user)\
        .order_by(Post.date_posted.desc())\
        .paginate(page=page, per_page=5)
    return render_template('user_posts.html', posts=posts, user=user)

# Before updating password
from werkzeug.security import check_password_hash

def is_reused_password(user, new_password):
    for entry in user.password_history:
        if check_password_hash(entry.password_hash, new_password):
            return True
    return False


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    user = User.verify_reset_token(token)
    if user is None:
        flash('⚠️ The token is invalid or has expired.', 'warning')
        return redirect(url_for('reset_request'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        new_password = form.password.data

        # Check against current password
        if bcrypt.check_password_hash(user.password, new_password):
            flash("⛔ New password cannot be same as the old one.", "danger")
            return redirect(url_for('reset_token', token=token))

        # Check against last 5 password hashes
        recent_history = PasswordHistory.query.filter_by(user_id=user.id).order_by(PasswordHistory.timestamp.desc()).limit(5).all()
        for entry in recent_history:
            if bcrypt.check_password_hash(entry.password_hash, new_password):
                flash("🚫 You cannot reuse any of your last 5 passwords.", "danger")
                return redirect(url_for('reset_token', token=token))

        # Hash new password and update user
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_password
        db.session.add(user)

        # Save new password to history
        history_entry = PasswordHistory(user_id=user.id, password_hash=hashed_password)
        db.session.add(history_entry)

        # Optional Cleanup: Keep only latest 5 passwords in DB
        all_history = PasswordHistory.query.filter_by(user_id=user.id).order_by(PasswordHistory.timestamp.desc()).all()
        if len(all_history) > 5:
            for old_entry in all_history[5:]:
                db.session.delete(old_entry)

        db.session.commit()
        flash('✅ Your password has been successfully updated.', 'success')
        return redirect(url_for('login'))

    return render_template("reset_token.html", title="Reset Password", form=form)


# Error handling for 403 Forbidden error
@app.errorhandler(403)
def forbidden_error(error):
    return render_template('errors/403.html'), 403

# Error handling for 404 Not Found error
@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

# Error handling for 500 Internal Server Error
@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()  # Rollback any database changes due to the error
    return render_template('errors/500.html'), 500
