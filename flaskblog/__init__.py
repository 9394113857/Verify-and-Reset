import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail
from flask_migrate import Migrate  # ✅ Migration support

# --- Initialize extensions globally ---
app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECURITY_PASSWORD_SALT'] = 'my_precious_two'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'barlapudiraghu@gmail.com'
app.config['MAIL_PASSWORD'] = 'imkn rath spoe vayl'  # ✅ Your latest Gmail app password

# --- Initialize Flask extensions with app ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
mail = Mail(app)
migrate = Migrate(app, db)  # ✅ Add this line to support flask-migrate

login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# --- Import routes at the end ---
from flaskblog import routes
