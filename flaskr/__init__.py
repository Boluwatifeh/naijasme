import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_mail import Mail

app = Flask(__name__)
app.config['SECRET_KEY'] = 'be16ffeeed186879873c70376509e506'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db' 
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'danger'
app.config['MAIL_SERVER'] = 'wghp5.wghservers.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = os.environ.get('USERNAME')
app.config['MAIL_USERNAME'] = 'noreply@ogundeyiboluwatife.com.ng'
app.config['MAIL_PASSWORD'] = 'QWERTYUIOP!@#$'
# app.config['MAIL_PASSWORD'] = os.environ.get('PASSWORD')
mail = Mail(app)


from flaskr import routes