from flaskr import db, login_manager
from datetime import datetime
from flask_login  import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    company_name = db.Column(db.String(50), unique=True, nullable=False)
    company_description = db.Column(db.Text, nullable=False)
    address = db.Column(db.String(120), unique=True, nullable=False)
    city = db.Column(db.String(20))
    state = db.Column(db.String(20), nullable=False)
    zip = db.Column(db.Integer)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    reports = db.relationship('Report', backref='user', lazy=True)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"

class Report(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255))
    data = db.Column(db.LargeBinary, nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id') ,nullable=False)

    def __repr__(self):
        return f"Report('{self.id}', '{self.filename}', '{self.date}')"