import json
from flaskr.models import User, Report
from flaskr import app, db, bcrypt, mail
from flask import render_template, url_for, redirect, flash
from flaskr.forms import RegistrationForm, LoginForm, UpdateAccountForm, RequestResetForm, ResetPasswordForm
from flask import request, jsonify
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message

ELECTRICITY = 0.439
LPG =1.56
COAL = 43.03576
DOMESTIC_FLIGHT = 0.24587
INTERNATIONAL_FLIGHT = 0.18362

fuel_emmmision_factors = {
    'petrol': 2.34,  # Default emission factor for petrol
    'diesel': 2.70  # Default emission factor for diesel
}

@app.route("/")
def home():
    return render_template('home.html', title="Home")

@app.route("/about")
def about():
    return render_template('about.html', title="About")


@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, company_name=form.company_name.data, company_description=form.company_description.data,
                    address=form.address.data, city=form.city.data, state=form.state.data, zip=form.zip_code.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash(f'Account created for {form.username.data}', 'success')
        return redirect(url_for('home'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash("Login successful", 'success')
            return redirect(next_page) if next_page else  redirect(url_for('calculate'))
        else:
            print('error')
            flash(f'Invalid username or password! Try again.', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/submit", methods=['POST'])
@login_required
def submit():
    data = request.json
    motor_vehicle = data.get('motorVehicle', [])
    motorbike = data.get('motorbike', [])
    tricycle = data.get('tricycle', [])
    flight_domestic = data.get('flightDomestic',[])
    flight_international = data.get('flightInternational')
    # print('motor vehicle: ', motor_vehicle)    
    # print('motorbike: ', motorbike)
    # print('tricycle: ', tricycle)
    # print('flight domestic: ', flight_domestic)   
    return jsonify({'message': 'data received!'})


@app.route('/calculate', methods=['GET'])
@login_required
def calculate():
    return render_template('calculate.html', title="Calculate")


@app.route('/account', methods = ['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Account info updated successfully', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', image_file=image_file, form=form, title="Account")

def send_reset_mail(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', sender='noreply@ogundeyiboluwatife.com.ng', recipients=[user.email])
    msg.body = f'''To reset your password, visit the link below: 
    {url_for('reset_token', token=token, _external=True)}
        If you did not make this request, you can safely ignore this email.
    '''
    mail.send(msg)

@app.route("/reset_password", methods=['POST', 'GET'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form =  RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_mail(user)
        flash('A password reset link has been sent to your email address', 'success')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)

@app.route("/reset_password/<token>", methods=['POST', 'GET'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)

    if user is None:
        flash('That is an invalid/expired token', 'warning')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash(f'Password updated successfully', 'success')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

