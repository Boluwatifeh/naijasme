import json
from flaskr.models import User, Report
from flaskr import app, db, bcrypt, mail
from flask import render_template, url_for, redirect, flash
from flaskr.forms import RegistrationForm, LoginForm, UpdateAccountForm, RequestResetForm, ResetPasswordForm
from flask import request
from flask_login import login_user, current_user, logout_user, login_required
from flask_mail import Message

ELECTRICITY = 0.439
LPG =1.56
COAL = 43.03576
DOMESTIC_FLIGHT = 0.24587
INTERNATIONAL_FLIGHT = 0.18362

fuel_coefficients = {
    'petrol': 2.34,  # Default coefficient for petrol
    'diesel': 2.70  # Coefficient for diesel
}

@app.route("/")
def home():
    return render_template('home.html', title=home)

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


@app.route("/calculate", methods=['GET', 'POST'])
@login_required
def calculate():
    if request.method == 'POST':
        labels = []
        values = []
        form = request.form.items()
        for key, value in form:

            if "fuelType"  not  in key and "price" not in key:
                labels.append(key)
                values.append(float(value))           

        # Retrieve form data for each vehicle type
        motor_vehicle = float(request.form['motor_vehicle'])
        fuel_type = request.form['fuelType']
        fuel_price = float(request.form['motor_price'])
        fuel_type_coefficient = fuel_coefficients.get(fuel_type, 1)  # Get the coefficient based on fuel type
        
        motorbike = float(request.form['motorbike'])
        fuel_type2 = request.form['fuelType2']
        motorbike_price = float(request.form['motorbike_price'])
        fuel_type_coefficient2 = fuel_coefficients.get(fuel_type2, 1)
        
        tricycle = float(request.form['tricycle'])
        fuel_type3 = request.form['fuelType3']
        tricycle_price = float(request.form['tricycle_price'])
        fuel_type_coefficient3 = fuel_coefficients.get(fuel_type3, 1)

        flight_domestic = float(request.form['flight_domestic'])
        flight_domestic_price = float(request.form['flight_domestic_price'])
        domestic_flight_coefficient = flight_domestic * DOMESTIC_FLIGHT

        flight_international = float(request.form['flight_international'])
        flight_international_price = float(request.form['flight_international_price'])
        inter_flight_coefficient = flight_international * INTERNATIONAL_FLIGHT

        electricity = float(request.form['electricity'])
        electricity_price = float(request.form['electricity_price'])
        electricity_coefficient = electricity * ELECTRICITY

        generator = float(request.form['generator'])
        fuel_type4 = request.form['fuelType4']
        generator_price = float(request.form['generator_price'])
        fuel_type_coefficient4 = fuel_coefficients.get(fuel_type4, 1)

        lpg = float(request.form['lpg'])
        lpg_price = float(request.form['lpg_price'])
        lpg_coefficient = lpg * LPG

        coal = float(request.form['coal'])
        coal_price = float(request.form['coal_price'])
        coal_coefficient = coal * COAL
        
        # Process data for each vehicle type, multiplying by the coefficient
        motor_vehicle_coefficient = motor_vehicle * fuel_type_coefficient
        motorbike_coefficient = motorbike * fuel_type_coefficient2 
        tricycle_coefficient = tricycle * fuel_type_coefficient3 
        generator_coefficient = generator * fuel_type_coefficient4
        
        # Calculate total cost
        total_cost = fuel_price + motorbike_price + tricycle_price + flight_domestic_price + flight_international_price + electricity_price + generator_price + lpg_price + coal_price

         # Calculate total coefficient
        total_coefficient = (motor_vehicle_coefficient + motorbike_coefficient + tricycle_coefficient + domestic_flight_coefficient + inter_flight_coefficient + electricity_coefficient + generator_coefficient + lpg_coefficient + coal_coefficient) / 1000
        sum_of_coefficient = [int(motor_vehicle_coefficient + motorbike_coefficient + tricycle_coefficient + domestic_flight_coefficient + inter_flight_coefficient), int(electricity_coefficient + generator_coefficient + lpg_coefficient + coal_coefficient)]
        list_of_coefficient = [motor_vehicle_coefficient, motorbike_coefficient, tricycle_coefficient, domestic_flight_coefficient, inter_flight_coefficient, electricity_coefficient, generator_coefficient, lpg_coefficient, coal_coefficient]
        return render_template('calculate.html', 
                               motor_vehicle_coefficient=motor_vehicle_coefficient, 
                               motorbike_coefficient=motorbike_coefficient, 
                               tricycle_coefficient=tricycle_coefficient,
                               domestic_flight_coefficient=domestic_flight_coefficient,
                               inter_flight_coefficient=inter_flight_coefficient,
                               electricity_coefficient=electricity_coefficient,
                               generator_coefficient=generator_coefficient,
                               lpg_coefficient=lpg_coefficient,
                               coal_coefficient=coal_coefficient,
                               total_coefficient=total_coefficient,
                               total_cost=total_cost,
                               labels=json.dumps(labels), 
                               data=list_of_coefficient,
                               sum_of_coefficient=sum_of_coefficient
                               )
        
    return render_template('calculate.html')

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
    return render_template('account.html', image_file=image_file, form=form)

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

