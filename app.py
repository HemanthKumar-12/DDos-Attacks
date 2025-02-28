from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from werkzeug.security import generate_password_hash, check_password_hash
import os
import email_validator
import pickle
import pandas as pd
import numpy as np
from werkzeug.utils import secure_filename
import lightgbm as lgb

from functools import wraps
from flask import redirect, url_for

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()  # Use a random secret key

def init_db():
    with sqlite3.connect('users.db') as conn:
        print('con sucss')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()

init_db()

class SignInForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class SignUpForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/signin", methods=['GET', 'POST'])
def signin():
    form = SignInForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT password FROM users WHERE username = ?', (email,))
            user = cursor.fetchone()
            if user and check_password_hash(user[0], password):
                session['user'] = email
                flash('Successfully signed in!', 'success')
                return redirect(url_for('recomendation'))
            else:
                flash('Invalid credentials, please try again.', 'danger')

    return render_template("signin.html", form=form)

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    form = SignUpForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        hashed_password = generate_password_hash(password)
        print(email)
        print(hashed_password)

        with sqlite3.connect('users.db') as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO users (name, username, password)
                    VALUES (?, ?, ?)
                ''', (name, email, hashed_password))
                conn.commit()
                flash('Account created successfully!', 'success')
                return redirect(url_for('signin'))
            except sqlite3.IntegrityError:
                flash('Username already exists!', 'danger')

    return render_template("signup.html", form=form)



def signin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            flash('You need to sign in first!', 'warning')
            return redirect(url_for('signin'))
        return f(*args, **kwargs)
    return decorated_function

app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'xlsx', 'xls'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

loaded_model = pickle.load(open('lgbm_model.pkl', 'rb'))




@app.route("/recomendation", methods=['GET', 'POST'])
@signin_required
def recomendation():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            try:
                # Read the file
                df = pd.read_excel(file_path)
                
                # Debug: print the DataFrame and its shape
                #print("DataFrame loaded successfully.")
                #print(df.head())
                #print(f"DataFrame shape: {df.shape}")
                
                # Check if the DataFrame is empty
                if df.empty:
                    flash('The uploaded file is empty.', 'danger')
                    return redirect(request.url)
                
                # Load the scaler
                scaler = pickle.load(open('minmax_scaler.pkl', 'rb'))

                # Process the data (ensure this matches your model's expected input)
                X_record = df

                # Apply the scaler
                X_scaled = scaler.transform(X_record)

                #print(X_scaled)
                # Debug: print the shape of X_scaled
                #print(f"X_scaled shape: {X_scaled.shape}")
                
                LABELS = {
                            0: 'Botnet',
                            1: 'Brute Force',
                            2: 'DoS/DDoS',
                            3: 'Infiltration',
                            4: 'Normal',
                            5: 'Port Scan',
                            6: 'Web Attack'
                        }
                
                # Make predictions
                predictions = loaded_model.predict(X_scaled)
                predicted_class_indices = np.argmax(predictions, axis=1)
                #print(predicted_class_indices)
                # Convert indices to labels
                predicted_classes = [LABELS[idx] for idx in predicted_class_indices]
                #print(predicted_classes)
                # Display the results
                return render_template('recomendation.html', predictions=predicted_classes)

            except Exception as e:
                flash(f'An error occurred: {e}', 'danger')
                return redirect(request.url)

    return render_template("recomendation.html")




@app.route("/signout")
def signout():
    session.pop('user', None)
    flash('You have been signed out.', 'info')
    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(debug=True)
