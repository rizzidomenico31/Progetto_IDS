import email
import os
import random
import secrets
from crypt import methods
from urllib.parse import urlencode
from hashlib import md5

import hashlib
import requests
from flask import Flask, render_template, redirect, url_for, current_app, abort, session, request, flash
from flask.cli import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager , UserMixin , login_user , logout_user , current_user , user_unauthorized
from dotenv import load_dotenv
from flask_mail import Mail, Message
from config import app
from funzioni_utili import send_otp , send_reset_password

load_dotenv()



mail = Mail(app)
db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view='login'
app.app_context().push()

@login.user_loader
def load_user(id):
    return db.session.query(User).get(id)

class User(UserMixin , db.Model):
    __tablename__ = 'utenti'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255) , nullable=False)
    email = db.Column(db.String(255) , nullable=True)
    hash_password = db.Column(db.String(200) , nullable=True)
    nome = db.Column(db.String(50) , nullable=True)
    cognome = db.Column(db.String(50) , nullable=True)
    verificato = db.Column(db.Boolean() , nullable=True)
    otp = db.Column(db.Integer() , nullable=True)
    securetoken = db.Column(db.String(100) , nullable=True)



@app.route('/'  ,methods=['GET','POST'])
def index():
    if not current_user.is_anonymous:
        username = current_user.username
        return render_template('index.html' , username=username )

    else:
        return redirect(url_for('login'))

@app.route('/login')
def login():# put application's code here
    return render_template('login.html')

@app.route('/trylogin' , methods=['GET','POST'])
def trylogin():
    email = request.form['email']
    hash_password = hashlib.md5(request.form['password'].encode()).hexdigest()
    user = db.session.scalar(db.Select(User).where(User.email == email , User.hash_password == hash_password ))
    if user is not None:
        login_user(user)
        return redirect(url_for('index'))
    else:
        return render_template('login.html' , errore = "Username o Password Errati!")

@app.route('/reset-password' , methods=['GET','POST'])
def reset_password():

    if request.method == 'POST':
        if request.form['changepassword'] == '5x53': #submit del form di invio link per cambio password
            email = request.form['email']
            user = db.session.scalar(db.Select(User).where(User.email == email))
            if user is None:
                return render_template('forgot-password.html' , errore= "Attenzione! Email non registrata!")
            reset_token = secrets.token_urlsafe(32)
            user.securetoken = reset_token
            db.session.commit()
            url = 'http://127.0.0.1:5000/reset-password?req=5x54&userid=' + str(user.id)  + '&securetoken=' + reset_token
            if send_reset_password(email  , url , mail) == True:
                return redirect(url_for('login'))
        if request.form['changepassword'] == '5x55': #submit del form di cambio password
            hash_password = hashlib.md5(request.form['password'].encode()).hexdigest()
            user = db.session.scalar(db.Select(User).where(User.id == session.get('change-user-id')))
            user.hash_password = hash_password
            db.session.commit()
            return render_template('login.html' , errore = "Password modificata con successo! Effettua il Login!")
        else:
            return render_template('forgot-password.html' , errore = 'Attenzione! Servizio momentaneamente fuori uso!')
    if request.method == 'GET':
        if request.args.get('req') == '5x54' and request.method == 'GET': #parte che viene eseguita aprendo il link via mail
            print('000')
            id = int(request.args.get('userid'))
            user = db.session.scalar(db.Select(User).where(User.id == id))

            if user.securetoken == request.args.get('securetoken'):
                session['change-user-id'] = user.id
                return render_template('change-password.html' , username = user.username)


    return render_template('login.html')
@app.route('/register')
def register():  # put application's code here
    return render_template('register.html')

@app.route('/verify' , methods=['GET', 'POST'])
def verify():
    if current_user.is_authenticated and current_user.verificato == 0:  #caso in cui l'utente ha effettuato la registrazione ma non ha attivato l'account
        return render_template('verify.html')
    if request.form['email'] is None:
        return redirect(url_for('login'))
    nome = request.form['nome']
    cognome = request.form['cognome']
    email = request.form['email']
    hash_password = hashlib.md5(request.form['password'].encode()).hexdigest()
    user = db.session.scalar(db.Select(User).where(User.email == email))
    if user is None:
        otp =  random.randint(10000 , 99999)
        user = User(nome=nome , cognome=cognome , hash_password = hash_password  , email = email , username = email.split('@')[0] , verificato =False , otp = otp)
        db.session.add(user)
        db.session.commit()
        if send_otp(user.email , otp , mail) == True:
            login_user(user)
            return render_template('verify.html')
    if user.verificato == 0:
        login_user(user)
        return render_template('verify.html')

    if user.verificato == 1:
        return render_template('register.html' , error = 'Utente già registrato!')

    if user.verificato is None:
        return render_template('register.html' , error = 'Utente già registrato tramite terze parti!')





    return render_template('verify.html')

@app.route('/attivazione' , methods=['GET', 'POST'])
def attivazone():
    if current_user.is_anonymous:
        return redirect(url_for('login'))
    otp_user = request.form['otp']
    print(otp_user)
    print(current_user.otp)
    if int(current_user.otp) == int(otp_user):
        current_user.verificato = 1
        db.session.commit()
        return render_template('success.html' , nome = current_user.nome , cognome = current_user.cognome)
    else:
        return render_template('verify.html' , error="OTP Errato!")
    return


@app.route('/forgot-password')
def forgotpassword():
    return render_template('forgot-password.html')

@app.route('/logout')
def logout():
    session.clear()
    logout_user()

    return redirect(url_for('login'))
@app.route('/authorize/<provider>')
def oauth2_authorize(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))

    provider_data = current_app.config['OAUTH2_PROVIDERS'].get(provider)
    if provider_data is None:
        abort(404)

    # generate a random string for the state parameter
    session['oauth2_state'] = secrets.token_urlsafe(16)

    # create a query string with all the OAuth2 parameters
    qs = urlencode({
        'client_id': provider_data['client_id'],
        'redirect_uri': url_for('oauth2_callback', provider=provider,
                                _external=True),
        'response_type': 'code',
        'scope': ' '.join(provider_data['scopes']),
        'state': session['oauth2_state'],
    })

    # redirect the user to the OAuth2 provider authorization URL
    return redirect(provider_data['authorize_url'] + '?' + qs)

@app.route('/callback/<provider>')
def oauth2_callback(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('index'))

    provider_data = current_app.config['OAUTH2_PROVIDERS'].get(provider)
    if provider_data is None:
        abort(404)

    # if there was an authentication error, flash the error messages and exit
    if 'error' in request.args:
        for k, v in request.args.items():
            if k.startswith('error'):
                flash(f'{k}: {v}')
        return redirect(url_for('index'))

    # make sure that the state parameter matches the one we created in the
    # authorization request
    if request.args['state'] != session.get('oauth2_state'):
        abort(401)

    # make sure that the authorization code is present
    if 'code' not in request.args:
        abort(401)

    # exchange the authorization code for an access token
    response = requests.post(provider_data['token_url'], data={
        'client_id': provider_data['client_id'],
        'client_secret': provider_data['client_secret'],
        'code': request.args['code'],
        'grant_type': 'authorization_code',
        'redirect_uri': url_for('oauth2_callback', provider=provider,
                                _external=True),
    }, headers={'Accept': 'application/json'})
    if response.status_code != 200:
        abort(401)
    oauth2_token = response.json().get('access_token')
    if not oauth2_token:
        abort(401)

    # use the access token to get the user's email address
    response = requests.get(provider_data['userinfo']['url'], headers={
        'Authorization': 'Bearer ' + oauth2_token,
        'Accept': 'application/json',
    })
    print(provider_data)
    if response.status_code != 200:
        abort(401)
    email = provider_data['userinfo']['email'](response.json())
    if provider == 'github' and '+' in email:
        email = email.split('+')[1]

    # find or create the user in the database
    user = db.session.scalar(db.select(User).where(User.username == email.split('@')[0] ))
    if user is None:
        user = User(email=email, username=email.split('@')[0])
        db.session.add(user)
        db.session.commit()

    # log the user in
    login_user(user)

    return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run()
