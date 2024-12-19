import os
import secrets

from flask.cli import load_dotenv

from flask_mail import Mail , Message


load_dotenv()
def send_otp(email , otp , mail):


    msg = Message(
        subject='Attiva il tuo Account - OTP Code',
        sender=os.environ.get('MAIL_USERNAME'),
        recipients=[email]
    )
    msg.body = 'Ecco il tuo OTP Code: \n' + str(otp) + '\nInserisci questo codice per attivare il tuo account!'
    mail.send(msg)
    return True

def send_reset_password(email , url , mail):
    msg = Message(
        subject='Reset Password - Gruppo 4 Politecnico di Bari',
        sender = os.environ.get('MAIL_USERNAME'),
        recipients = [email]
    )
    msg.body = "Di seguito troverai il link per resettare la tua password: \n" + str(url)

    mail.send(msg)
    return True

