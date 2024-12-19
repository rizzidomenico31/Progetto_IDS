import os

from flask.cli import load_dotenv

from app import mail
from flask_mail import Mail , Message

load_dotenv()
# Define the list of recipients
recipients = ['gnlucaputignano@gmail.com']

# Create a Message object with subject, sender, and recipient list
msg = Message(subject='Progetto Ingegneria del Software!',
              sender= os.environ.get('MAIL_USERNAME'),
              recipients=recipients)  # Pass the list of recipients here

# Email body
msg.body = 'Foggia merda! - No reply mail inviata automaticamente'

# Send the email
mail.send(msg)