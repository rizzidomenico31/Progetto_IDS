from flask import Flask
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)


@app.route('/')
def hello_world():  # put application's code here
    return 'Ciao Mondo!'


if __name__ == '__main__':
    app.run()
