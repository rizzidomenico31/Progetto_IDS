from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from app import db

class User(UserMixin , db.Model):
    __tablename__ = 'utenti'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255) , nullable=False)
    email = db.Column(db.String(255) , nullable=True)

