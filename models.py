from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(20), default='user')
    is_deleted = db.Column(db.Boolean, default=False)

    def is_admin(self):
        return self.role == 'admin'

class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(20), default="Medium")
    status = db.Column(db.String(20), default="Open")
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='tickets')
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    is_deleted = db.Column(db.Boolean, default=False)