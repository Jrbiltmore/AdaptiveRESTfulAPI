from flask_sqlalchemy import SQLAlchemy
from enum import Enum
from flask_jwt_extended import create_access_token, create_refresh_token
import bcrypt
from datetime import timedelta

db = SQLAlchemy()

# User Role Enum
class UserRole(Enum):
    USER = 'user'
    ADMIN = 'admin'

# Create the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.Enum(UserRole), default=UserRole.USER, nullable=False)

    def __init__(self, username, password, role=UserRole.USER):
        self.username = username
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.role = role

    @staticmethod
    def hash_password(password):
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def verify_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))

    def to_json(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role.value
        }

    def create_access_token(self):
        return create_access_token(identity=self.username, expires_delta=timedelta(hours=1))

    def create_refresh_token(self):
        return create_refresh_token(identity=self.username)

    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()

    def has_role(self, role):
        return self.role == role

    @classmethod
    def get_all_users(cls):
        return cls.query.all()

    @staticmethod
    def serialize_users(users):
        return [user.to_json() for user in users]
