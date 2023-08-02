from flask import Flask, request, jsonify, make_response
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, jwt_refresh_token_required, create_refresh_token
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_compress import Compress
from flask_cors import CORS
from dotenv import load_dotenv
import bcrypt
import os
from marshmallow import Schema, fields, validate
from datetime import timedelta

app = Flask(__name__)

# Load environment variables from .env file
load_dotenv()

# Set up database (Replace 'your_db_uri' with your actual database URI)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI', 'your_db_uri')
db = SQLAlchemy(app)

# Set up JWT and authentication configurations
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your_secret_key_here')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
jwt = JWTManager(app)

# Set up rate limiting configurations
limiter = Limiter(app, key_func=get_remote_address)

# Set up response compression
Compress(app)

# Enable CORS
CORS(app)

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

# User Schema for Input Validation using Marshmallow
class UserSchema(Schema):
    username = fields.String(required=True, validate=validate.Length(min=3, max=80))
    password = fields.String(required=True, validate=validate.Length(min=6, max=200))

# User Registration endpoint
@app.route('/register', methods=['POST'])
def register():
    user_schema = UserSchema()
    data = user_schema.load(request.json)

    if User.query.filter_by(username=data['username']).first():
        return jsonify({"message": "Username already exists"}), 400

    new_user = User(data['username'], data['password'])
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

# User Login endpoint
@app.route('/login', methods=['POST'])
def login():
    user_schema = UserSchema()
    data = user_schema.load(request.json)

    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.checkpw(data['password'].encode('utf-8'), user.password.encode('utf-8')):
        access_token = create_access_token(identity=user.username)
        refresh_token = create_refresh_token(identity=user.username)
        return jsonify({"access_token": access_token, "refresh_token": refresh_token}), 200

    return jsonify({"message": "Invalid credentials"}), 401

# Token Refresh endpoint
@app.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    return jsonify({"access_token": access_token}), 200

# Protected endpoint that requires JWT
@app.route('/protected', methods=['GET'])
@jwt_required()
@limiter.limit("100 per day")  # Rate limit the endpoint to 100 requests per day
def protected():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Hello {current_user}, this is a protected endpoint."}), 200

# Get All Users endpoint with Pagination
@app.route('/users', methods=['GET'])
@jwt_required()
def get_all_users():
    current_user = get_jwt_identity()
    if not User.find_by_username(current_user).has_role(UserRole.ADMIN):
        return jsonify({"message": "Unauthorized to access this resource"}), 403

    page = request.args.get('page', default=1, type=int)
    per_page = request.args.get('per_page', default=10, type=int)

    if per_page > 100:
        per_page = 100

    users = User.query.paginate(page=page, per_page=per_page, error_out=False)
    serialized_users = User.serialize_users(users.items)

    return jsonify({
        "users": serialized_users,
        "total_users": users.total,
        "current_page": users.page,
        "per_page": users.per_page
    }), 200

# Get User Details endpoint
@app.route('/user/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user(user_id):
    current_user = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    if current_user != user.username and not user.has_role(UserRole.ADMIN):
        return jsonify({"message": "Unauthorized to access this resource"}), 403

    return jsonify(user.to_json()), 200

# Error handler for 404 Not Found
@app.errorhandler(404)
def not_found(error):
    return jsonify({"message": "Not Found"}), 404

# Error handler for 500 Internal Server Error
@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({"message": "Internal Server Error"}), 500

# Error handler for 400 Bad Request
@app.errorhandler(400)
def bad_request(error):
    return jsonify({"message": "Bad Request"}), 400

# Error handler for 401 Unauthorized
@app.errorhandler(401)
def unauthorized(error):
    return jsonify({"message": "Unauthorized"}), 401

# Error handler for 403 Forbidden
@app.errorhandler(403)
def forbidden(error):
    return jsonify({"message": "Forbidden"}), 403

# Error handler for 429 Too Many Requests
@app.errorhandler(429)
def too_many_requests(error):
    return jsonify({"message": "Too Many Requests"}), 429

if __name__ == '__main__':
    # Initialize the database
    db.create_all()

    app.run()
