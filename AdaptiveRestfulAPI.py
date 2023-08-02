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

# Create the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)

    def __init__(self, username, password):
        self.username = username
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# User Schema for Input Validation using Marshmallow
class UserSchema(Schema):
    username = fields.String(required=True)
    password = fields.String(required=True)

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

