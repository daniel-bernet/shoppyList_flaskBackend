# app/routes.py
from flask import current_app, jsonify, request
from flask_jwt_extended import create_access_token
from app import db
from app.models import User
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# User Registration Endpoint
@current_app.route('/register', methods=['POST'])
@limiter.limit("10 per minute")
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if username is None or email is None or password is None:
        return jsonify({'message': 'Missing information'}), 400

    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        return jsonify({'message': 'Username or email already exists'}), 400

    user = User(username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    # Generate JWT token
    access_token = create_access_token(identity=email)

    return jsonify({
        'message': 'Registration successfully',
        'access_token': access_token
    }), 201

# User Login Endpoint
@current_app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data.get('email')).first()

    if user is None or not user.check_password(data.get('password')):
        return jsonify({'message': 'Invalid email or password'}), 401

    access_token = create_access_token(identity=user.email)
    return jsonify({
        'message': 'Login successful',
        'access_token': access_token
        }), 200