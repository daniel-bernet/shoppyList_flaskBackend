from flask import request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, db
from app.models import User
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from app import app

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# User Register Endpoint
@app.route('/register', methods=['POST'])
@limiter.limit("10 per minute")
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if username is None or email is None or password is None:
        return jsonify({'message': 'Missing information'}), 400

    if User.query.filter_by(username=username).first() is not None:
        return jsonify({'message': 'Username already exists'}), 400

    user = User(username=username, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

# User Login Endpoint
@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()

    if user is None or not user.check_password(data.get('password')):
        return jsonify({'message': 'Invalid username or password'}), 401

    # Here you should implement token generation and return it to the user
    # Placeholder response:
    return jsonify({'message': 'Login successful'}), 200

# Change Password Endpoint
@app.route('/change-password', methods=['POST'])
@limiter.limit("10 per minute")
def change_password():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()

    if user is None or not user.check_password(data.get('old_password')):
        return jsonify({'message': 'Invalid username or password'}), 401

    user.set_password(data.get('new_password'))
    db.session.commit()
    return jsonify({'message': 'Password updated successfully'}), 200

# Change Email Endpoint
@app.route('/change-email', methods=['POST'])
def change_email():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()

    if user is None:
        return jsonify({'message': 'Invalid username'}), 401

    user.email = data.get('new_email')
    db.session.commit()
    return jsonify({'message': 'Email updated successfully'}), 200

# Change Username Endpoint
@app.route('/change-username', methods=['POST'])
def change_username():
    data = request.get_json()
    existing_user = User.query.filter_by(username=data.get('new_username')).first()

    if existing_user:
        return jsonify({'message': 'Username already taken'}), 400

    user = User.query.filter_by(username=data.get('username')).first()

    if user is None:
        return jsonify({'message': 'Invalid username'}), 401

    user.username = data.get('new_username')
    db.session.commit()
    return jsonify({'message': 'Username updated successfully'}), 200
