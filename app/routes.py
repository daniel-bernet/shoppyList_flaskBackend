# app/routes.py
from flask import current_app, jsonify, request
from flask_jwt_extended import create_access_token
from app import db
from app.models import User, ShoppingList
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import jwt_required, get_jwt_identity

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

# Token Validation Endpoint
@current_app.route('/validate-token', methods=['GET'])
@jwt_required()
def validate_token():
    return jsonify({'message': 'Token is valid'}), 200

# Endpoint to create a shopping list
@current_app.route('/shopping_lists', methods=['POST'])
@jwt_required()
def create_shopping_list():
    data = request.get_json()
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    if 'title' not in data:
        return jsonify({'message': 'Title is required'}), 400
    
    shopping_list = ShoppingList(title=data['title'], owner_id=user.id)
    db.session.add(shopping_list)
    db.session.commit()

    return jsonify({'message': 'Shopping list created successfully', 'shopping_list_id': str(shopping_list.id)}), 201

# Endpoint to delete a shopping list
@current_app.route('/shopping_lists/<list_id>', methods=['DELETE'])
@jwt_required()
def delete_shopping_list(list_id):
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    shopping_list = ShoppingList.query.filter_by(id=list_id, owner_id=user.id).first()

    if not shopping_list:
        return jsonify({'message': 'Shopping list not found or you do not have permission to delete it'}), 404

    db.session.delete(shopping_list)
    db.session.commit()

    return jsonify({'message': 'Shopping list deleted successfully'}), 200