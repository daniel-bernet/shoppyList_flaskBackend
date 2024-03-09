from flask import jsonify, request
from flask_jwt_extended import JWTManager, create_access_token, get_jwt_identity, jwt_required
from werkzeug.security import check_password_hash

from app import app, db
from app.models import User

app.config['JWT_SECRET_KEY'] = 'super-secret-jwt-key'  # change this key!!!!!!!!!!!
jwt = JWTManager(app)

def authenticate_user(username, password):
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200

    return jsonify({"msg": "Invalid username or password"}), 401

def register_jwt_routes():
    @app.route('/login', methods=['POST'])
    def login():
        username = request.json.get('username', None)
        password = request.json.get('password', None)
        return authenticate_user(username, password)
