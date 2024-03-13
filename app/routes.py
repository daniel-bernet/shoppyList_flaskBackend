from datetime import datetime
from flask import current_app, jsonify, request
from flask_jwt_extended import create_access_token
from app import db
from app.models import User, ShoppingList, Product, shopping_list_collaborators
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["500 per day", "50 per hour"]
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
    refresh_token = create_refresh_token(identity=email)
    
    return jsonify({
        'message': 'Registration successful',
        'access_token': access_token,
        'refresh_token': refresh_token
    }), 201

# User Login Endpoint
@current_app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    print("Login endpoint hit")
    data = request.get_json()
    user = User.query.filter_by(email=data.get('email')).first()

    if user is None or not user.check_password(data.get('password')):
        return jsonify({'message': 'Invalid email or password'}), 401

    access_token = create_access_token(identity=user.email)
    refresh_token = create_refresh_token(identity=user.email)
    
    return jsonify({
        'message': 'Login successful',
        'access_token': access_token,
        'refresh_token': refresh_token
        }), 200

# Token Validation Endpoint
@current_app.route('/validate-token', methods=['GET'])
@jwt_required()
def validate_token():
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()
    
    if user:
        user.last_login = datetime.utcnow()
        db.session.commit()
        return jsonify({'message': 'Token is valid'}), 200
    else:
        return jsonify({'message': 'User not found'}), 404

# Endpoint refresh access-JWT
@current_app.route('/token/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify({'access_token': new_access_token}), 200

# Enpoint for password change
@current_app.route('/change_password', methods=['POST'])
@jwt_required()
def change_password():
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')

    if not user.check_password(current_password):
        return jsonify({'message': 'Invalid current password'}), 401

    if current_password == new_password:
        return jsonify({'message': 'New password cannot be the same as the current password'}), 400

    user.set_password(new_password)
    db.session.commit()

    return jsonify({'message': 'Password changed successfully'}), 200

# Endpoint to edit username
@current_app.route('/edit_username', methods=['POST'])
@jwt_required()
def edit_username():
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    data = request.get_json()
    new_username = data.get('new_username')
    current_password = data.get('current_password')

    if not user.check_password(current_password):
        return jsonify({'message': 'Invalid password'}), 401

    if User.query.filter_by(username=new_username).first():
        return jsonify({'message': 'Username already exists'}), 400

    user.username = new_username
    db.session.commit()

    return jsonify({'message': 'Username updated successfully'}), 200

# Endpoint to edit email
@current_app.route('/edit_email', methods=['POST'])
@jwt_required()
def edit_email():
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    data = request.get_json()
    new_email = data.get('new_email')
    current_password = data.get('current_password')

    if not user.check_password(current_password):
        return jsonify({'message': 'Invalid password'}), 401

    if User.query.filter_by(email=new_email).first():
        return jsonify({'message': 'Email already exists'}), 400

    user.email = new_email
    db.session.commit()

    return jsonify({'message': 'Email updated successfully'}), 200

# Enpoint for account deletion
@current_app.route('/delete_account', methods=['DELETE'])
@jwt_required()
def delete_account():
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    Product.query.filter_by(creator_id=user.id).delete()

    ShoppingList.query.filter_by(owner_id=user.id).delete()

    collaborator_lists = ShoppingList.query.join(shopping_list_collaborators, (ShoppingList.id == shopping_list_collaborators.c.shopping_list_id)).filter(shopping_list_collaborators.c.account_id == user.id).all()
    for shopping_list in collaborator_lists:
        shopping_list.collaborators.remove(user)

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message': 'Account deleted successfully'}), 200

# Endpoint to get user account information
@current_app.route('/account', methods=['GET'])
@jwt_required()
def get_account_info():
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    account_info = {
        'account_id': str(user.id),
        'username': user.username,
        'email': user.email,
        'registered_on': user.registered_on.strftime('%Y-%m-%d %H:%M:%S')
    }

    return jsonify(account_info), 200

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

    shopping_list = ShoppingList.query.filter_by(id=list_id).first()
    if not shopping_list or (shopping_list.owner_id != user.id and user not in shopping_list.collaborators):
        return jsonify({'message': 'Shopping list not found or you do not have permission to delete it'}), 403

    Product.query.filter_by(shopping_list_id=shopping_list.id).delete()

    shopping_list.collaborators = []
    
    db.session.delete(shopping_list)
    db.session.commit()

    return jsonify({'message': 'Shopping list deleted successfully'}), 200

# Endpoint to add a collaborator to a shopping list
@current_app.route('/shopping_lists/<list_id>/collaborators', methods=['POST'])
@jwt_required()
def add_collaborator(list_id):
    user_email = get_jwt_identity()
    owner = User.query.filter_by(email=user_email).first()
    shopping_list = ShoppingList.query.filter_by(id=list_id, owner_id=owner.id).first()

    if not shopping_list:
        return jsonify({'message': 'Shopping list not found'}), 404

    data = request.get_json()
    collaborator_email = data.get('email')
    collaborator = User.query.filter_by(email=collaborator_email).first()

    if not collaborator:
        return jsonify({'message': 'User not found'}), 404

    shopping_list.updated_at = datetime.utcnow()
    shopping_list.collaborators.append(collaborator)

    db.session.commit()

    return jsonify({'message': 'Collaborator added successfully'}), 200

# Endpoint to remove a collaborator from a shopping list
@current_app.route('/shopping_lists/<list_id>/collaborators/<collaborator_username>', methods=['DELETE'])
@jwt_required()
def remove_collaborator(list_id, collaborator_username):
    user_email = get_jwt_identity()
    owner = User.query.filter_by(email=user_email).first()
    shopping_list = ShoppingList.query.filter_by(id=list_id, owner_id=owner.id).first()

    if not shopping_list:
        return jsonify({'message': 'Shopping list not found'}), 404

    collaborator = User.query.filter_by(username=collaborator_username).first()

    if not collaborator or collaborator not in shopping_list.collaborators:
        return jsonify({'message': 'Collaborator not found'}), 404

    Product.query.filter_by(shopping_list_id=list_id, creator_id=collaborator.id).delete()

    shopping_list.updated_at = datetime.utcnow()
    shopping_list.collaborators.remove(collaborator)

    db.session.commit()

    return jsonify({'message': 'Collaborator and their products removed successfully'}), 200

# Enpoint to get all owned and collaborating lists
@current_app.route('/shopping_lists', methods=['GET'])
@jwt_required()
def get_all_lists():
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    owned_lists = user.owned_shopping_lists.all()
    collaborating_lists = user.collaborating_shopping_lists.all()
    all_lists = owned_lists + collaborating_lists

    lists_data = [{
        'id': shop_list.id,
        'title': shop_list.title,
        'created_at': shop_list.created_at.isoformat(),
        'updated_at': shop_list.updated_at.isoformat(),
        'owner': shop_list.owner.username, 
        'collaborators': [collaborator.username for collaborator in shop_list.collaborators],
        'is_owner': shop_list.owner_id == user.id
    } for shop_list in all_lists]

    return jsonify(lists_data), 200

# Endpoint to leave a shopping list as a collaborator
@current_app.route('/shopping_lists/<list_id>/leave', methods=['POST'])
@jwt_required()
def leave_list(list_id):
    user_email = get_jwt_identity()
    collaborator = User.query.filter_by(email=user_email).first()
    shopping_list = ShoppingList.query.filter_by(id=list_id).first()

    if not shopping_list:
        return jsonify({'message': 'Shopping list not found'}), 404

    if collaborator not in shopping_list.collaborators:
        return jsonify({'message': 'You are not a collaborator of this list'}), 403

    Product.query.filter_by(shopping_list_id=list_id, creator_id=collaborator.id).delete()
    
    shopping_list.updated_at = datetime.utcnow()
    shopping_list.collaborators.remove(collaborator)
    
    db.session.commit()

    return jsonify({'message': 'You have successfully left the list and your products have been removed'}), 200

# Endpoint to add a product to a shopping list
@current_app.route('/shopping_lists/<list_id>/products', methods=['POST'])
@jwt_required()
def add_product(list_id):
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    shopping_list = ShoppingList.query.filter_by(id=list_id).first()

    if not shopping_list or (user != shopping_list.owner and user not in shopping_list.collaborators):
        return jsonify({'message': 'Shopping list not found or access denied'}), 403

    data = request.get_json()
    if not all(key in data for key in ['name', 'quantity', 'unit_of_measurement']):
        return jsonify({'message': 'Missing product data (name, quantity, unit_of_measurement required)'}), 400

    product = Product(
        name=data['name'],
        quantity=data['quantity'],
        unit_of_measurement=data['unit_of_measurement'],
        creator_id=user.id,
        shopping_list_id=shopping_list.id
    )

    db.session.add(product)
    db.session.commit()

    return jsonify({'message': 'Product added successfully', 'product_id': str(product.id)}), 201

# Endpoint to get products of a shopping list
@current_app.route('/shopping_lists/<list_id>/products', methods=['GET'])
@jwt_required()
def get_products(list_id):
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    shopping_list = ShoppingList.query.filter_by(id=list_id).first()

    if not shopping_list or (user != shopping_list.owner and user not in shopping_list.collaborators):
        return jsonify({'message': 'Shopping list not found or access denied'}), 403

    products = Product.query.filter_by(shopping_list_id=shopping_list.id).all()

    product_details = [{
        'id': product.id,
        'name': product.name,
        'quantity': product.quantity,
        'unit_of_measurement': product.unit_of_measurement,
        'creator': product.creator.username,
        'created_at': product.created_at.isoformat(),
        'updated_at': product.updated_at.isoformat()
    } for product in products]

    return jsonify(product_details), 200

# Endpoint to delete a product from a shopping list
@current_app.route('/shopping_lists/<list_id>/products/<product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(list_id, product_id):
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    shopping_list = ShoppingList.query.filter_by(id=list_id).first()
    product = Product.query.filter_by(id=product_id, shopping_list_id=list_id).first()

    if not shopping_list or not product:
        return jsonify({'message': 'Shopping list or product not found'}), 404
    if user != shopping_list.owner and user not in shopping_list.collaborators:
        return jsonify({'message': 'Access denied'}), 403

    db.session.delete(product)
    db.session.commit()

    return jsonify({'message': 'Product deleted successfully'}), 200

# Endpoint to update a product's details in a shopping list
@current_app.route('/shopping_lists/<list_id>/products/<product_id>', methods=['PUT'])
@jwt_required()
def update_product(list_id, product_id):
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    shopping_list = ShoppingList.query.filter_by(id=list_id).first()
    product = Product.query.filter_by(id=product_id, shopping_list_id=list_id).first()

    if not shopping_list or not product:
        return jsonify({'message': 'Shopping list or product not found'}), 404
    if user != shopping_list.owner and user not in shopping_list.collaborators:
        return jsonify({'message': 'Access denied'}), 403

    data = request.get_json()
    product.name = data.get('name', product.name)
    product.quantity = data.get('quantity', product.quantity)
    product.unit_of_measurement = data.get('unit_of_measurement', product.unit_of_measurement)
    product.creator_id = user.id
    product.updated_at = datetime.utcnow()

    db.session.commit()

    return jsonify({
        'message': 'Product details updated successfully',
        'product': {
            'id': product.id,
            'name': product.name,
            'quantity': product.quantity,
            'unit_of_measurement': product.unit_of_measurement,
            'creator': product.creator.username,
            'created_at': product.created_at.isoformat(),
            'updated_at': product.updated_at.isoformat(),
        }
    }), 200

# Endpoint to delete multiple products from a shopping list
@current_app.route('/shopping_lists/<list_id>/products/batch_delete', methods=['POST'])
@jwt_required()
def delete_multiple_products(list_id):
    user_email = get_jwt_identity()
    user = User.query.filter_by(email=user_email).first()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    shopping_list = ShoppingList.query.filter_by(id=list_id).first()

    if not shopping_list:
        return jsonify({'message': 'Shopping list not found'}), 404
    if user != shopping_list.owner and user not in shopping_list.collaborators:
        return jsonify({'message': 'Access denied'}), 403

    data = request.get_json()
    product_ids = data.get('product_ids', [])

    if not product_ids:
        return jsonify({'message': 'No product IDs provided'}), 400

    for product_id in product_ids:
        product = Product.query.filter_by(id=product_id, shopping_list_id=list_id).first()
        if product:
            db.session.delete(product)

    db.session.commit()
    return jsonify({'message': 'Products deleted successfully'}), 200
