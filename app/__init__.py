from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from app import auth

auth.register_jwt_routes()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:project_home_me@192.168.100.88:5432/postres'
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)

from app import routes
