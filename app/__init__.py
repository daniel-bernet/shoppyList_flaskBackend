from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from app import auth

auth.register_jwt_routes()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:REDACTED_DB_PASSWORD@DB_HOST:5432/postres'
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)

from app import routes
