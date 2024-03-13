from datetime import timedelta
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
jwt = JWTManager()
limiter = Limiter(key_func=get_remote_address)

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:my_shop_database@192.168.100.88:5432/shop_list'
    app.config['SECRET_KEY'] = '0872c39786gtm0a87gt0wmv*ç%&/(37ga087g46WVC623ANB'
    app.config['JWT_SECRET_KEY'] = '80CMAGQ02387G,0A7WXG67GC0WG*ç%&/()VG70CMG70'
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(weeks=25)

    db.init_app(app)
    jwt.init_app(app)
    limiter.init_app(app)

    with app.app_context():
        from app import routes, models

        db.create_all()

    return app
