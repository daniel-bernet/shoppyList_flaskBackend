from datetime import datetime
import uuid
from sqlalchemy.dialects.postgresql import UUID
from app import db
from werkzeug.security import generate_password_hash, check_password_hash

# Association table for the many-to-many relationship
shopping_list_collaborators = db.Table(
    'shopping_list_collaborators',
    db.Column('shopping_list_id', UUID(as_uuid=True), db.ForeignKey('shopping_list.id'), primary_key=True),
    db.Column('account_id', UUID(as_uuid=True), db.ForeignKey('account.id'), primary_key=True)
)

class User(db.Model):
    __tablename__ = 'account'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(512))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class ShoppingList(db.Model):
    __tablename__ = 'shopping_list'
    
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = db.Column(db.String(120), nullable=False)
    owner_id = db.Column(UUID(as_uuid=True), db.ForeignKey('account.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    owner = db.relationship('User', backref=db.backref('owned_shopping_lists', lazy='dynamic'))
    collaborators = db.relationship('User', secondary=shopping_list_collaborators,
                                    backref=db.backref('collaborating_shopping_lists', lazy='dynamic'))
