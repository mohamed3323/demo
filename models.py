from flask_sqlalchemy import SQLAlchemy
import bcrypt

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

def init_db():
    db.drop_all()
    db.create_all()
    
    users = [
        ('john_doe', 'john.doe@example.com', 'John', 'Doe', 'password123', False),
        ('alice', 'alice@example.com', 'Alice', 'Smith', 'alicepass', False),
        ('mohamed wafiq', 'mohamed.wafiq@example.com', 'Mohamed', 'Wafiq', '123321@', True)
    ]
    
    for username, email, first_name, last_name, password, is_admin in users:
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = User(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            password_hash=hashed.decode('utf-8'),
            is_admin=is_admin
        )
        db.session.add(user)
    
    db.session.commit()