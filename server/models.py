from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin
from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    _password_hash = db.Column(db.String(255))
    image_url = db.Column(db.String(255))
    bio = db.Column(db.String(500))
    
    recipes = db.relationship(
        "Recipe", 
        back_populates="user", 
        cascade="all, delete-orphan"
    )
    
    # Validation for username
    @validates('username')
    def validate_username(self, key, username):
        if not username:
            raise ValueError("Username is required")
        return username

    @hybrid_property
    def password_hash(self):
        raise AttributeError('Cannot access password_hash attribute directly')
    
    @password_hash.setter
    def password_hash(self, password):
        if not password:
            raise ValueError("Password is required")
        password_hash = bcrypt.generate_password_hash(password.encode('UTF-8'))
        self._password_hash = password_hash.decode('UTF-8')
    
    def authenticate(self, password):
        return bcrypt.check_password_hash(self._password_hash, password.encode('utf-8'))
    
    def __repr__(self):
        return f"<User {self.id}: Username : {self.username}, Bio: {self.bio}"

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    instructions = db.Column(db.String(2000))
    minutes_to_complete = db.Column(db.Integer)
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship("User", back_populates="recipes")
    
    # Validation for title
    @validates('title')
    def validate_title(self, key, title):
        if not title:
            raise ValueError("Title is required")
        return title
    
    # Validation for instructions
    @validates('instructions')
    def validate_instructions(self, key, instructions):
        if not instructions or len(instructions) < 50:
            raise ValueError("Instructions must be more than 50 characters")
        return instructions