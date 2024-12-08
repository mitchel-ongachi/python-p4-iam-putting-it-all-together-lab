#!/usr/bin/env python3
from flask import request, session, make_response
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json() if request.is_json else request.form
        
        # Validate required fields
        if not all(key in data for key in ["username", "password"]):
            return {"error": "Missing required fields"}, 422
        
        try:
            # Create new user
            user = User(
                username=data["username"],
                # Optional fields with default values
                image_url=data.get("image_url", ""),
                bio=data.get("bio", "")
            )
            # Set password hash
            user.password_hash = data["password"]
            
            # Add and commit to database
            db.session.add(user)
            db.session.commit()
            
            # Set session
            session["user_id"] = user.id
            
            # Return user data
            return make_response(user.to_dict(), 201)
        
        except IntegrityError:
            # Handle duplicate username
            db.session.rollback()
            return {"error": "Username already exists"}, 422
        
        except Exception as e:
            # Catch any other unexpected errors
            db.session.rollback()
            print(f"Signup Error: {e}")
            return {"error": "An unexpected error occurred"}, 500

class CheckSession(Resource):
    def get(self):
        # Safely get user_id from session
        user_id = session.get('user_id')
        
        # No user in session
        if not user_id:
            return make_response({"error": "Unauthorized"}, 401)
        
        try:
            # Find user
            user = User.query.get(user_id)
            
            # No user found
            if not user:
                return make_response({"error": "User not found"}, 401)
            
            # Return user data
            
            return make_response(user.to_dict(rules=('-_password_hash', '-recipes')), 200)
        
        except Exception as e:
            print(f"CheckSession Error: {e}")
            return make_response({"error": "An unexpected error occurred"}, 500)

class Login(Resource):
    def post(self):
        data = request.get_json() if request.is_json else request.form
        
        # Validate required fields
        if not all(key in data for key in ["username", "password"]):
            return {"error": "Missing required fields"}, 422
        
        # Find user
        user = User.query.filter_by(username=data["username"]).first()
        
        # Authenticate user
        if user and user.authenticate(data["password"]):
            # Set session
            session["user_id"] = user.id
            return make_response(user.to_dict(), 200)
        else:
            return make_response({"error": "Invalid credentials"}, 401)

class Logout(Resource):
    def delete(self):
        # Check if user_id exists in session
        if session.get("user_id") is None:
            return make_response({"error": "Unauthorized"}, 401)
        
        # Remove user from session
        session.pop("user_id", None)
        return make_response({}, 204)

class RecipeIndex(Resource):
    def get(self):
        # Ensure user is logged in
        user_id = session.get('user_id')
        if not user_id:
            return make_response({"error": "Unauthorized"}, 401)
        
        # Get all recipes
        recipes = Recipe.query.all()
        return make_response([recipe.to_dict() for recipe in recipes], 200)

    def post(self):
        # Ensure user is logged in
        user_id = session.get('user_id')
        if not user_id:
            return make_response({"error": "Unauthorized"}, 401)
        
        data = request.get_json() if request.is_json else request.form
        
        # Validate recipe data
        if not all(key in data for key in ["title", "instructions", "minutes_to_complete"]):
            return {"error": "Invalid recipe data"}, 422
        
        try:
            # Create new recipe
            recipe = Recipe(
                title=data["title"],
                instructions=data["instructions"],
                minutes_to_complete=data["minutes_to_complete"],
                user_id=user_id,
            )
            
            # Add and commit to database
            db.session.add(recipe)
            db.session.commit()
            
            return make_response(recipe.to_dict(), 201)
        
        except Exception as e:
            # Handle any errors
            db.session.rollback()
            print(f"Recipe Creation Error: {e}")
            return {"error": "An unexpected error occurred"}, 500

# Add resources to API
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)