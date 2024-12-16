from flask import Flask, request, session, jsonify
from flask_restful import Api, Resource
from models import db, User, Recipe
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)
app.secret_key = b'a\xdb\xd2\x13\x93\xc1\xe9\x97\xef2\xe3\x004U\xd1Z'
api = Api(app)

def validate_user_data(data):
    return all(key in data and data[key] for key in ['username', 'password'])

class Signup(Resource):
    def post(self):
        data = request.get_json()
        if not validate_user_data(data):
            return {"error": "Invalid input"}, 422

        try:
            user = User(
                username=data['username'],
                bio=data.get('bio', ''),
                image_url=data.get('image_url', '')
            )
            user.set_password(data['password'])
            db.session.add(user)
            db.session.commit()
            return user.to_dict(), 201

        except IntegrityError:
            db.session.rollback()
            return {"error": "Username already taken"}, 422

class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(username=data.get('username')).first()
        if user and user.authenticate(data.get('password')):
            session['user_id'] = user.id
            return user.to_dict(), 200
        return {"error": "Invalid username or password"}, 401

class Logout(Resource):
    def delete(self):
        if 'user_id' not in session:
            return {"error": "No active session"}, 401
        session.pop('user_id', None)
        return {}, 204

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {"error": "Unauthorized"}, 401
        user = db.session.get(User, user_id)
        if user:
            return user.to_dict(), 200
        return {"error": "User not found"}, 404

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {"error": "Unauthorized"}, 401

        user = db.session.get(User, user_id)
        if not user:
            return {"error": "User not found"}, 404

        return [recipe.to_dict() for recipe in user.recipes], 200

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {"error": "Unauthorized"}, 401

        data = request.get_json()
        if not data.get('title') or not data.get('instructions') or not isinstance(data.get('minutes_to_complete'), int):
            return {"error": "Invalid input"}, 422

        try:
            recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data['minutes_to_complete'],
                user_id=user_id
            )
            db.session.add(recipe)
            db.session.commit()
            return recipe.to_dict(), 201
        except IntegrityError:
            db.session.rollback()
            return {"error": "Could not process recipe"}, 422

api.add_resource(Signup, '/signup')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(CheckSession, '/check_session')
api.add_resource(RecipeIndex, '/recipes')

if __name__ == '__main__':
    from models import db
    db.init_app(app)
    with app.app_context():
        db.create_all()
    app.run(debug=True)
