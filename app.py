import os

from flask import Flask, request, session, g, abort, jsonify, make_response
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError
import jwt

from forms import UserAddForm, LoginForm
from models import db, connect_db, User, Like, Dislike

CURR_USER_KEY = "curr_user"

app = Flask(__name__)

# Get DB_URI from environ variable (useful for production/testing) or,
# if not set there, use development local db.
app.config['SQLALCHEMY_DATABASE_URI'] = (
    os.environ.get('DATABASE_URL', 'postgres:///friender'))

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = True
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', "it's a secret")
toolbar = DebugToolbarExtension(app)

connect_db(app)


##############################################################################
# User signup/login/logout


@app.before_request
def add_user_to_g():
    """If we're logged in, add curr user to Flask global."""

    if "token" in request.json:
        token = request.json["token"]
        payload = jwt.decode(token, app.config.get('SECRET_KEY'), algorithms=["HS256"])

        if "username" in payload:
            g.user = User.query.filter_by(username=payload["username"])

    else:
        g.user = None

    print('end of add_user_to_g, g.user=', g.user)


def do_login(user):
    """Log in user."""

    payload = {
        "username": user.username
    }

    return jwt.encode(payload, app.config.get('SECRET_KEY'))


@app.route('/signup', methods=["POST"])
def signup():
    """Handle user signup.

    Create new user and add to DB. Return JSON of new user.

    If the there already is a user with that username: return JSON
    with error message
    """
    if CURR_USER_KEY in session:
        del session[CURR_USER_KEY]

    received = request.json

    form = UserAddForm(csrf_enabled=False, data=received)

    if form.validate_on_submit():
        try:
            user = User.signup(
                username=form.username.data,
                password=form.password.data,
                email=form.email.data,
                first_name=form.first_name.data,
                last_name=form.last_name.data,
                image_url=form.image_url.data or User.image_url.default.arg,
                hobbies=form.hobbies.data,
                interests=form.interests.data,
                zip_code=form.zip_code.data,
                friend_radius=form.friend_radius.data,
            )
            db.session.commit()

        except IntegrityError as e:
            status_message = "username or email already taken"
            return jsonify(
                status=status_message
            )

        token = do_login(user)

        user_to_send = {
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "image_url": user.image_url,
            "hobbies": user.hobbies,
            "interests": user.interests,
            "zip_code": user.zip_code,
            "friend_radius": user.friend_radius,
            }

        return (jsonify(
            user=user_to_send,
            token=token
        ), 201)

    else:
        return (jsonify(status="unable to add user"), 400)


@app.route('/login', methods=["POST"])
def login():
    """Handle user login."""

    received = request.json
    form = LoginForm(csrf_enabled=False, data=received)

    if form.validate_on_submit():
        user = User.authenticate(form.username.data,
                                 form.password.data)

        if user:
            token = do_login(user)

            return (jsonify(
                    user=user.serialize(),
                    token=token), 201)
    
    return (jsonify(status="invalid credentials"), 400)


##############################################################################
# General user routes:

@app.route('/users/<int:user_id>')
def users_show(user_id):
    """Get a user info.
    Returns JSON: 
        {
        "user": {
            "email": "test1@test.com",
            "first_name": "test",
            "friend_radius": 5,
            "hobbies": "test",
            "image_url": "/static/images/default-pic.png",
            "interests": "test",
            "last_name": "test",
            "username": "test1",
            "zip_code": "11111"
            }
        }
    """

    if not g.user:
        (jsonify(status="invalid credentials"), 400)

    user = User.query.get_or_404(user_id)

    return jsonify(user=user.serialize())

@app.route('/users/<int:user_id>/potentials')
def get_potential_friends(user_id):
    """Get list of users where current user has not already liked/disliked them,
    and other user has not disliked them.
    Also filters by location.
    """

    if not g.user:
        (jsonify(status="invalid credentials"), 400)

    current_user = User.query.get_or_404(user_id)
    users = User.query.all()

    def filterUsers(user):
        return current_user.is_potential(user)

    user_options = list(filter(filterUsers, users))
    user_options_serialized = [ user.serialize() for user in user_options]

    return jsonify(user_options=user_options_serialized)