import os

from flask import Flask, request, session, g, abort, jsonify
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError
import jwt

# from forms import UserAddForm, UserEditForm, LoginForm, MessageForm
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

    if CURR_USER_KEY in session:
        g.user = User.query.get(session[CURR_USER_KEY])

    else:
        g.user = None


def do_login(user):
    """Log in user."""

    payload = {
        username: user.username
    }

    return jwt.sign(payload, SECRET_KEY)


def do_logout():
    """Logout user."""

    if CURR_USER_KEY in session:
        del session[CURR_USER_KEY]


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
            status_message = "username already taken"
            return jsonify(
                status=status_message
            )

        token = do_login(user)
        print('token is', token)
        print('user', user)
        user_to_send = {
            "username":user.username,
            "email":user.password,
            "first_name":user.first_name,
            "last_name":user.last_name,
            "image_url":user.image_url,
            "hobbies":user.hobbies,
            "interests":user.interests,
            "zip_code":user.zip_code,
            "friend_radius":user.friend_radius,
            }

        return jsonify(
            user=user_to_send,
            token=token
        )

    else:
        return jsonify(status="unable to add user")


@app.route('/login', methods=["GET", "POST"])
def login():
    """Handle user login."""

    form = LoginForm()

    if form.validate_on_submit():
        user = User.authenticate(form.username.data,
                                 form.password.data)

        if user:
            do_login(user)
            flash(f"Hello, {user.username}!", "success")
            return redirect("/")

        flash("Invalid credentials.", 'danger')

    return render_template('users/login.html', form=form)


@app.route('/logout')
def logout():
    """Handle logout of user."""

    do_logout()

    flash("You have successfully logged out.", 'success')
    return redirect("/login")

