"""SQLAlchemy models for Friender."""

from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

bcrypt = Bcrypt()
db = SQLAlchemy()


class Like(db.Model):
    """Connection of a user <-> liked_user."""

    __tablename__ = 'likes'

    liker_user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete="cascade"),
        primary_key=True,
    )

    liked_user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete="cascade"),
        primary_key=True,
    )

class Dislike(db.Model):
    """Connection of a user <-> disliked_user."""

    __tablename__ = 'dislikes'

    disliker_user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete="cascade"),
        primary_key=True,
    )

    disliked_user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id', ondelete="cascade"),
        primary_key=True,
    )


class User(db.Model):
    """User in the system."""

    __tablename__ = 'users'

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    email = db.Column(
        db.Text,
        nullable=False,
        unique=True,
    )

    username = db.Column(
        db.Text,
        nullable=False,
        unique=True,
    )

    first_name = db.Column(
        db.Text,
        nullable=False,
    )

    last_name = db.Column(
        db.Text,
        nullable=False,
    )

    image_url = db.Column(
        db.Text,
        default="/static/images/default-pic.png",
    )

    hobbies = db.Column(
        db.Text,
        nullable=False,
    )
    
    interests = db.Column(
        db.Text,
        nullable=False,
    )

    zip_code = db.Column(
        db.Text,
        nullable=False,
    )
    
    friend_radius = db.Column(
        db.Integer,
        nullable=False,
    )

    password = db.Column(
        db.Text,
        nullable=False,
    )

    likes = db.relationship(
        "User",
        secondary="likes",
        primaryjoin=(Like.liker_user_id == id),
        secondaryjoin=(Like.liked_user_id == id)
    )

    liked_by = db.relationship(
        "User",
        secondary="likes",
        primaryjoin=(Like.liked_user_id == id),
        secondaryjoin=(Like.liker_user_id == id)
    )

    dislikes = db.relationship(
        "User",
        secondary="dislikes",
        primaryjoin=(Dislike.disliker_user_id == id),
        secondaryjoin=(Dislike.disliked_user_id == id)
    )

    disliked_by = db.relationship(
        "User",
        secondary="dislikes",
        primaryjoin=(Dislike.disliked_user_id == id),
        secondaryjoin=(Dislike.disliker_user_id == id)
    )

    def __repr__(self):
        return f"<User #{self.id}: {self.username}, {self.email}>"

    def is_liked_by(self, other_user):
        """Is this user liked by `other_user`?"""

        found_user_list = [user for user in self.liked_by if user == other_user]
        return len(found_user_list) == 1

    def is_liking(self, other_user):
        """Is this user liking `other_user`?"""

        found_user_list = [user for user in self.likes if user == other_user]
        return len(found_user_list) == 1
    
    def is_disliked_by(self, other_user):
        """Is this user disliked by `other_user`?"""

        found_user_list = [user for user in self.disliked_by if user == other_user]
        return len(found_user_list) == 1

    def is_disliking(self, other_user):
        """Is this user disliking `other_user`?"""

        found_user_list = [user for user in self.dislikes if user == other_user]
        return len(found_user_list) == 1

    @classmethod
    def signup(cls, username, email, password, first_name, last_name, image_url, hobbies, interests, zip_code, friend_radius):
        """Sign up user.

        Hashes password and adds user to system.
        """

        hashed_pwd = bcrypt.generate_password_hash(password).decode('UTF-8')

        user = User(
            username=username,
            email=email,
            password=hashed_pwd,
            first_name=first_name,
            last_name=last_name,
            image_url=image_url,
            hobbies=hobbies,
            interests=interests,
            zip_code=zip_code,
            friend_radius=friend_radius,
        )

        db.session.add(user)
        return user

    @classmethod
    def authenticate(cls, username, password):
        """Find user with `username` and `password`.

        This is a class method (call it on the class, not an individual user.)
        It searches for a user whose password hash matches this password
        and, if it finds such a user, returns that user object.

        If can't find matching user (or if password is wrong), returns False.
        """

        user = cls.query.filter_by(username=username).first()

        if user:
            is_auth = bcrypt.check_password_hash(user.password, password)
            if is_auth:
                return user

        return False

def connect_db(app):
    """Connect this database to provided Flask app.

    You should call this in your Flask app.
    """

    db.app = app
    db.init_app(app)


