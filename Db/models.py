from . import db
from flask_login import UserMixin
import datetime
from sqlalchemy.sql import func


class users(db.Model, UserMixin):

    __tablename__ = 'users'


    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(300), nullable=False)

    def __repr__(self):
        return f'id:{self.id}, username:{self.username}'
    

class initiative(db.Model):

    __tablename__ = 'initiative'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(50), nullable=False)
    article_text = db.Column(db.Text, nullable=False)
    is_favorite = db.Column(db.Boolean)
    is_public = db.Column(db.Boolean)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    likes = db.Column(db.Integer)

    # Устанавливаем связь с таблицей users
    user = db.relationship('users', backref=db.backref('initiatives', lazy=True))

    def __repr__(self):
        return f'id:{self.id}, title:{self.title}'


class Comment(db.Model):
    __tablename__ = 'comments'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    article_id = db.Column(db.Integer, db.ForeignKey('initiative.id', ondelete='CASCADE'), nullable=False)
    text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=func.now())
    user = db.relationship('users', backref='comments', lazy=True)
    article = db.relationship('initiative', backref=db.backref('comments', cascade='all, delete-orphan', lazy=True))


class Vote(db.Model):
    __tablename__ = 'votes'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    article_id = db.Column(db.Integer, db.ForeignKey('initiative.id', ondelete='CASCADE'), nullable=False)
    vote_type = db.Column(db.String(10), nullable=False)  # 'up' или 'down'

    user = db.relationship('users', backref='votes')
    article = db.relationship('initiative', backref=db.backref('votes', cascade='all, delete-orphan', lazy=True))

