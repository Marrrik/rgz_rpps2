from flask import Flask, redirect, url_for, render_template, Blueprint, request
from Db import db
from Db.models import users
from flask_login import LoginManager
from dotenv import load_dotenv
import os


app = Flask(__name__)

load_dotenv()  # Загрузка переменных из .env

app.secret_key = '123'

user_db = os.getenv('USER_DB', 'default_user')
host_ip = os.getenv('HOST_IP', '127.0.0.1')
host_port = os.getenv('HOST_PORT', '5432')
database_name = os.getenv('DATABASE_NAME', 'default_db')
password = os.getenv('PASSWORD', 'default_password')

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{user_db}:{password}@{host_ip}:{host_port}/{database_name}?client_encoding=UTF8'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    db.create_all()

login_manager = LoginManager()

login_manager.login_view = 'rgz.login6'
login_manager.init_app(app)

@login_manager.user_loader
def load_users(user_id):
    return users.query.get(int(user_id))

# Перемещенный импорт
from rgz import rgz

app.register_blueprint(rgz)

if __name__ == '__main__':
    app.run(debug=True)





