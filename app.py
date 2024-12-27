from flask import Flask, redirect, url_for, render_template, request, session, flash, Blueprint, abort
from flask_login import LoginManager, login_user, login_required, current_user, logout_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

from Db import db
from Db.models import users, Articles, Comment


app = Flask(__name__)

load_dotenv()

app.secret_key = os.getenv("APP_SECRET_KEY", "default_secret_key")
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
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_users(user_id):
    return users.query.get(int(user_id))

limiter = Limiter(get_remote_address, app=app)

blocked_users = {}
blocked_ips = {}
MAX_ATTEMPTS = 5
USER_BLOCK_TIME = timedelta(minutes=5)
IP_BLOCK_TIME = timedelta(minutes=15)

@app.route('/')
def redir():
    return redirect('/rgz/glav')

@app.route('/rgz/glav')
def rgz_glav():
    username_form = session.get('username')
    return render_template('glav6.html', username=username_form)

@app.route('/rgz/register', methods=['GET', 'POST'])
def register():
    errors = []
    if request.method == 'GET':
        return render_template('register6.html')
    
    username_form = request.form.get('username')
    password_form = request.form.get('password')

    if users.query.filter_by(username=username_form).first():
        errors.append("Пользователь уже существует")
        return render_template('register6.html', errors=errors)   

    if not username_form or not password_form:
        errors.append("Пожалуйста заполните все поля")
        return render_template('register6.html', errors=errors)
    
    if len(password_form) < 5:
        errors.append("Пароль должен содержать не менее 5 символов")
        return render_template('register6.html', errors=errors)
        
    hashPassword = generate_password_hash(password_form, method='pbkdf2')
    newUser = users(username=username_form, password=hashPassword)

    db.session.add(newUser)
    db.session.commit()

    return redirect('/rgz/login')


@app.route('/rgz/login', methods=["GET", "POST"])
def login6():
    errors = []
    client_ip = request.remote_addr

    if client_ip in blocked_ips:
        blocked_until = blocked_ips[client_ip]
        if datetime.utcnow() < blocked_until:
            remaining_time = blocked_until - datetime.utcnow()
            minutes, seconds = divmod(remaining_time.seconds, 60)
            flash(f"Ваш IP заблокирован. Попробуйте снова через {minutes} минут {seconds} секунд.", "danger")
            return render_template("login6.html"), 429
        else:
            del blocked_ips[client_ip]

    if request.method == "GET":
        return render_template("login6.html")

    username_form = request.form.get("username")
    password_form = request.form.get("password")

    if not username_form or not password_form:
        errors.append("Пожалуйста, заполните все поля")
        return render_template("login6.html", errors=errors)

    if username_form in blocked_users:
        blocked_until = blocked_users[username_form]
        if datetime.utcnow() < blocked_until:
            remaining_time = blocked_until - datetime.utcnow()
            minutes, seconds = divmod(remaining_time.seconds, 60)
            flash(f"Ваш аккаунт заблокирован. Попробуйте снова через {minutes} минут {seconds} секунд.", "danger")
            return render_template("login6.html"), 429
        else:
            del blocked_users[username_form]

    my_user = users.query.filter_by(username=username_form).first()
    if my_user and check_password_hash(my_user.password, password_form):
        login_user(my_user)
        flash("Успешный вход", "success")
        return redirect("/rgz/glav")
    else:
        errors.append("Неверное имя пользователя или пароль")
        session['attempts'] = session.get('attempts', 0) + 1
        if session['attempts'] >= MAX_ATTEMPTS:
            blocked_users[username_form] = datetime.utcnow() + USER_BLOCK_TIME
            blocked_ips[client_ip] = datetime.utcnow() + IP_BLOCK_TIME
            session.pop('attempts', None)
            flash(f"Вы превысили лимит попыток. Ваш аккаунт заблокирован на {USER_BLOCK_TIME.seconds // 60} минут.", "danger")

    return render_template("login6.html", errors=errors)


@app.route("/rgz/artic", methods=['GET'])
def art():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    articles = Articles.query.paginate(page=page, per_page=per_page, error_out=False)
    usernames = [users.query.get(articl.user_id).username for articl in articles.items]
    return render_template("articles6.html", articles=articles, usernames=usernames, users=users)


@app.route("/rgz/newarticle", methods=["GET", "POST"])
@login_required
def createArticle():
    if request.method == "GET":
        return render_template("newarticle6.html")

    text = request.form.get("text")
    title = request.form.get("title")

    if not text:
        errors = ["Заполните текст"]
        return render_template("newarticle6.html", errors=errors)

    new_articl = Articles(user_id=current_user.id, title=title, article_text=text)
    db.session.add(new_articl)
    db.session.commit()
    return redirect("/rgz/artic")

@app.route("/rgz/articles/<int:article_id>", methods=['POST'])
@login_required
def editArticle(article_id):
    if request.form.get("_method") == "PUT":
        article = Articles.query.get(article_id)
        if not article:
            return {"error": "Статья не найдена"}, 404

        if article.user_id != current_user.id:
            return {"error": "Вы не можете редактировать эту статью"}, 403

        title = request.form.get("title")
        text = request.form.get("text")

        if not title or not text:
            return {"error": "Заголовок и текст обязательны"}, 400

        article.title = title
        article.article_text = text
        db.session.commit()
        return redirect("/rgz/artic")
    
    return {"error": "Неверный метод"}, 405

@app.route("/rgz/comments", methods=["POST"])
@login_required
def addComment():
    article_id = request.form.get("article_id")
    text = request.form.get("text")

    if not article_id or not text:
        flash("ID статьи и текст комментария обязательны", "danger")
        return redirect(url_for('art'))

    article = Articles.query.get(article_id)
    if not article:
        flash("Статья не найдена", "danger")
        return redirect(url_for('art'))

    comment = Comment(user_id=current_user.id, article_id=article_id, text=text)
    db.session.add(comment)
    db.session.commit()
    flash("Комментарий успешно добавлен", "success")

    return redirect(url_for('getArticle', article_id=article_id))

@app.route("/rgz/articles/<int:article_id>", methods=['GET', 'POST'])
def getArticle(article_id):
    article = Articles.query.get(article_id)

    if not article:
        abort(404, description="Статья не найдена")

    if not current_user.is_authenticated or (
        article.user_id != current_user.id and not article.is_public
    ):
        abort(403, description="У вас нет доступа к этой статье")

    return render_template(
        "6articles.html",
        article=article,
        title=article.title,
        title_text=article.article_text,
    )


@app.route("/rgz/articles/<int:article_id>/delete", methods=['POST'])
@login_required
def deleteArticle(article_id):
    if request.form.get('_method') == 'DELETE':
        selected_articles = Articles.query.get(article_id)

        if not selected_articles:
            return "Статья не найдена", 404

        if selected_articles.user_id != current_user.id:
            return "Вы не можете удалить эту статью", 403

        db.session.delete(selected_articles)
        db.session.commit()
        return redirect(url_for('art'))

    return "Неверный метод", 405



@app.route("/rgz/logout", methods=["POST", "GET"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("redir"))

if __name__ == '__main__':
    app.run()