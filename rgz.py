from flask import Flask, Blueprint, redirect, url_for, render_template, flash,request, session
from flask_login import login_user, login_required, current_user, logout_user

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded

from Db import db
from Db.models import users, initiative, Comment, Vote

from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta

app = Flask(__name__)

limiter = Limiter(
    get_remote_address,
    app=app
)

rgz = Blueprint('rgz', __name__)

blocked_users = {}
blocked_ips = {}

MAX_ATTEMPTS = 5
USER_BLOCK_TIME = timedelta(minutes=5)
IP_BLOCK_TIME = timedelta(minutes=15)

@rgz.route('/')
def redir():
    return redirect('/rgz/glav')


@rgz.route('/rgz/glav') # Защёл оглядеться 
def rgz_glav():
    username_form = session.get('username')
    return render_template('glav6.html', username = username_form)


@rgz.route('/rgz/register', methods = ['GET', 'POST']) # Зарегался
def register():
    errors = []
    if request.method == 'GET':
        return render_template('register6.html')
    
    username_form = request.form.get('username')
    password_form = request.form.get('password')

    isUserExist = users.query.filter_by(username=username_form).first()
    if isUserExist is not None:
        errors.append("Пользователь уже существует")
        return render_template('register6.html', errors=errors)   

    if not (username_form or password_form):
        errors.append("Пожалуйста заполните все поля")
        print(errors)
        return render_template('register6.html', errors=errors)
    if username_form == '':
        errors.append("Пожалуйста заполните все поля")
        print(errors)
        return render_template('register6.html', errors=errors)
    if not password_form.strip():
        errors.append("Пожалуйста заполните все поля")
        print(errors)
        return render_template('register6.html', errors=errors)
    
    if len(password_form) < 5:
            errors.append("Пароль должен содержать не менее 5 символов")
            print(errors)
            return render_template('register6.html', errors=errors)
        
    
    hashPassword = generate_password_hash(password_form, method='pbkdf2')
    newUser = users(username=username_form, password=hashPassword)

    db.session.add(newUser)
    db.session.commit()

    return redirect('/rgz/login')


@rgz.route('/rgz/login', methods=["GET", "POST"])
def login6():
    try:
        errors = []
        client_ip = request.remote_addr

        # Проверяем блокировку по IP
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

        if not (username_form and password_form):
            errors.append("Пожалуйста, заполните все поля")
            return render_template("login6.html", errors=errors)

        # Проверяем блокировку пользователя
        if username_form in blocked_users:
            blocked_until = blocked_users[username_form]
            if datetime.utcnow() < blocked_until:
                remaining_time = blocked_until - datetime.utcnow()
                minutes, seconds = divmod(remaining_time.seconds, 60)
                flash(f"Ваш аккаунт заблокирован. Попробуйте снова через {minutes} минут {seconds} секунд.", "danger")
                return render_template("login6.html"), 429
            else:
                del blocked_users[username_form]

        # Проверяем пользователя в базе
        my_user = users.query.filter_by(username=username_form).first()
        if my_user and check_password_hash(my_user.password, password_form):
            login_user(my_user)
            flash("Успешный вход", "success")
            return redirect("/rgz/glav")
        else:
            errors.append("Неверное имя пользователя или пароль")

            # Отслеживаем попытки авторизации
            session['attempts'] = session.get('attempts', 0) + 1
            if session['attempts'] >= MAX_ATTEMPTS:
                blocked_users[username_form] = datetime.utcnow() + USER_BLOCK_TIME
                blocked_ips[client_ip] = datetime.utcnow() + IP_BLOCK_TIME
                session.pop('attempts', None)  # Сбрасываем счётчик
                flash(f"Вы превысили лимит попыток. Ваш аккаунт заблокирован на {USER_BLOCK_TIME.seconds // 60} минут.", "danger")

        return render_template("login6.html", errors=errors)

    except Exception as e:
        flash("Произошла ошибка. Попробуйте снова.", "danger")
        return render_template("login6.html"), 500


@rgz.route("/rgz/artic", methods=['GET'])
def art():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    initiatives = initiative.query.paginate(page=page, per_page=per_page, error_out=False)
    usernames = [users.query.get(initiative.user_id).username for initiative in initiatives.items]
    return render_template("articles6.html", initiatives=initiatives, usernames=usernames, users=users)


@rgz.route("/rgz/newarticle", methods=["GET", "POST"]) # Новая статья
@login_required
def createArticle():
    if request.method == "GET":
        return render_template("newarticle6.html")

    text = request.form.get("text")
    title = request.form.get("title")

    if text is None or len(text) == 0:
        errors = ["Заполните текст"]
        return render_template("newarticle6.html", errors=errors)

    new_initiative = initiative(user_id=current_user.id, title=title, article_text=text)
        

    db.session.add(new_initiative)
    db.session.commit()
    
    return redirect("/rgz/initiative")

@rgz.route("/rgz/articles/<int:article_id>", methods=['POST'])  # Редакция есть
@login_required
def editArticle(article_id):
    if request.form.get("_method") == "PUT":
        article = initiative.query.get(article_id)
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
        print('Ok')
        return redirect("/rgz/initiative")
    
    return {"error": "Неверный метод"}, 405



@rgz.route("/rgz/comments", methods=["POST"])   # Комменты есть
@login_required
def addComment():
    article_id = request.form.get("article_id")
    text = request.form.get("text")

    if not article_id or not text:
        flash("ID статьи и текст комментария обязательны", "danger")
        return redirect(url_for('rgz.art'))

    article = initiative.query.get(article_id)
    if not article:
        flash("Статья не найдена", "danger")
        return redirect(url_for('rgz.art'))

    comment = Comment(user_id=current_user.id, article_id=article_id, text=text)
    db.session.add(comment)
    db.session.commit()
    flash("Комментарий успешно добавлен", "success")

    return redirect(url_for('rgz.getArticle', article_id=article_id))


@rgz.route("/rgz/articles/<int:article_id>", methods=['GET', 'POST']) # Перенаправление на само стаью
def getArticle(article_id):
    selected_initiative = initiative.query.get(article_id)

    if not selected_initiative:
        return "Статья не найдена", 404

    if not current_user.is_authenticated or (
        selected_initiative.user_id != current_user.id and not selected_initiative.is_public
    ):
        return "У вас нет доступа к этой статье", 403

    return render_template(
        "6articles.html",
        initiative=selected_initiative,
        title=selected_initiative.title,
        title_text = selected_initiative.article_text,
        username=current_user.username
    )

@rgz.route("/rgz/initiative/<int:article_id>/delete", methods=['POST'])
@login_required
def deleteArticle(article_id):
    # Check if the request method is overridden to DELETE
    if request.form.get('_method') == 'DELETE':
        selected_initiative = initiative.query.get(article_id)

        if not selected_initiative:
            return "Статья не найдена", 404

        if selected_initiative.user_id != current_user.id:
            return "Вы не можете удалить эту статью", 403

        db.session.delete(selected_initiative)
        db.session.commit()
        return redirect(url_for('rgz.art')), 204

    return "Метод не разрешен", 405


@rgz.route('/rgz/initiative/<int:article_id>/vote', methods=['POST']) # Голосование
@login_required
def vote(article_id):
    vote_type = request.form.get('vote')
    article = initiative.query.get(article_id)  

    if not article:
        return "Статья не найдена", 404

    existing_vote = Vote.query.filter_by(user_id=current_user.id, article_id=article_id).first()

    if existing_vote:
        if existing_vote.vote_type == vote_type:
            return "Вы уже проголосовали таким образом", 400  

        existing_vote.vote_type = vote_type
    else:
        new_vote = Vote(user_id=current_user.id, article_id=article_id, vote_type=vote_type)
        db.session.add(new_vote)

    # Обновляем количество лайков/дизлайков на статье
    if vote_type == 'up':
        article.likes = article.likes + 1 if article.likes else 1
    elif vote_type == 'down':
        article.likes = article.likes - 1 if article.likes else -1

    
    if article.likes <= -10:
        db.session.delete(article)

    db.session.commit()  
    return redirect(url_for('rgz.art'))  


@rgz.route('/rgz/logout')
@login_required
def logout():
    logout_user()
    return redirect('/rgz/glav')
    

   