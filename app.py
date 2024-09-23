import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from dotenv import load_dotenv
import json

load_dotenv()

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# DATABASE_URL 처리
uri = os.getenv("DATABASE_URL")
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

logger.info(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    expiry_date = db.Column(db.DateTime, nullable=False)

@app.route('/favicon.png')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),'favicon.png', mimetype='image/png')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            if user.expiry_date < datetime.utcnow():
                flash('계정이 만료되었습니다. 관리자에게 문의하세요.', 'error')
                return redirect('https://edmakers-0804e31d8eb9.herokuapp.com/login')
            login_user(user)
            return redirect('https://edmakers-gpt.streamlit.app/')
        flash('ID 혹은 비밀번호가 잘못되었습니다.', 'error')
    return redirect('https://edmakers-0804e31d8eb9.herokuapp.com/login')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        if 'delete' in request.form:
            user_id = request.form['delete']
            user = User.query.get(user_id)
            if user:
                db.session.delete(user)
                db.session.commit()
                flash('사용자가 성공적으로 삭제되었습니다.', 'success')

    expired_users = User.query.filter(User.expiry_date < datetime.utcnow()).all()
    for user in expired_users:
        db.session.delete(user)
    if expired_users:
        db.session.commit()
        flash(f'{len(expired_users)} 명의 만료된 사용자(들)이 자동으로 삭제되었습니다.', 'info')

    users = User.query.order_by(User.expiry_date).all()
    return render_template('admin.html', users=users)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        expiry_days = int(request.form['expiry_days'])
        expiry_date = datetime.utcnow() + timedelta(days=expiry_days)
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user and check_password_hash(existing_user.password, password):
            flash('사용할 수 없는 계정입니다. 비밀번호를 변경해주세요.', 'error')
            return redirect('https://edmakers-0804e31d8eb9.herokuapp.com/register')
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, expiry_date=expiry_date)
        db.session.add(new_user)
        db.session.commit()
        flash('등록이 완료되었습니다.', 'success')
    return redirect('https://edmakers-0804e31d8eb9.herokuapp.com/register')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('로그아웃합니다.', 'info')
    return redirect('https://edmakers-0804e31d8eb9.herokuapp.com/login')

def save_codes(user_code, admin_code):
    codes = {
        "user_code": user_code,
        "admin_code": admin_code
    }
    with open('codes.json', 'w') as f:
        json.dump(codes, f)

def load_codes():
    try:
        with open('codes.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"user_code": "5678", "admin_code": "1234"}

@app.route('/', methods=['GET', 'POST'])
def login_page():
    codes = load_codes()
    if request.method == 'POST':
        secret_code = request.form.get('secret_code')
        if secret_code == codes["admin_code"]:
            flash("관리자 코드가 입력되었습니다. 관리자 페이지로 이동합니다.")
            return redirect("https://edmakers-0804e31d8eb9.herokuapp.com/index")
        elif secret_code == codes["user_code"]:
            flash("사용자 코드가 입력되었습니다. Chat GPT로 이동합니다.")
            return redirect('https://edmakers-gpt.streamlit.app/')
        else:
            flash("잘못된 코드입니다.", "error")
            return redirect('https://edmakers-0804e31d8eb9.herokuapp.com/cod')
    return render_template('login.html')

@app.route('/cod', methods=['GET', 'POST'])
def cod():
    codes = load_codes()
    if request.method == 'POST':
        secret_code = request.form.get('secret_code')
        if secret_code == codes["admin_code"]:
            flash("관리자 코드가 입력되었습니다. 관리자 페이지로 이동합니다.")
            return redirect(url_for("index"))
        elif secret_code == codes["user_code"]:
            flash("사용자 코드가 입력되었습니다. Chat GPT로 이동합니다.")
            return redirect('https://edmakers-gpt.streamlit.app/')
        else:
            flash("잘못된 코드입니다.", "error")
            return redirect(url_for("cod"))
    return render_template('cod.html')

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/set_code', methods=['GET', 'POST'])
def set_code_page():
    if request.method == 'POST':
        new_user_code = request.form.get('user_code')
        new_admin_code = request.form.get('admin_code')
        save_codes(new_user_code, new_admin_code)
        flash(f"관리자 코드는 {new_admin_code}, 사용자 코드는 {new_user_code}로 변경되었습니다.")
        return redirect('https://edmakers-0804e31d8eb9.herokuapp.com/set_code')
    codes = load_codes()
    return render_template('set_code.html', current_user_code=codes["user_code"], current_admin_code=codes["admin_code"])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
