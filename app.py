from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
import json
from flask import Flask, send_from_directory

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
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
                return render_template('login.html')
            login_user(user)
            # 여기에 Streamlit 페이지 URL을 입력하세요
            return redirect('https://edmakers-gpt.streamlit.app/')
        flash('ID 혹은 비밀번호가 잘못되었습니다.', 'error')
    return render_template('login.html')

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

    # 만료된 사용자 자동 삭제
    expired_users = User.query.filter(User.expiry_date < datetime.utcnow()).all()
    for user in expired_users:
        db.session.delete(user)
    if expired_users:
        db.session.commit()
        flash(f'{len(expired_users)} 명의 만료된 사용자(들)이 자동으로 삭제되었습니다.', 'info')

    # 사용자를 만료일 순으로 정렬
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
            return render_template('register.html')
        
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, expiry_date=expiry_date)
        db.session.add(new_user)
        db.session.commit()
        flash('등록이 완료되었습니다.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('로그아웃합니다.', 'info')
    return redirect(url_for('login'))

# 암호 코드를 저장하는 함수
def save_codes(user_code, admin_code):
    codes = {
        "user_code": user_code,
        "admin_code": admin_code
    }
    with open('codes.json', 'w') as f:
        json.dump(codes, f)

# 암호 코드를 불러오는 함수
def load_codes():
    try:
        with open('codes.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"user_code": "5678", "admin_code": "1234"}  # 기본값

@app.route('/', methods=['GET', 'POST'])
def login_page():
    codes = load_codes()  # 항상 최신 코드를 불러옴
    if request.method == 'POST':
        secret_code = request.form.get('secret_code')
        if secret_code == codes["admin_code"]:
            flash("관리자 코드가 입력되었습니다. 관리자 페이지로 이동합니다.")
            return redirect("index.html")  # 1111 입력 시 네이버로 이동
        elif secret_code == codes["user_code"]:
            flash("사용자 코드가 입력되었습니다. Chat GPT로 이동합니다.")
            return redirect('https://edmakers-gpt.streamlit.app/')  # 2222 입력 시 인덱스 페이지로 이동
        else:
            flash("잘못된 코드입니다.", "error")
            return redirect(url_for('login_page'))
    return render_template('login.html')

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/set_code', methods=['GET', 'POST'])
def set_code_page():
    if request.method == 'POST':
        new_user_code = request.form.get('user_code')
        new_admin_code = request.form.get('admin_code')
        save_codes(new_user_code, new_admin_code)  # 암호 저장
        flash(f"관리자 코드는 {new_admin_code}, 사용자 코드는 {new_user_code}로 변경되었습니다.")
        return redirect(url_for('set_code_page'))  # 암호 설정 페이지로 리디렉션
    codes = load_codes()  # 항상 최신 코드를 불러옴
    return render_template('set_code.html', current_user_code=codes["user_code"], current_admin_code=codes["admin_code"])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('FLASK_RUN_PORT', 5001))
    app.run(debug=True, port=5002)
