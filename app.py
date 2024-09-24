import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask import jsonify
import json
from flask_cors import CORS

load_dotenv()

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

DATABASE_URL = os.getenv('DATABASE_URL')
if DATABASE_URL is None:
    logger.error("DATABASE_URL is not set.")
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///site.db"
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL.replace("postgres://", "postgresql://", 1)

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
                return redirect(url_for('login'))
            login_user(user)
            return redirect(url_for('index'))  # 또는 다른 메인 페이지로 리다이렉트
        flash('아이디 또는 비밀번호가 잘못되었습니다.', 'error')
    return render_template('login.html')
    

@app.route('/api/login', methods=['POST'])
def api_login():
    username = request.json.get('username')
    password = request.json.get('password')
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        if user.expiry_date < datetime.utcnow():
            return jsonify({'message': '계정이 만료되었습니다. 관리자에게 문의하세요.', 'category': 'error'}), 401
        login_user(user)
        return jsonify({'message': '로그인 성공', 'redirect': 'https://edmakers-gpt.streamlit.app/'})
    return jsonify({'message': 'ID 혹은 비밀번호가 잘못되었습니다.', 'category': 'error'}), 401

@app.route('/admin')
def admin():
    users = User.query.order_by(User.expiry_date).all()
    return render_template('admin.html', users=users)

@app.route('/api/delete_user', methods=['POST'])
def delete_user():
    user_id = request.json.get('user_id')
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'success': True})
    return jsonify({'success': False}), 404

@app.route('/api/delete_expired_users', methods=['POST'])
def delete_expired_users():
    expired_users = User.query.filter(User.expiry_date < datetime.utcnow()).all()
    deleted_count = len(expired_users)
    expired_ids = [user.id for user in expired_users]
    for user in expired_users:
        db.session.delete(user)
    db.session.commit()
    return jsonify({'deleted': deleted_count, 'expired_ids': expired_ids})

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/api/register', methods=['POST'])
def api_register():
    username = request.json.get('username')
    password = request.json.get('password')
    expiry_days = int(request.json.get('expiry_days'))
    expiry_date = datetime.utcnow() + timedelta(days=expiry_days)
    
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'message': '이미 존재하는 사용자명입니다.', 'category': 'error'}), 400
    
    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password=hashed_password, expiry_date=expiry_date)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': '등록이 완료되었습니다.', 'category': 'success'})

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

@app.route('/cod')
def cod():
    return render_template('cod.html')

@app.route('/api/check_code', methods=['POST'])
def check_code():
    secret_code = request.json.get('secret_code')
    codes = load_codes()
    if secret_code == codes["admin_code"]:
        return jsonify({"message": "관리자 코드가 입력되었습니다. 관리자 페이지로 이동합니다.", "redirect": url_for("index")})
    elif secret_code == codes["user_code"]:
        return jsonify({"message": "사용자 코드가 입력되었습니다. Chat GPT로 이동합니다.", "redirect": 'https://edmakers-gpt.streamlit.app/'})
    else:
        return jsonify({"message": "잘못된 코드입니다.", "redirect": url_for("cod")}), 400

@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/set_code')
def set_code_page():
    codes = load_codes()
    return render_template('set_code.html', current_user_code=codes["user_code"], current_admin_code=codes["admin_code"])

@app.route('/api/set_code', methods=['POST'])
def api_set_code():
    new_user_code = request.json.get('user_code')
    new_admin_code = request.json.get('admin_code')
    save_codes(new_user_code, new_admin_code)
    return jsonify({
        'message': f"관리자 코드는 {new_admin_code}, 사용자 코드는 {new_user_code}로 변경되었습니다.",
        'new_user_code': new_user_code,
        'new_admin_code': new_admin_code
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
