from flask import Flask, render_template, request, redirect, url_for, make_response, jsonify, flash
import pymysql
import jwt
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import time

app = Flask(__name__)
app.secret_key = 'super_secret_lab_key_2024'

DB_CONFIG = {
    'host': 'db',
    'user': 'lab_user',
    'password': 'lab_password_456',
    'database': 'secret_lab',
    'charset': 'utf8mb4',
    'use_unicode': True
}

def get_db_connection():
    return pymysql.connect(**DB_CONFIG)

def generate_jwt_token(user_id, username, role):
    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'exp': int(time.time()) + 3600  # 1 час
    }
    return jwt.encode(payload, 'weak_jwt_secret_1234567891234567', algorithm='HS256')

def verify_jwt_token(token):
    try:
        payload = jwt.decode(token, 'weak_jwt_secret_1234567891234567', algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # УЯЗВИМОСТЬ 1: SQL Injection
        # Намеренно уязвимый запрос без параметризации
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            
            if user:
                user_id, username, role = user
                token = generate_jwt_token(user_id, username, role)
                
                # Создаём ответ и сохраняем JWT в cookie
                response = make_response(redirect(url_for('dashboard')))
                response.set_cookie(
                    'token',
                    token,
                    max_age=3600,  # 1 час
                    httponly=True,  
                    secure=True,   
                    samesite='Strict' 
                )
                
                # Первый флаг за SQL injection
                if "'" in request.form['username'] or "'" in request.form['password']:
                    flash('HITS{web_1nj3ct10n_m4st3r}', 'success')
                
                return response
            else:
                flash('Неверные учетные данные', 'error')
        except Exception as e:
            flash(f'Ошибка базы данных: {str(e)}', 'error')
        finally:
            cursor.close()
            conn.close()
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('login'))
    
    token_data = verify_jwt_token(token)
    if not token_data:
        response = make_response(redirect(url_for('login')))
        response.delete_cookie('token')
        return response
    
    return render_template('dashboard.html', user=token_data)

@app.route('/research')
def research():
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('login'))
    
    token_data = verify_jwt_token(token)
    if not token_data:
        response = make_response(redirect(url_for('login')))
        response.delete_cookie('token')
        return response
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, encrypted_content, encryption_key FROM research_data")
    research_data = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template('research.html', research_data=research_data, user=token_data)

@app.route('/decrypt/<int:research_id>')
def decrypt_research(research_id):
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('login'))
    
    token_data = verify_jwt_token(token)
    if not token_data:
        response = make_response(redirect(url_for('login')))
        response.delete_cookie('token')
        return response
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT title, encrypted_content, encryption_key FROM research_data WHERE id = %s", (research_id,))
    research = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if research:
        title, encrypted_content, encryption_key = research
        
        # УЯЗВИМОСТЬ 2: Слабый шифр Цезаря с анализом частот
        return render_template('crypto_challenge.html', 
                             title=title, 
                             encrypted_content=encrypted_content,
                             hint=encryption_key,
                             research_id=research_id,
                             user=token_data)
    
    return redirect(url_for('research'))

@app.route('/analyze_cipher', methods=['POST'])
def analyze_cipher():
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('login'))
    
    token_data = verify_jwt_token(token)
    if not token_data:
        response = make_response(redirect(url_for('login')))
        response.delete_cookie('token')
        return response
    
    research_id = request.form.get('research_id')
    proposed_shift = request.form.get('shift', type=int)
    
    if research_id and proposed_shift is not None:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT title, encrypted_content, encryption_key FROM research_data WHERE id = %s", (research_id,))
        research = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if research:
            title, encrypted_content, encryption_key = research
            
            decrypted = caesar_decrypt(encrypted_content, proposed_shift)
            
            # Проверяем правильность расшифровки
            if is_valid_decryption(decrypted):
                # Второй флаг за правильную расшифровку
                flash('HITS{cr7pt0_k3y_r3v3rs3d}', 'success')
                return render_template('decrypted.html', 
                                     title=title, 
                                     content=decrypted, 
                                     shift=proposed_shift,
                                     method="Шифр Цезаря")
            else:
                flash(f'Неправильный сдвиг. Попробуйте другое значение.', 'warning')
                return render_template('crypto_challenge.html', 
                                     title=title, 
                                     encrypted_content=encrypted_content,
                                     hint=encryption_key,
                                     research_id=research_id,
                                     user=token_data,
                                     attempted_shift=proposed_shift,
                                     attempted_result=decrypted)
    
    return redirect(url_for('research'))

def caesar_decrypt(text, shift):
    """Расшифровка шифра Цезаря"""
    result = ""
    for char in text:
        if char.isalpha():
            # Определяем базу (A или a)
            base = ord('A') if char.isupper() else ord('a')
            # Применяем сдвиг
            shifted = (ord(char) - base - shift) % 26
            result += chr(shifted + base)
        else:
            result += char
    return result

def is_valid_decryption(text):
    """Проверяем, является ли расшифрованный текст осмысленным"""
    keywords = ['SECRET', 'LABORATORY', 'RESEARCH', 'EXPERIMENT', 'DATA', 'CLASSIFIED']
    text_upper = text.upper()
    return any(keyword in text_upper for keyword in keywords)

@app.route('/admin')
def admin():
    token = request.cookies.get('token')
    if not token:
        return redirect(url_for('login'))
    
    token_data = verify_jwt_token(token)
    if not token_data:
        response = make_response(redirect(url_for('login')))
        response.delete_cookie('token')
        return response
    
    # УЯЗВИМОСТЬ 3: Недостаточная проверка прав доступа
    if token_data.get('role') != 'admin':
        flash('Доступ запрещен. Требуются права администратора.', 'error')
        return redirect(url_for('dashboard'))
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT secret_name, secret_value FROM admin_secrets")
    secrets = cursor.fetchall()
    cursor.close()
    conn.close()
    
    # Третий флаг за получение админских прав
    flash('HITS{pr1v1l3g3_3sc4l4t10n}', 'success')
    
    return render_template('admin.html', secrets=secrets, user=token_data)

@app.route('/api/user_info')
def api_user_info():
    token = request.cookies.get('token')
    if not token:
        return jsonify({'error': 'Не авторизован'}), 401
    
    token_data = verify_jwt_token(token)
    if not token_data:
        return jsonify({'error': 'Недействительный токен'}), 401
    
    return jsonify({
        'user_id': token_data['user_id'],
        'username': token_data['username'],
        'role': token_data['role'],
        'jwt_token': token, 
        'jwt_secret': 'weak_jwt_secret_1234567891234567' # Намеренная утечка секрета
    })

@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('index')))
    response.delete_cookie('token')
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)