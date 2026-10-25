import os
import sqlite3
from flask import Flask, request, jsonify
from dotenv import load_dotenv
from crypto import hash_password, verify_password

load_dotenv()

app = Flask(__name__)

API_KEY = os.getenv("API_KEY")
ADMIN_API_KEY = os.getenv("ADMIN_API_KEY")

def get_db_connection():
    conn = sqlite3.connect('app.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    hashed = hash_password(password)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (username, hashed)
    )
    conn.commit()
    conn.close()

    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    )
    user = cursor.fetchone()
    conn.close()

    if user and verify_password(password, user['password']):
        return jsonify({"message": "Login successful"}), 200

    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/admin', methods=['GET'])
def admin_dashboard():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Unauthorized"}), 401

    token = auth_header.split(' ')[1]
    if token != ADMIN_API_KEY:
        return jsonify({"error": "Forbidden"}), 403

    return jsonify({"data": "Confidential Admin Statistics"}), 200

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)