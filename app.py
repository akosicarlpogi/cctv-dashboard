from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime

app = Flask(__name__)
# Secret key is required to use sessions for the login system
app.secret_key = 'your_secret_key_here' 

# --- Hardcoded Admin Credentials ---
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "password123"

# --- Mock System Logs ---
system_logs = [
    {"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "event": "System Started", "user": "SYSTEM"},
]

# --- Network Configuration (Based on your manual) ---
CAMERA_IP = "192.168.1.10"
# Option B from manual: Snapshot Auto-Refresh
CAMERA_URL = f"http://{CAMERA_IP}/snapshot.jpg"

@app.route('/')
def index():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            session['username'] = username
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            system_logs.append({"time": timestamp, "event": "Successful Login", "user": username})
            
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.')
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            system_logs.append({"time": timestamp, "event": "Failed Login Attempt", "user": username})

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'logged_in' not in session:
        return redirect(url_for('login'))
        
    return render_template('dashboard.html', camera_url=CAMERA_URL, logs=system_logs[::-1])

if __name__ == '__main__':
    # Binding to 0.0.0.0 makes the server accessible across your local network
    app.run(host='0.0.0.0', port=5000, debug=True)