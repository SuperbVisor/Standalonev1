from flask import Flask, render_template, redirect, url_for, request, session, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt, check_password_hash
import os
import time
from werkzeug.utils import secure_filename
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
import requests

# Google Sign-In Configuration
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# Configure Google Sign-In flow
flow = Flow.from_client_config(
    {
        "web": {
            "client_id": '260418655884-g8qql6osd9hclkof5835g4hv6j8qekib.apps.googleusercontent.com',
            "project_id": os.getenv('webs-apps-443712'),
            "auth_uri": os.getenv('GOOGLE_AUTH_URI', 'https://accounts.google.com/o/oauth2/auth'),
            "token_uri": os.getenv('GOOGLE_TOKEN_URI', 'https://oauth2.googleapis.com/token'),
            "auth_provider_x509_cert_url": os.getenv('GOOGLE_AUTH_PROVIDER_X509_CERT_URL', 'https://www.googleapis.com/oauth2/v3/certs'),
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uris": [os.getenv('https://gamestorefree-edczbmc0e5hdb9en.southeastasia-01.azurewebsites.net/login/google/callback')]
        }
    },
    scopes=["openid", "email", "profile"],
    redirect_uri=os.getenv('https://gamestorefree-edczbmc0e5hdb9en.southeastasia-01.azurewebsites.net/login/google/callback')
)

app = Flask(__name__)
app.secret_key = '123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///game_store.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
bcrypt = Bcrypt(app)

db = SQLAlchemy(app)

# Folder untuk menyimpan file yang diunggah
UPLOAD_FOLDER = 'static/uploads'
PROFILE_PIC_FOLDER = 'static/uploads/pp'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PROFILE_PIC_FOLDER'] = PROFILE_PIC_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROFILE_PIC_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    profile_pic = db.Column(db.String(120), default='default.png')
    bio = db.Column(db.String(255), default='')

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    genre = db.Column(db.String(120), nullable=False)
    image_url = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    download_url = db.Column(db.String(255), nullable=False)

# Initial Setup
def setup_admin():
    if not Admin.query.filter_by(username='admin123').first():
        hashed_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
        new_admin = Admin(username='admin123', password=hashed_password)
        db.session.add(new_admin)
        db.session.commit()

# Buat tabel database dan tambahkan admin
with app.app_context():
    db.create_all()
    setup_admin()

@app.route('/')
def index():
    if 'user_id' in session or 'admin_id' in session:
        games = Game.query.all()
        user = User.query.get(session['user_id']) if 'user_id' in session else Admin.query.get(session['admin_id'])
        time.sleep(0.5)  # Add a small delay
        return render_template('dashboard.html', user=user, games=games)
    visitor_count = User.query.count()
    user_count = User.query.count()
    online_users = 0
    time.sleep(0.5)  # Add a small delay
    return render_template('landing.html', visitor_count=visitor_count, user_count=user_count, online_users=online_users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('index'))

        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password, password):
            session['admin_id'] = admin.id
            session['username'] = admin.username
            return redirect(url_for('index'))

        flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/google_login')
def google_login():
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

@app.route('/login/google/callback')
def callback():
    if not session.get('state') == request.args.get('state'):
        flash("Invalid state parameter. Login failed.", "error")
        return redirect(url_for('login'))

    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    headers = {'Authorization': f'Bearer {credentials.token}'}
    response = requests.get('https://www.googleapis.com/oauth2/v3/userinfo', headers=headers)

    if response.status_code != 200:
        flash("Error authenticating with Google.", "error")
        return redirect(url_for('login'))

    userinfo = response.json()
    user = User.query.filter_by(email=userinfo['email']).first()
    if not user:
        user = User(email=userinfo['email'], username=userinfo.get('name', 'Google User'), password=bcrypt.generate_password_hash('google_auth').decode('utf-8'))
        db.session.add(user)
        db.session.commit()

    session['user_id'] = user.id
    session['username'] = user.username
    flash('Logged in successfully via Google', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))

        if username.lower() == 'admin123':
            flash('This username is reserved.', 'error')
            return redirect(url_for('register'))

        existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
        if existing_user:
            flash('Email or username already exists.', 'error')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful!', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if request.method == 'POST':
            user.username = request.form['username']
            user.bio = request.form['bio']

            if 'profile_pic' in request.files:
                file = request.files['profile_pic']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    file_path = os.path.join(app.config['PROFILE_PIC_FOLDER'], filename)
                    file.save(file_path)
                    user.profile_pic = filename

            db.session.commit()
            flash('Profile updated successfully', 'success')
            return redirect(url_for('profile'))

        return render_template('profile.html', user=user)

    elif 'admin_id' in session:
        admin = Admin.query.get(session['admin_id'])
        recent_games = Game.query.order_by(Game.id.desc()).limit(5).all()
        return render_template('admin_profile.html', admin=admin, recent_games=recent_games)

    return redirect(url_for('login'))

@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    if user:
        if user.profile_pic and user.profile_pic != 'default.png':
            os.remove(os.path.join(app.config['PROFILE_PIC_FOLDER'], user.profile_pic))

        db.session.delete(user)
        db.session.commit()
        session.clear()
        flash('Account deleted successfully.', 'success')

    return redirect(url_for('index'))

@app.route('/add_game', methods=['GET', 'POST'])
def add_game():
    if request.method == 'POST':
        name = request.form['name']
        genre = request.form['genre']
        description = request.form['description']
        download_url = request.form['download_url']

        image_file = request.files['image_file']
        if image_file and allowed_file(image_file.filename):
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)
        else:
            return "Invalid image file", 400

        new_game = Game(name=name, genre=genre, description=description, download_url=download_url, image_url=image_path)
        db.session.add(new_game)
        db.session.commit()
        return redirect('/')

    return render_template('add_game.html')

@app.route('/edit_game/<int:game_id>', methods=['GET', 'POST'])
def edit_game(game_id):
    game = Game.query.get_or_404(game_id)
    if request.method == 'POST':
        game.name = request.form['name']
        game.genre = request.form['genre']
        game.description = request.form['description']
        game.download_url = request.form['download_url']

        if 'image_file' in request.files:
            image_file = request.files['image_file']
            if image_file and allowed_file(image_file.filename):
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
                game.image_url = image_path

        db.session.commit()
        return redirect('/')

    return render_template('edit_game.html', game=game)

@app.route('/delete_game/<int:game_id>')
def delete_game(game_id):
    if 'admin_id' not in session:
        return redirect(url_for('login'))

    game = Game.query.get(game_id)
    db.session.delete(game)
    db.session.commit()
    flash('Game deleted successfully', 'success')
    return redirect(url_for('index'))

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '').strip()
    results = Game.query.filter((Game.name.ilike(f"%{query}%")) | (Game.genre.ilike(f"%{query}%"))).all() if query else []
    
    # Get the current user
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    elif 'admin_id' in session:
        user = Admin.query.get(session['admin_id'])
    
    return render_template('dashboard.html', games=results, user=user)


@app.route('/404')
def error_404():
    return render_template('404.html'), 404

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(debug=True)
