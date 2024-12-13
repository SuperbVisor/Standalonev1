from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt, check_password_hash
import os
from werkzeug.utils import secure_filename
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
import requests


# Google Sign-In Configuration
GOOGLE_CLIENT_ID = "260418655884-g8qql6osd9hclkof5835g4hv6j8qekib.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
GOOGLE_DISCOVERY_URL = "https://accounts.google.com/.well-known/openid-configuration"

# Configure Google Sign-In flow
flow = Flow.from_client_secrets_file(
    'client_secrets.json',
    scopes=['openid', 'email', 'profile'],
    redirect_uri='https://gamestorefree-edczbmc0e5hdb9en.southeastasia-01.azurewebsites.net/login/google/callback'
)

app = Flask(__name__)
app.secret_key = 'your_secret_key'
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

# Ensure both folders exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROFILE_PIC_FOLDER, exist_ok=True)
# Fungsi untuk memeriksa ekstensi file
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

# Routes
@app.route('/google-login')
def google_login():
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)


@app.route('/login/google/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session['state'] == request.args['state']:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    token_request = requests.Request().prepare()

    token_request.headers['Authorization'] = f'Bearer {credentials.token}'
    token_request.url = 'https://www.googleapis.com/oauth2/v3/userinfo'
    response = request_session.send(token_request)
    userinfo = response.json()

    # Check if user exists, if not, create a new user
    user = User.query.filter_by(email=userinfo['email']).first()
    if not user:
        user = User(email=userinfo['email'], 
                    username=userinfo['name'], 
                    password=bcrypt.generate_password_hash('google_auth').decode('utf-8'))
        db.session.add(user)
        db.session.commit()
        

    # Log in the user
    session['user_id'] = user.id
    session['username'] = user.username
    print("After Google login, session:", session)  # Debug: Print session after setting
    flash('Logged in successfully via Google', 'success')
    return redirect(url_for('index'))  # This will redirect to the dashboard




@app.route('/404')
def error_404():
    return render_template('404.html'), 404

@app.route('/')
def index():
    print("Session:", session)  # Debug: Print session contents
    if 'user_id' in session or 'admin_id' in session:
        games = Game.query.all()
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            print("User:", user)  # Debug: Print user object
        else:
            user = Admin.query.get(session['admin_id'])
            print("Admin:", user)  # Debug: Print admin object
        return render_template('dashboard.html', user=user, games=games)
    else:
        # Get stats for the landing page
        visitor_count = User.query.count()
        user_count = User.query.count()
        online_users = 0  # You'll need to implement a way to track online users

        return render_template('landing.html', 
                               visitor_count=visitor_count, 
                               user_count=user_count, 
                               online_users=online_users)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check User Login
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username  # Add this line
            return redirect(url_for('index'))

        # Check Admin Login
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password, password):
            session['admin_id'] = admin.id
            session['username'] = admin.username  # Add this line
            return redirect(url_for('index'))

        flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Check if the passwords match
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
            return redirect(url_for('register'))

        # Check if the username is 'admin123'
        if username.lower() == 'admin123':
            flash('This username is reserved. Please choose a different username.', 'error')
            return redirect(url_for('register'))

        # Check if the email or username already exists
        existing_user = User.query.filter((User.email == email) | (User.username == username)).first()
        if existing_user:
            flash('Email or username already exists. Please choose different credentials.', 'error')
            return redirect(url_for('register'))

        # If all checks pass, proceed with registration
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(email=email, username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
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
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('profile'))

    # Delete the user's profile picture if it exists
    if user.profile_pic and user.profile_pic != 'default.png':
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], user.profile_pic))
        except Exception as e:
            print(f"Error deleting profile picture: {e}")

    # Delete the user from the database
    db.session.delete(user)
    db.session.commit()

    # Clear the session
    session.clear()

    flash('Your account has been successfully deleted.', 'success')
    return redirect(url_for('index'))

@app.route('/add_game', methods=['GET', 'POST'])
def add_game():
    if request.method == 'POST':
        name = request.form['name']
        genre = request.form['genre']
        description = request.form['description']
        download_url = request.form['download_url']
        
        # Mengunggah file gambar
        image_file = request.files['image_file']
        if image_file and allowed_file(image_file.filename):
            filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image_file.save(image_path)
        else:
            return "Invalid image file", 400
        
        # Simpan data ke database
        new_game = Game(
            name=name,
            genre=genre,
            description=description,
            download_url=download_url,
            image_url=image_path  # Simpan path file
        )
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
        
        # Perbarui file gambar jika ada file baru yang diunggah
        if 'image_file' in request.files:
            image_file = request.files['image_file']
            if image_file and allowed_file(image_file.filename):
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
                game.image_url = image_path  # Perbarui path gambar
        
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

# Search Game
@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '').strip()
    if query:
        # Cari game berdasarkan nama atau genre (case-insensitive)
        results = Game.query.filter(
            (Game.name.ilike(f"%{query}%")) | (Game.genre.ilike(f"%{query}%"))
        ).all()
    else:
        results = []
    
    return render_template('dashboard.html', games=results)


if __name__ == '__main__':
    app.run(debug=True)
