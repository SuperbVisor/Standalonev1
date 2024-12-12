from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt, check_password_hash
import os
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///game_store.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
bcrypt = Bcrypt(app)

db = SQLAlchemy(app)

# Folder untuk menyimpan file yang diunggah
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Fungsi untuk memeriksa ekstensi file
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
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
@app.route('/')
def index():
    if 'user_id' in session or 'admin_id' in session:
        games = Game.query.all()
        return render_template('dashboard.html', games=games)
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check User Login
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))

        # Check Admin Login
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password, password):
            session['admin_id'] = admin.id
            return redirect(url_for('index'))

        flash('Invalid username or password', 'error')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful', 'success')
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
            db.session.commit()
            flash('Profile updated successfully', 'success')

        return render_template('profile.html', user=user)
    elif 'admin_id' in session:
        admin = Admin.query.get(session['admin_id'])
        games = Game.query.all()
        return render_template('admin_profile.html', admin=admin, games=games)
    return redirect(url_for('login'))

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
