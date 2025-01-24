from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

# Configurazione di base
app = Flask(__name__)
app.secret_key = "supersecretkey"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inizializza Bcrypt e SQLAlchemy
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

# Modello User per il database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    posts = db.relationship('Post', back_populates='user')

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='posts')

# Rotta per la homepage
@app.route('/')
def home():
    if "user" in session:
        posts = Post.query.all()  # Ottieni tutti i post
        return render_template('home.html', username=session['user'], posts=posts)
    return redirect(url_for('login'))

# Rotta per la registrazione
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Controllo sulla lunghezza di username e password
        if len(username) < 6:
            return render_template('register.html', error="L'username deve contenere almeno 6 caratteri.")
        if len(password) < 6:
            return render_template('register.html', error="La password deve contenere almeno 6 caratteri.")

        # Cripta la password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Salva il nuovo utente
        new_user = User(username=username, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
        except:
            return render_template('register.html', error="Errore: username già esistente.")
    return render_template('register.html')

# Rotta per il login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user'] = username
            return redirect(url_for('home'))
        return "Credenziali non valide."
    return render_template('login.html')

# Rotta per il logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# Rotta per creare un nuovo post
@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if "user" not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['user']).first()  # Recupera l'utente dalla sessione
    if user is None:  # Aggiungi un controllo in caso di utente non trovato
        return redirect(url_for('login'))  # Se l'utente non esiste, torna alla pagina di login

    if request.method == 'POST':
        content = request.form['content']

        new_post = Post(content=content, user_id=user.id)

        try:
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for('home'))
        except:
            return "Errore nel creare il post."

    return render_template('new_post.html')


# Esegui l'app
if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Crea il database al primo avvio
    app.run(debug=True)
