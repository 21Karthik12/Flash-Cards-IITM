from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, RadioField
from wtforms.validators import Length, EqualTo, Email, DataRequired, ValidationError
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, UserMixin, logout_user
import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///flash_cards.db'
app.config['SECRET_KEY'] = '80b41981c0fb8718c11966d3'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

@login_manager.user_loader
def load_user(user_id):
    return user.query.get(int(user_id))

class user(db.Model, UserMixin):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(length=30), nullable=False, unique=True)
    email = db.Column(db.String(length=50), nullable=False, unique=True)
    password_hash = db.Column(db.String(length=60), nullable=False)
    decks = db.relationship('deck', backref='owned_user', lazy=True)
    
    def __repr__(self):
        return f'user {self.username}'

    def get_id(self):
        return self.user_id

    @property
    def password(self):
        return self.password

    @password.setter
    def password(self, plain_text_password):
        self.password_hash = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')

    def check_password(self, tried_password):
        return bcrypt.check_password_hash(self.password_hash, tried_password)

class deck(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(length=50), nullable=False)
    score = db.Column(db.Float(precision=2), nullable=False, default=0)
    temp_score = db.Column(db.Float, nullable=False, default=0)
    times = db.Column(db.Integer, nullable=False, default=0)
    last_review = db.Column(db.DateTime, nullable=False, default=datetime.datetime.now)
    owner = db.Column(db.Integer, db.ForeignKey('user.user_id'))
    cards = db.relationship('card', backref='parent', lazy=True)

    def __repr__(self):
        return f'deck {self.name}'

class card(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(length=70), nullable=False)
    answer = db.Column(db.String(length=200), nullable=False)
    parent_deck = db.Column(db.Integer, db.ForeignKey('deck.id'))

class RegisterForm(FlaskForm):
    def validate_username(self, username_to_check):
        usr = user.query.filter_by(username=username_to_check.data).first()
        if usr:
            raise ValidationError('Username already exists! Please try a different username.')
    
    def validate_email(self, email_to_check):
        e = user.query.filter_by(email=email_to_check.data).first()
        if e:
            raise ValidationError('Email already exists! Please try a different email address.')

    username = StringField(label='Username:', validators=[Length(min=2, max=30), DataRequired()])
    email = StringField(label='Email Address:', validators=[Email(), DataRequired()])
    password1 = PasswordField(label='Password:', validators=[Length(min=6), DataRequired()])
    password2 = PasswordField(label='Confirm Password:', validators=[EqualTo('password1'), DataRequired()])
    submit = SubmitField(label='Submit')

class LoginForm(FlaskForm):
    username = StringField(label='Username:', validators=[DataRequired()])
    password = PasswordField(label='Password:', validators=[DataRequired()])
    submit = SubmitField(label='Sign in')

class AddDeckForm(FlaskForm):
    name = StringField(label='Deck Name:', validators=[DataRequired()])
    submit = SubmitField(label='Create Deck')

class AddCardForm(FlaskForm):
    question = StringField(label='Question:', validators=[DataRequired()])
    answer = StringField(label='Answer:', validators=[DataRequired()])
    submit = SubmitField(label='Create Card')

class DifficultyForm(FlaskForm):
    difficulty = RadioField(label = "Difficulty: ", choices = [('easy', 'Easy'), ('medium', 'Medium'), ('hard', 'Hard')])
    submit = SubmitField(label = "Next")

class DifficultyFormLast(FlaskForm):
    difficulty = RadioField(label = "Difficulty: ", choices = [('easy', 'Easy'), ('medium', 'Medium'), ('hard', 'Hard')])
    submit = SubmitField(label = "Exit")

@app.route('/')
@app.route('/home')
def home():
    return render_template('homepage.html')

@app.route('/<uid>/decks', methods=['GET', 'POST'])
def decks(uid):
    decks = deck.query.filter_by(owner=uid)
    cards = []
    for d in decks:
        temp = card.query.filter_by(parent_deck=d.id).first()
        cards.append(temp)
    return render_template('decks.html', items = decks, uid = uid, cards = cards, l=len(cards))

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    form = RegisterForm()
    if form.validate_on_submit():
        user_to_create = user(username=form.username.data, email=form.email.data, password=form.password1.data)
        db.session.add(user_to_create)
        db.session.commit()
        login_user(user_to_create)
        flash(f'Account created successfully! You are now logged in as {user_to_create.username}.', category='success')
        return redirect(url_for('decks', uid=user_to_create.user_id))
    if form.errors != {}:
        for err in form.errors.values():
            flash(err[0], category='danger')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        current_user = user.query.filter_by(username=form.username.data).first()
        if current_user and current_user.check_password(form.password.data):
            login_user(current_user)
            flash(f'Success! You are logged in as {current_user.username}.', category='success')
            return redirect(url_for('decks', uid=current_user.user_id))
        flash('Username and password mismatch!', category='danger')

    return render_template('login.html', form=form)

@app.route('/logout' , methods=['GET', 'POST'])
def logout():
    logout_user()
    flash("You have been logged out!", category='info')
    return redirect(url_for('login'))

@app.route('/<uid>/add_deck', methods=['GET', 'POST'])
def add_deck(uid):
    form = AddDeckForm()
    if request.method=="POST":
        current_deck = deck(name=form.name.data, owner=uid)
        db.session.add(current_deck)
        db.session.commit()
        return redirect(url_for('decks', uid=uid))
    return render_template('add_deck.html', form=form)

@app.route('/<uid>/<deckid>/delete_deck', methods=['GET', 'POST'])
def delete_deck(uid, deckid):
    cards_to_delete = card.query.filter_by(parent_deck=deckid)
    for i in cards_to_delete:
        card.query.filter_by(id=i.id).delete()
    deck.query.filter_by(id=deckid).delete()
    db.session.commit()
    return redirect(url_for('decks', uid=uid))

@app.route('/<uid>/<deckid>/add_card', methods=['GET', 'POST'])
def add_card(uid, deckid):
    form = AddCardForm()
    if request.method == 'POST':
        current_card = card(question=form.question.data, answer=form.answer.data, parent_deck=deckid)
        db.session.add(current_card)
        db.session.commit()
        return redirect(url_for('decks', uid=uid))
    return render_template('add_card.html', form=form)

@app.route('/<uid>/<deckid>/<cardid>/show_card', methods=['GET', 'POST'])
def show_card(uid, deckid, cardid):
    cards = card.query.filter_by(parent_deck=deckid)
    c = card.query.filter_by(id=cardid).first()
    l = []
    for i in cards:
        l.append(i)
    next = None
    for i in range(len(l) - 1):
        if l[i].id == int(cardid):
            next = l[i+1]
    form = DifficultyForm()
    d = form.difficulty.data
    if d == 'easy':
        score=10
    elif d == 'medium':
        score=5
    else:
        score=0
    temp = deck.query.filter_by(id=deckid).first()
    temp.temp_score = deck.temp_score + score
    db.session.commit()
    return render_template('show_card.html', uid=uid, deckid=deckid, curr=c, next=next, form=form)

@app.route('/<uid>/<deckid>/<cardid>/show_last', methods=['GET', 'POST'])
def show_last(uid, deckid, cardid):
    form = DifficultyForm()
    d = form.difficulty.data
    if d == 'easy':
        score=10
    elif d == 'medium':
        score=5
    else:
        score=0
    temp = deck.query.filter_by(id=deckid)
    temp.update(dict(last_review = datetime.datetime.now()))
    temp = temp.first()
    temp.temp_score = deck.temp_score + score
    temp.score = ((deck.score * temp.times) + temp.temp_score) / (temp.times + 1)
    temp.times = deck.times + 1
    temp.temp_score = 0
    db.session.commit()
    return redirect(url_for('decks', uid=uid))

@app.route('/<uid>/<deckid>/edit_deck', methods=['GET', 'POST'])
def edit_deck(uid, deckid):
    cards = card.query.filter_by(parent_deck=deckid)
    return render_template('edit_deck.html', items = cards, uid = uid, deckid = deckid)

@app.route('/<uid>/<deckid>/<cardid>/delete_card', methods=['GET', 'POST'])
def delete_card(uid, deckid, cardid):
    card.query.filter_by(id=cardid).delete()
    db.session.commit()
    return redirect(url_for('edit_deck', uid=uid, deckid=deckid))

@app.route('/<uid>/<deckid>/exit_from_view', methods=['GET', 'POST'])
def exit_from_view(uid, deckid):
    temp = deck.query.filter_by(id=deckid).first()
    temp.temp_score = 0
    db.session.commit()
    return redirect(url_for('decks', uid=uid))

if __name__ == '__main__':
    app.run(debug=True)
