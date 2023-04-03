from flask import Flask, render_template, redirect, request
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
import datetime
import pytz
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SECRET_KEY'] = os.urandom(24)
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(20))
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/', methods=['GET', 'POST'])
def index_no_login():
    if request.method == 'POST':
        pass
    return render_template("index.html")


@app.route('/login/home', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        pass
    now = datetime.datetime.now(pytz.timezone('Asia/Tokyo'))
    return render_template("home.html",login=1)




@app.route('/signup', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        user_name = request.form.get("user_name")
        password = request.form.get("password")

        user = User(username=user_name, password=generate_password_hash(password, method='sha256'))

        db.session.add(user)
        db.session.commit()
        return redirect('/login')

    else:
        return render_template("signup.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_name = request.form.get("user_name")
        password = request.form.get("password")

        user = User.query.filter_by(username=user_name).first()
        if check_password_hash(user.password, password):
            login_user(user)
            return redirect('/login/home')
        else:
            return redirect('/login')

    else:
        return render_template("login.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')


if __name__ == '__main__':
    # app.debug = True
    app.run(debug=True)