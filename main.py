from flask import Flask, render_template, request, redirect, url_for, flash
import image_slicer
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from twilio.rest import Client
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'

# image_slicer.slice('static/emoji.jpg', 25)
# Creating the extention
db = SQLAlchemy()
##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# initialize the app with the extension
db.init_app(app)
app.app_context().push()

Account_Sid = 'ACafef6ed5bfb81825e5ccde2412877167'
Auth_Token = 'f497d34d8b83501949e090845fe27333'

# Creating the table in the database
class user_info(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(20), unique=True)
    email = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(100))
    phone = db.Column(db.String(12), unique=True)
    password = db.Column(db.String(100))


db.create_all()

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)



@login_manager.user_loader
def load_user(user_name):
    return user_info.query.get(int(user_name))


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/login", methods=['POST', 'GET'])
def login():
    image_src_list = []
    check_box_id = []
    for i in range(1, 6):
        for j in range(1, 6):
            image_src_list.append(f"static/emoji_0{i}_0{j}.png")
    for i in range(1, 26):
        check_box_id.append(f"cb{i}")

    if request.method == 'POST':
        username = request.form.get('username')
        user = user_info.query.filter_by(user_name=username).first()
        print(user.password)

        selected_images = []

        for i in range(25):
            if request.form.get(check_box_id[i]) == 'on':
                selected_images.append(image_src_list[i])


        password_string = (' '.join([str(elem) for elem in selected_images])).replace(" ", "")
        # creating the password to the hash
        generated_hash = generate_password_hash(password_string, method='pbkdf2:sha256', salt_length=8)
        print(username)
        print(generated_hash)
        # Email doesn't exist
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        # Password incorrect
        elif not check_password_hash(user.password, password_string):
            flash('Password incorrect, please try again.')
            print('Password')
            return redirect(url_for('login'))
        else:
            print("Login")
            login_user(user)
            return redirect(url_for('home'))
    return render_template("login.html", images=image_src_list, check_box_id=check_box_id, list_range=range(0, 25))


@app.route('/register', methods=['GET', 'POST'])
def register():
    image_src_list = []
    check_box_id = []
    for i in range(1, 6):
        for j in range(1, 6):
            image_src_list.append(f"static/emoji_0{i}_0{j}.png")
    for i in range(1, 26):
        check_box_id.append(f"cb{i}")


    selected_images = []

    if request.method == 'POST':
        name = request.form.get('name')
        username = request.form.get('username')
        phone = request.form.get('phone')
        email = request.form.get('email')
        for i in range(25):
            if request.form.get(check_box_id[i]) == 'on':
                selected_images.append(image_src_list[i])


        password_string = (' '.join([str(elem) for elem in selected_images])).replace(" ", "")
        # creating the password to the hash
        generated_hash = generate_password_hash(password_string, method='pbkdf2:sha256', salt_length=8)
        print(username, name, phone, email, generated_hash)
        # Storing the user data in the database
        new_user = user_info(
            user_name=username,
            name=name,
            phone=phone,
            email=email,
            password=generated_hash
        )
        db.session.add(new_user)
        db.session.commit()
    return render_template("register.html", images=image_src_list, check_box_id=check_box_id, list_range=range(0, 25))




@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/viewusers', methods=['POST', 'GET'])
def viewusers():
    allUsers = user_info.query.all()
    if request.method == 'POST':
        # Deleting the User
        userid = request.form.get('id')
        userid_to_delete = user_info.query.get(userid)
        db.session.delete(userid_to_delete)
        db.session.commit()
        print(userid)
        return redirect(url_for('viewusers'))
    return render_template('viewusers.html', allUsers=allUsers, length=len(allUsers))


@app.route('/about')
def about():
    return render_template('about.html')


OTP = ""
@app.route('/forgotpassword', methods=['POST','GET'])
def forgotpassword():
    if request.method=='POST':
        user_id = request.form.get('username')
        user = user_info.query.get(user_id)
        # phone = user.phone()
        client = Client(Account_Sid, Auth_Token)
        global OTP
        for _ in range(0, 5):

            OTP += str(random.randint(0, 9))
        message = client.messages.create(
            from_='+13613458502',
            body=f'The Verification Code : {OTP}',
            to='+917057811446'
        )
        return redirect(url_for('VerifyOTP'))
    return render_template('forgotpassword.html')


@app.route('/verify', methods=['POST','GET'])
def VerifyOTP():
    if request.method=='POST':
        userotp = request.form.get('otp')
        print(OTP)
        if userotp != OTP:
            flash('Wrong OTP')
            print('wrong OTP')
        else:
            return redirect(url_for('ChangePassword'))
    return render_template('verify.html')


@app.route('/changepassword', methods=['POST', 'GET'])
def ChangePassword():
    image_src_list = []
    check_box_id = []
    for i in range(1, 6):
        for j in range(1, 6):
            image_src_list.append(f"static/emoji_0{i}_0{j}.png")
    for i in range(1, 26):
        check_box_id.append(f"cb{i}")

    if request.method == 'POST':
        print('Changing Password')
        username = request.form.get('username')
        user = user_info.query.filter_by(user_name=username).first()
        print(user.password)

        selected_images = []

        for i in range(25):
            if request.form.get(check_box_id[i]) == 'on':
                selected_images.append(image_src_list[i])

        password_string = (' '.join([str(elem) for elem in selected_images])).replace(" ", "")
        generated_hash = generate_password_hash(password_string, method='pbkdf2:sha256', salt_length=8)
        user.password = generated_hash
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('changepassword.html', images=image_src_list, check_box_id=check_box_id, list_range=range(0, 25))


@app.route('/contact')
def contact():
    return render_template('contact.html')


if __name__ == '__main__':
    app.run(debug=True, port=1000)