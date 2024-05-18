from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
import mysql.connector
from flask_bcrypt import Bcrypt

app = Flask(__name__, template_folder="templates", static_folder="static")

bcrypt = Bcrypt()

app.secret_key = 'lilmuzi619'

# Connect to the database
conn = mysql.connector.connect(database='protectium', user='root',
                               password='!1m$qL@2o@E', auth_plugin='mysql_native_password')
cur = conn.cursor()


@app.route('/')
def home():
    return render_template('Home.html')


@app.route('/login/', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        pattern_password = request.form["pattern_password"]
        picture_password = request.form["picture_password"]

        cur.execute(
            'SELECT * FROM accounts WHERE username = %s', [username])
        user_exists = cur.fetchone()

        if user_exists:
            cur.execute(
                'SELECT password FROM accounts WHERE username = %s', [username])
            hashed_password_from_database = cur.fetchone()[0]

            cur.execute(
                'SELECT pattern_password FROM accounts WHERE username = %s', [username])
            hashed_pattern_password_from_database = cur.fetchone()[0]

            cur.execute(
                'SELECT picture_password FROM accounts WHERE username = %s', [username])
            hashed_picture_password_from_database = cur.fetchone()[0]

            if (bcrypt.check_password_hash(hashed_password_from_database, password)) and (bcrypt.check_password_hash(hashed_pattern_password_from_database, pattern_password)) and (bcrypt.check_password_hash(hashed_picture_password_from_database, picture_password)):
                return redirect(url_for('welcome', fname=username))
            else:
                error = 'Incorrect credentials'
                return redirect(url_for('login', error=error))
        else :
            error = 'User does not exist'
            return redirect(url_for('login', error=error))
    return render_template('Login.html', error=error)


@app.route('/signup/',  methods=['GET', 'POST'])
def signup():
    error = ''
    if request.method == 'POST':
        fname = request.form["fname"]
        lname = request.form["lname"]
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]
        pattern_password = request.form["pattern_password"]
        picture_password = request.form["picture_password"]

        hashed_email = bcrypt.generate_password_hash(
            email).decode('utf-8')
        
        hashed_password = bcrypt.generate_password_hash(
            password).decode('utf-8')
        
        hashed_pattern_password = bcrypt.generate_password_hash(
            pattern_password).decode('utf-8')
        
        hashed_picture_password = bcrypt.generate_password_hash(
            picture_password).decode('utf-8')

        cur.execute(
            'SELECT * FROM accounts WHERE username = %s', [username])
        username_from_database = cur.fetchone()
        
        if username_from_database:
            error = 'Username already exists !'
            return redirect(url_for('signup', error=error))
        else:
            cur.execute(
                "INSERT INTO accounts (fname, lname, email, username, password, pattern_password, picture_password) VALUES (%s, %s, %s, %s, %s, %s, %s)", (fname, lname, hashed_email, username, hashed_password, hashed_pattern_password, hashed_picture_password))
            
            conn.commit()
            return redirect(url_for('welcome', fname=fname))

    return render_template("SignUp.html", error=error)


@app.route('/aboutus/')
def aboutus():
    return render_template('AboutUs.html')


@app.route('/underdevelopment/')
def underdevelopment():
    return render_template('UnderDevelopment.html')

@app.route('/welcome/')
def welcome():
    fname = request.args.get("fname")
    return render_template('Welcome.html', fname=fname)


if __name__ == '__main__':
    app.run(debug=True)
