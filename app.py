from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

app.secret_key = "cybershield-secret-key"

# MySQL Configuration
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = ""
app.config["MYSQL_DB"] = "cybershield_db"
app.config["MYSQL_PORT"] = 3306

mysql = MySQL(app)


# Home
@app.route("/")
def home():
    return redirect(url_for("login"))


# Register
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]

        # Basic validation
        if not username or not email or not password:
            flash("All fields are required!")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("Password must contain at least 6 characters!")
            return redirect(url_for("register"))

        cursor = mysql.connection.cursor()

        # Check existing username/email
        cursor.execute(
            "SELECT id FROM users WHERE username = %s OR email = %s",
            (username, email)
        )

        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()
            flash("Username or email already exists!")
            return redirect(url_for("register"))

        # Hash password
        hashed_password = generate_password_hash(password)

        # Insert user
        cursor.execute(
            """
            INSERT INTO users (username, email, password)
            VALUES (%s, %s, %s)
            """,
            (username, email, hashed_password)
        )

        mysql.connection.commit()
        cursor.close()

        flash("Registration successful! Please login.")
        return redirect(url_for("login"))

    return render_template("register.html")


# Login
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"].strip()
        password = request.form["password"]

        cursor = mysql.connection.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE email = %s",
            (email,)
        )

        user = cursor.fetchone()
        cursor.close()

        if user and check_password_hash(user[3], password):

            session["user_id"] = user[0]
            session["username"] = user[1]
            session["role"] = user[4]

            return redirect(url_for("dashboard"))

        flash("Invalid email or password!")

    return render_template("login.html")


# Dashboard
@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        username=session["username"]
    )


# Logout
@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.")

    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)