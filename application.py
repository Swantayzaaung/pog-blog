#!/usr/bin/python3
import os

from cs50 import SQL
from flask import Flask, flash, get_flashed_messages, redirect, render_template, request, session
from flask_session import Session
from functools import wraps
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from socket import socket, AF_INET, SOCK_DGRAM 
from time import time
from helpers import apology, login_required, unix_to_date, unix_to_time

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Create a filter for timestamps
app.jinja_env.filters["unix_to_date"] = unix_to_date
app.jinja_env.filters["unix_to_time"] = unix_to_time

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///pogblog.db")


@app.route("/")
@login_required
def index():
    """Show main page of the blog"""
    username = db.execute("SELECT username FROM users WHERE id = :userid", userid=session["user_id"])[0]["username"]
    posts = db.execute("SELECT users.username, posts.title, posts.content, posts.time\
                        FROM users INNER JOIN posts ON users.id = posts.user\
                        ORDER BY posts.time DESC;")
    return render_template("index.html", username=username, posts=posts)


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    """Show the user's account page"""
    
    # Change username and password
    if request.method == "POST":
        # Old user data
        userdata = db.execute("SELECT username, hash FROM users WHERE id = :userid", userid=session["user_id"])
        old_name = userdata[0]["username"]
        old_pw = userdata[0]["hash"]

        # Get new username, password and password confirm
        nameinput = request.form.get("username")
        confirm1 = request.form.get("confirm1")
        password = request.form.get("password")
        confirm2 = request.form.get("confirm2")

        # Change username
        if not password and not confirm2:
            # Validate the data entered
            if not nameinput:
                return apology("Missing username")
            if not confirm1:
                return apology("Missing password confirm")
            if not check_password_hash(old_pw, confirm1):
                return apology("Passwords do not match")
            if nameinput == old_name:
                return apology("New username cannot be the same as the old one")
            rows = db.execute("SELECT * FROM users WHERE username=?", nameinput)
            if len(rows) != 0:
                return apology("Username already exists")
            db.execute("UPDATE users SET username = :username WHERE id = :userid",\
                        username=nameinput, userid=session["user_id"])
            return redirect("/")
        
        # Change password
        elif not nameinput and not confirm1:
            # Validate the data entered
            if not password:
                return apology("Missing password")
            if not confirm2:
                return apology("Missing password confirm")
            if len(password) < 8:
                return apology("Password must be at least 8 characters long")
            if not check_password_hash(old_pw, confirm2):
                return apology("Passwords do not match")
            if check_password_hash(old_pw, password):
                return apology("New password cannot be the same as the old one")
            db.execute("UPDATE users SET hash = :pw_hash WHERE id = :userid",\
                        pw_hash=generate_password_hash(password), userid=session["user_id"])
            return redirect("/")

    # Get the username, password length and post data
    username = db.execute("SELECT username FROM users WHERE id = :userid", userid=session["user_id"])[0]["username"]
    password = "*" * db.execute("SELECT pw_len FROM users WHERE id = :userid", userid=session["user_id"])[0]["pw_len"]
    userposts = db.execute("SELECT id, title, content, time FROM posts\
                            WHERE user = :userid ORDER BY time DESC", userid=session["user_id"])
    # print("\033[1;32m", username, "\033[1;33m", password, "\033[1;34m", userposts, "\033[0;31m")
    return render_template("account.html", username=username, userposts=userposts, password=password)

@app.route("/about")
def about():
    """Show information about the blog"""
    return render_template("about.html")


@app.route("/delete", methods=["POST"])
def delete():
    """Delete user's posts"""
    if request.method == "POST":
        postid = request.form.get("postid")
        db.execute("DELETE FROM posts WHERE id=:postid", postid=postid)
        # print("\033[1;35m", postid)
        return redirect("/account")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    error = ""
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("Please enter a username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("Please enter a password", 403)
            
        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("Invalid username or password", 403)
            
        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""
    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/search", methods=["GET", "POST"])
@login_required
def search():
    """Show a page where user can search posts"""
    if request.method == "POST":
        term = str(request.form.get("term"))
        posts = db.execute("SELECT users.username, posts.title, posts.content, posts.time\
                            FROM users INNER JOIN posts ON users.id = posts.user\
                            WHERE posts.title LIKE ? OR posts.content LIKE ?\
                            ORDER BY posts.time DESC;", "%" + term + "%", "%" + term + "%")
    return render_template("search.html", term=term, posts=posts)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Confirm the username and password
        # Get username and password
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Check for missing username or password
        if not username or not password or not confirmation:
            return apology("Missing name or password", 400)
        # Check if passwords match
        if password != confirmation:
            return apology("Passwords don't match", 400)
        # Check if username exists
        rows = db.execute("SELECT * FROM users WHERE username=?", username)
        # Check if password is a certain length 
        if len(password) < 8:
            return apology("Password must be at least 8 characters long")
        if len(rows) == 0:
            # Hash the password
            password_hash = generate_password_hash(password)
            # Insert the user into the table
            userindex = db.execute("INSERT INTO users (username, hash, pw_len)\
                                    VALUES (:username, :hash, :pw_len)", username=username, hash=password_hash, pw_len=len(password))
            session["user_id"] = userindex
        else:
            return apology("User already exists", 400)
        
        return redirect("/")

    else:
        # Display registration form
        return render_template("register.html")


@app.route("/write", methods=["GET", "POST"])
@login_required
def write():
    """Show a page where user can write a post"""
    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")
        db.execute("INSERT INTO posts (user, title, content, time)\
                    VALUES (:userid, :title, :content, :unixepoch);",\
                    userid=session["user_id"], title=title, content=content, unixepoch=time())
        return redirect("/")
    else:
        return render_template("write.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

# Run the flask server on the local network
if __name__ == '__main__':
    # Find the device IP - Credit: https://www.delftstack.com/howto/python/get-ip-address-python/
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.connect(("8.8.8.8", 80))
    ip_addr = sock.getsockname()[0]
    app.run(host=ip_addr, port=5000, debug=True, threaded=True)