import secrets
import os
from datetime import datetime, timedelta

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy

import Diffie_hellman as dh
import Totp as totp

app = Flask(__name__)
app.secret_key = "super_secure_bifrost_key"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///bifrost.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


# --- DATABASE MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    shared_secret = db.Column(db.String(500), nullable=False)


class PendingExchange(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    alice_private = db.Column(db.String(500), nullable=False)
    alice_public = db.Column(db.String(500), nullable=False)
    exchange_code = db.Column(db.String(6), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)


with app.app_context():
    db.create_all()


def to_hex_be(num):
    return hex(int(num))[2:]


def from_hex_be(hex_str):
    return int(hex_str, 16)


@app.route("/")
def home():
    if "user" in session:
        return render_template("index.html", user=session["user"])
    return render_template("index.html", user=None)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists. Please choose a different one.", "danger")
            return redirect(url_for("signup"))

        # Clean up any existing pending exchanges for this user (Only 1 allowed)
        PendingExchange.query.filter_by(username=username).delete()

        # Generate Alice's Keys and a 6-digit endpoint code
        alice_private, alice_public = dh.generate_keys()
        exchange_code = str(secrets.randbelow(1000000)).zfill(6)

        # Store in pending database, expires in 5 minutes
        pending = PendingExchange(
            username=username,
            password=password,
            alice_private=str(alice_private),
            alice_public=str(alice_public),
            exchange_code=exchange_code,
            expires_at=datetime.utcnow() + timedelta(minutes=5),
        )
        db.session.add(pending)
        db.session.commit()

        # Save username in session so the browser knows who to poll for
        session["pending_username"] = username

        # Render the waiting screen with the code
        return render_template("signup_waiting.html", exchange_code=exchange_code)

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.args.get("success") == "1":
        flash("Exchange Successful! Please log in.", "success")

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session["pending_user"] = username
            return redirect(url_for("verify_totp"))

        flash("Invalid username or password. Please try again.", "danger")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/verify-totp", methods=["GET", "POST"])
def verify_totp():
    if "pending_user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        user_otp = request.form.get("otp")
        username = session["pending_user"]

        user = User.query.filter_by(username=username).first()
        expected_otp = totp.generate_totp(user.shared_secret)

        print(f"Expected OTP: {expected_otp}")

        if user_otp == expected_otp:
            session["user"] = session.pop("pending_user")
            return redirect(url_for("home"))

        flash("Invalid TOTP code. Please check your Bifrost and try again.", "danger")
        return redirect(url_for("verify_totp"))

    return render_template("verify_totp.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/signup/<code>", methods=["POST"])
def bifrost_exchange(code):
    # Clean up globally expired endpoints to keep DB clean
    PendingExchange.query.filter(
        PendingExchange.expires_at < datetime.utcnow()
    ).delete()
    db.session.commit()

    # Look for the specific code
    pending = PendingExchange.query.filter_by(exchange_code=code).first()

    if not pending:
        return jsonify(
            {"status": "fail", "error": "Endpoint does not exist or has expired"}
        ), 404

    data = request.get_json()
    if not data or "bifrost-public-key" not in data:
        return jsonify({"status": "fail", "error": "Missing bifrost-public-key"}), 400

    try:
        # Perform the DH Math using Big-Endian Hex conversion
        bob_public = from_hex_be(data["bifrost-public-key"])
        alice_private = int(pending.alice_private)

        shared_secret = dh.compute_shared_secret(bob_public, alice_private, dh.P)

        # Save the finalized user to the permanent database
        new_user = User(
            username=pending.username,
            password=pending.password,
            shared_secret=str(shared_secret),
        )
        db.session.add(new_user)

        # Destroy the temporary endpoint
        db.session.delete(pending)
        db.session.commit()

        print(f"bifrost public key: {to_hex_be(bob_public)}")
        print(f"server public key: {to_hex_be(pending.alice_public)}")
        print(f"shared secret: {hex(shared_secret)}")

        return jsonify(
            {"server-public-key": to_hex_be(pending.alice_public), "status": "success"}
        )

    except Exception as e:
        return jsonify({"status": "fail", "error": str(e)}), 500


@app.route("/api/status/<code>", methods=["GET"])
def check_status(code):
    username = session.get("pending_username")
    if not username:
        return jsonify({"status": "error"})

    # If the user is in the main DB, the exchange succeeded
    if User.query.filter_by(username=username).first():
        session.pop("pending_username", None)
        return jsonify({"status": "success"})

    # Check if the pending endpoint still exists and hasn't expired
    pending = PendingExchange.query.filter_by(exchange_code=code).first()
    if pending and pending.expires_at > datetime.utcnow():
        return jsonify({"status": "waiting"})

    return jsonify({"status": "expired"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
