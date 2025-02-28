"""
CypherVault Application
-----------------------
A Flask application for secure file storage and sharing.
Features include:
 • User registration and login
 • File encryption/decryption using AES
 • Password recovery (for both login and file passwords)
 • File upload/download with GridFS storage
 • File sharing with access requests and notifications
"""

import os
import base64
import mimetypes
from io import BytesIO

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, send_file, flash, abort, send_from_directory
)
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from pymongo import MongoClient
from bson.objectid import ObjectId
from gridfs import GridFS
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from datetime import datetime, timedelta
from bson.objectid import ObjectId
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2

# ---------------------- Configuration ---------------------- #

MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
SECRET_KEY = os.environ.get('SECRET_KEY', 'pranes@23')

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.secret_key = SECRET_KEY

# Email configuration (adjust these for your email provider)
app.config.update(
    MAIL_SERVER='smtp.gmail.com',  # e.g. Gmail SMTP
    MAIL_PORT=587,
    MAIL_USE_TLS=True,
    MAIL_USERNAME='praneswara2003@gmail.com',
    MAIL_PASSWORD='spkl ysud nygk xkne'
)
mail = Mail(app)
serializer = URLSafeTimedSerializer(SECRET_KEY)
file_reset_serializer = URLSafeTimedSerializer(SECRET_KEY)

# ---------------------- Database Setup ---------------------- #

client = MongoClient(MONGO_URI)
db = client['secure_file_storage']
fs = GridFS(db)  # For file data storage in Atlas

# Other collections (for sharing flow)
access_requests = db['access_requests']
shared_files = db['shared_files']

# ---------------------- Helper Functions ---------------------- #



def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=32)

def encrypt_recovery(file_password, login_password):
    """
    Encrypts the file password using a key derived from the login password.
    Returns salt (16 bytes) + IV (16 bytes) + ciphertext.
    """
    salt = os.urandom(16)
    key = PBKDF2(login_password, salt, dkLen=32)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(file_password.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return salt + iv + ciphertext

def decrypt_recovery(encrypted_recovery, login_password):
    """
    Decrypts the recoverable file password using the login password.
    Returns the original file password as a string.
    """
    salt = encrypted_recovery[:16]
    iv = encrypted_recovery[16:32]
    ciphertext = encrypted_recovery[32:]
    key = PBKDF2(login_password, salt, dkLen=32)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, AES.block_size).decode('utf-8')

def encrypt_data(data, file_password):
    salt = os.urandom(16)
    key = derive_key(file_password, salt)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return salt + iv + ciphertext

def decrypt_data(encrypted_data, file_password):
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    key = derive_key(file_password, salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, AES.block_size)

def reencrypt_user_files(username, old_file_password, new_file_password):
    """
    For each file belonging to the user:
      - Retrieve the encrypted data from GridFS.
      - Decrypt using the old file password.
      - Encrypt with the new file password.
      - Delete the old GridFS file and update metadata with the new GridFS file id.
    """
    files = list(db.files.find({'username': username}))
    for file_meta in files:
        file_id = file_meta['gridfs_id']
        try:
            file_obj = fs.get(file_id)
            encrypted_data = file_obj.read()
            decrypted_data = decrypt_data(encrypted_data, old_file_password)
            new_encrypted_data = encrypt_data(decrypted_data, new_file_password)
            fs.delete(file_id)
            new_file_id = fs.put(new_encrypted_data, filename=file_meta['filename'], owner=username)
            db.files.update_one({'_id': file_meta['_id']}, {'$set': {'gridfs_id': new_file_id}})
        except Exception as e:
            print(f"Error re-encrypting file {file_meta['filename']}: {e}")

# ---------------------- Routes ---------------------- #

@app.route('/')
def index():
    return render_template('index.html')

# ----- Registration Route -----
@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register a new user, send confirmation email, and redirect to email confirmation page."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']

        # Check if the username or email is already taken
        if db.users.find_one({'username': username}):
            flash("Username already taken.", "error")
            return render_template('register.html')

        if db.users.find_one({'email': email}):
            flash("Email already registered.", "error")
            return render_template('register.html')

        # Hash password and insert user into the database
        hashed_pw = generate_password_hash(password)
        db.users.insert_one({
            'username': username,
            'password': hashed_pw,
            'email': email,
            'email_verified': False
        })

        # Store user session data
        session['username'] = username
        session['email'] = email

        # Generate email confirmation token
        token = serializer.dumps(email, salt='email-confirm-salt')
        confirm_url = url_for('confirm_email', token=token, _external=True)

        # Send confirmation email
        msg = Message("Confirm Your Email – ZypherVault",
                      sender=app.config['MAIL_USERNAME'],
                      recipients=[email])
        msg.body = f"""Dear {username},

We received a request to register with ZypherVault.
Please confirm your email by visiting the following link:
{confirm_url}

If you didn’t register, you can safely ignore this email. This link will expire in 60 minutes for security reasons.

Stay secure,
The ZypherVault Team
"""
        msg.html = f"""
<html>
  <body>
    <p>Dear {username},</p>
    <p>We received a request to register with ZypherVault. Please confirm your email by clicking the button below:</p>
    <p style="text-align: center;">
      <a href="{confirm_url}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Confirm Email</a>
    </p>
    <p>If you didn’t register, you can safely ignore this email. This link will expire in 60 minutes for security reasons.</p>
    <p>Stay secure,<br>The ZypherVault Team</p>
  </body>
</html>
"""
        mail.send(msg)

        flash("A confirmation email has been sent. Please check your email.", "success")
        return render_template('email_confirmation.html', email=email)

    return render_template('register.html')              




# ----- Confirm Email Route -----
@app.route('/confirm_email/<token>')
def confirm_email(token):
    """Marks the user's email as verified when they click the link in the email."""
    try:
        email = serializer.loads(token, salt='email-confirm-salt', max_age=3600)
    except (SignatureExpired, BadSignature):
        return "The confirmation link is invalid or has expired.", 400
    
    db.users.update_one({'email': email}, {'$set': {'email_verified': True}})
    # Return a simple message; the user can close this tab.
    return "Email confirmed successfully. You may now close this tab."

@app.route('/resend_confirmation', methods=['POST'])
def resend_confirmation():
    """Resend the email confirmation link using an updated email from the form."""
    # Get the email from the form (the user-entered email)
    new_email = request.form.get('email')
    if not new_email:
        flash("Please enter an email address.", "error")
        return redirect(url_for('register'))
    
    email = new_email.strip()
    print("DEBUG: New email entered:", email)
    
    # Find the user based on the username stored in session.
    user = db.users.find_one({'username': session.get('username')})
    if not user:
        flash("User not found. Please register again.", "error")
        return redirect(url_for('register'))
    
    # If the email in the DB is different from the new email, update it.
    if user.get('email') != email:
        result = db.users.update_one({'_id': user['_id']}, {'$set': {'email': email}})
        print("DEBUG: DB update modified count:", result.modified_count)
    
    # Update the session with the new email.
    session['email'] = email

    # Retrieve the updated user record.
    user = db.users.find_one({'username': session.get('username')})
    if user.get('email_verified'):
        flash("Your email is already verified.", "success")
        return redirect(url_for('login'))

    # Generate a new confirmation token using the updated email.
    token = serializer.dumps(email, salt='email-confirm-salt')
    confirm_url = url_for('confirm_email', token=token, _external=True)
    print("DEBUG: Sending confirmation email to:", email)
    print("DEBUG: Confirmation URL:", confirm_url)

    # Compose and send the confirmation email.
    msg = Message("Confirm Your Email – ZypherVault",
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[email])
    msg.body = f"""Dear {user['username']},

Please confirm your email by visiting the following link:
{confirm_url}

If you didn’t request this, you can safely ignore this email.

Stay secure,
The ZypherVault Team
"""
    msg.html = f"""
<html>
  <body>
    <p>Dear {user['username']},</p>
    <p>Please confirm your email by clicking the button below:</p>
    <p style="text-align: center;">
      <a href="{confirm_url}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Confirm Email</a>
    </p>
    <p>If you didn’t request this, you can safely ignore this email.</p>
    <p>Stay secure,<br>The ZypherVault Team</p>
  </body>
</html>
"""
    mail.send(msg)

    flash("A new confirmation email has been sent.", "success")
    return render_template('email_confirmation.html', email=email)



@app.route('/check_verification')
def check_verification():
    email = request.args.get('email')
    user = db.users.find_one({'email': email})
    if user and user.get('email_verified'):
        return {"verified": True}
    return {"verified": False}


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = db.users.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            if not user.get('email_verified', False):
                flash("Please verify your email before logging in.", "error")
                return redirect(url_for('login'))
            session['username'] = username
            session['user_id'] = str(user['_id'])
            return redirect(url_for('home'))
        else:
            flash("Invalid credentials", "error")
    return render_template('login.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form.get('email')
        user = db.users.find_one({'email': email})
        if user:
            token = serializer.dumps(email, salt='password-reset-salt')
            reset_url = url_for('reset_password_token', token=token, _external=True)
            msg = Message("Reset Your Password – CypherVault",
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[email])
            user_name = user.get('username', 'User')
            msg.body = f"""Dear {user_name},

We received a request to reset your CypherVault password. If you made this request, please visit the following link to reset your password:
{reset_url}

If you didn’t request this, you can safely ignore this email. This link will expire in 60 minutes for security reasons.

Stay secure,
The CypherVault Team
"""
            msg.html = f"""
<html>
  <body>
    <p>Dear {user_name},</p>
    <p>We received a request to reset your CypherVault password. If you made this request, click the button below to securely reset your password.</p>
    <p style="text-align: center;">
      <a href="{reset_url}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a>
    </p>
    <p>If you didn’t request this, you can safely ignore this email. This link will expire in 60 minutes for security reasons.</p>
    <p>Stay secure,<br>The CypherVault Team</p>
  </body>
</html>
"""
            mail.send(msg)
            flash("A password reset link has been sent to your email.", "success")
            return redirect(url_for('login'))
        else:
            flash("No account found with that email.", "error")
            return render_template('reset_password_request.html')
    return render_template('reset_password_request.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        flash("The reset link has expired.", "error")
        return redirect(url_for('reset_password_request'))
    except BadSignature:
        flash("Invalid reset token.", "error")
        return redirect(url_for('reset_password_request'))
    
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        hashed_pw = generate_password_hash(new_password)
        db.users.update_one({'email': email}, {'$set': {'password': hashed_pw}})
        flash("Your password has been updated.", "success")
        return redirect(url_for('login'))
    
    return render_template('reset_password_token.html', token=token)

@app.route('/home')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    unread_count = db.access_requests.count_documents({
        'sender': session['username'],
        'read': False
    })
    unread_pending = db.shared_files.count_documents({
        'recipient_username': session['username'],
        'status': 'pending',
        'read_pending': False
    })
    unread_approved = db.shared_files.count_documents({
        'recipient_username': session['username'],
        'status': 'approved',
        'read_approved': False
    })
    return render_template('home.html',
                           unread_count=unread_count,
                           unread_pending=unread_pending,
                           unread_approved=unread_approved)

# List only active (non-deleted) files on My Files page.
@app.route('/files', endpoint='list_files')
def list_files():
    if 'username' not in session:
        return redirect(url_for('login'))
    user_files = list(db.files.find({
        'username': session['username'],
        'deleted': {"$ne": True}
    }))
    return render_template('files.html', user_files=user_files)


@app.route('/set_file_password', methods=['GET', 'POST'])
def set_file_password():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        file_password = request.form['file_password']
        login_password = request.form['login_password']  # From form
        user = db.users.find_one({'username': session['username']})
        if not check_password_hash(user['password'], login_password):
            flash("Login password is incorrect.", "error")
            return redirect(url_for('set_file_password'))
        hashed_fp = generate_password_hash(file_password)
        recoverable = encrypt_recovery(file_password, login_password)
        db.users.update_one({'username': session['username']},
                            {'$set': {'file_password': hashed_fp,
                                      'recoverable_file_password': recoverable}})
        flash("File password set successfully.", "success")
        return redirect(url_for('home'))
    return render_template('set_file_password.html')

@app.route('/forgot_file_password_email', methods=['GET', 'POST'])
def forgot_file_password_email():
    if request.method == 'POST':
        email = request.form.get('email')
        # If the user is logged in, ensure the entered email matches the logged-in user's email.
        if session.get('username'):
            current_user = db.users.find_one({'username': session['username']})
            if current_user.get('email') != email:
                flash("Please enter your own email address.", "error")
                return render_template('forgot_file_password_email.html')
            user = current_user
        else:
            # If not logged in, search for the user by email.
            user = db.users.find_one({'email': email})
        
        if user:
            token = file_reset_serializer.dumps(user['username'], salt='file-reset-salt')
            reset_url = url_for('reset_file_password_by_email', token=token, _external=True)
            msg = Message("Reset Your File Password – CypherVault",
                          sender=app.config['MAIL_USERNAME'],
                          recipients=[email])
            msg.body = f"""Dear {user.get('username', 'User')},

A request was made to reset your encrypted file password in CypherVault.
Please click the following link to reset your file password:
{reset_url}

If you didn’t request this, please ignore this email. This link is valid for 60 minutes to ensure security.

Need help? Contact our support team anytime.

Best,
The CypherVault Team
"""
            msg.html = f"""
<html>
  <body>
    <p>Dear {user.get('username', 'User')},</p>
    <p>A request was made to reset your encrypted file password in CypherVault. Click the button below to proceed with resetting your file password.</p>
    <p style="text-align: center;">
      <a href="{reset_url}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset File Password</a>
    </p>
    <p>If you didn’t request this, please ignore this email. This link is valid for 60 minutes to ensure security.</p>
    <p>Need help? Contact our support team anytime.</p>
    <p>Best,<br>The CypherVault Team</p>
  </body>
</html>
"""
            mail.send(msg)
            flash("A file password reset link has been sent to your email.", "success")
            return redirect(url_for('home'))
        else:
            flash("Email address does not match our records.", "error")
            return render_template('forgot_file_password_email.html')
    return render_template('forgot_file_password_email.html')




@app.route('/reset_file_password_by_email/<token>', methods=['GET', 'POST'])
def reset_file_password_by_email(token):
    try:
        username = file_reset_serializer.loads(token, salt='file-reset-salt', max_age=3600)
    except (SignatureExpired, BadSignature):
        flash("The reset link is invalid or has expired.", "error")
        return redirect(url_for('forgot_file_password_email'))
    if request.method == 'POST':
        new_file_password = request.form.get('new_file_password')
        login_password = request.form.get('login_password')
        user = db.users.find_one({'username': username})
        if not user or not check_password_hash(user['password'], login_password):
            flash("Login password is incorrect.", "error")
            return redirect(url_for('reset_file_password_by_email', token=token))
        try:
            old_file_password = decrypt_recovery(user['recoverable_file_password'], login_password)
        except Exception as e:
            flash("Failed to recover old file password: " + str(e), "error")
            return redirect(url_for('reset_file_password_by_email', token=token))
        reencrypt_user_files(username, old_file_password, new_file_password)
        new_hash = generate_password_hash(new_file_password)
        new_recoverable = encrypt_recovery(new_file_password, login_password)
        db.users.update_one({'username': username},
                            {'$set': {'file_password': new_hash,
                                      'recoverable_file_password': new_recoverable}})
        db.shared_files.update_many({'sender': username},
                                    {'$set': {'sender_file_password': new_file_password}})
        flash("File password reset successfully. All files have been re-encrypted.", "success")
        return redirect(url_for('login'))
    return render_template('reset_file_password_by_email.html', token=token)

@app.route('/reset_file_password/<token>', methods=['GET', 'POST'])
def reset_file_password(token):
    """
    Allows the user to set a new file password using a secure token.
    WARNING: Changing the file password may render previously encrypted files inaccessible.
    """
    try:
        username = file_reset_serializer.loads(token, salt='file-reset-salt', max_age=3600)
    except (SignatureExpired, BadSignature):
        flash("The reset link is invalid or has expired.", "error")
        return redirect(url_for('forgot_file_password'))
    if request.method == 'POST':
        new_file_password = request.form.get('new_file_password')
        hashed_new = generate_password_hash(new_file_password)
        db.users.update_one({'username': username}, {'$set': {'file_password': hashed_new}})
        flash("Your file password has been updated.", "success")
        return redirect(url_for('home'))
    return render_template('reset_file_password.html', token=token)

@app.route('/reset_file_password_options')
def reset_file_password_options():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('reset_file_password_options.html')

@app.route('/change_file_password', methods=['GET', 'POST'])
def change_file_password():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        old_file_password = request.form.get('old_file_password')
        new_file_password = request.form.get('new_file_password')
        login_password = request.form.get('login_password')
        user = db.users.find_one({'username': session['username']})
        if not user or not check_password_hash(user['file_password'], old_file_password):
            flash("Old file password is incorrect.", "error")
            return redirect(url_for('change_file_password'))
        if not check_password_hash(user['password'], login_password):
            flash("Login password is incorrect.", "error")
            return redirect(url_for('change_file_password'))
        reencrypt_user_files(session['username'], old_file_password, new_file_password)
        new_hash = generate_password_hash(new_file_password)
        new_recoverable = encrypt_recovery(new_file_password, login_password)
        db.users.update_one({'username': session['username']},
                            {'$set': {'file_password': new_hash,
                                      'recoverable_file_password': new_recoverable}})
        db.shared_files.update_many({'sender': session['username']},
                                    {'$set': {'sender_file_password': new_file_password}})
        flash("File password changed and files re-encrypted.", "success")
        return redirect(url_for('home'))
    return render_template('change_file_password.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """
    Upload a file, encrypt it with the user's file password,
    store encrypted data in GridFS, and save metadata in db.files.
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        user = db.users.find_one({'username': session['username']})
        if not user:
            flash("User not found.", "error")
            return redirect(url_for('login'))
        file_password = request.form.get('file_password')
        if 'file_password' not in user or not check_password_hash(user['file_password'], file_password):
            flash("Invalid file password.", "error")
            return redirect(url_for('upload_file'))
        uploaded_file = request.files['file']
        if uploaded_file:
            filename = secure_filename(uploaded_file.filename)
            data = uploaded_file.read()
            encrypted_data = encrypt_data(data, file_password)
            file_id = fs.put(encrypted_data, filename=filename, owner=session['username'])
            db.files.insert_one({
                'username': session['username'],
                'filename': filename,
                'gridfs_id': file_id
            })
            flash("File uploaded and encrypted.", "success")
            return redirect(url_for('upload_file'))
    return render_template('upload.html')


# Soft-delete a file: mark it as deleted with a deletion timestamp.
@app.route('/soft_delete_file/<file_id>', methods=['POST'])
def soft_delete_file(file_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    file_meta = db.files.find_one({
        '_id': ObjectId(file_id),
        'username': session['username'],
        'deleted': {"$ne": True}
    })
    if not file_meta:
        flash("File not found or already deleted.", "error")
        return redirect(url_for('list_files'))
    try:
        db.files.update_one(
            {'_id': file_meta['_id']},
            {'$set': {'deleted': True, 'deleted_at': datetime.utcnow()}}
        )
        flash("File moved to Restore Items. You can restore it within 30 days.", "success")
    except Exception as e:
        flash(f"Error deleting file: {str(e)}", "error")
    return redirect(url_for('list_files'))
@app.route('/restore_items')
def restore_items():
    if 'username' not in session:
        return redirect(url_for('login'))
    cutoff_date = datetime.utcnow() - timedelta(days=30)
    # Permanently delete files older than 30 days.
    expired_files = db.files.find({
        'username': session['username'],
        'deleted': True,
        'deleted_at': {"$lt": cutoff_date}
    })
    for file in expired_files:
        try:
            fs.delete(file['gridfs_id'])
        except Exception as e:
            print(f"Error deleting GridFS file: {e}")
        db.files.delete_one({'_id': file['_id']})
    # Retrieve remaining deleted files.
    deleted_files = list(db.files.find({
        'username': session['username'],
        'deleted': True,
        'deleted_at': {"$gte": cutoff_date}
    }))
    # For each file, calculate remaining days until permanent deletion.
    for file in deleted_files:
        deleted_at = file.get('deleted_at')
        if deleted_at:
            remaining = timedelta(days=30) - (datetime.utcnow() - deleted_at)
            file['days_remaining'] = max(remaining.days, 0)
        else:
            file['days_remaining'] = 30
    return render_template('restore_items.html', deleted_files=deleted_files)

# Restore a single file (remove deleted flag).
@app.route('/restore_file/<file_id>', methods=['POST'])
def restore_file(file_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    file_meta = db.files.find_one({
        '_id': ObjectId(file_id),
        'username': session['username'],
        'deleted': True
    })
    if not file_meta:
        flash("File not found or cannot be restored.", "error")
        return redirect(url_for('restore_items'))
    try:
        db.files.update_one(
            {'_id': file_meta['_id']},
            {'$unset': {'deleted_at': ""}, '$set': {'deleted': False}}
        )
        flash("File restored successfully.", "success")
    except Exception as e:
        flash(f"Error restoring file: {str(e)}", "error")
    return redirect(url_for('restore_items'))

# Permanently delete a single file from Restore Items.
@app.route('/permanent_delete_file/<file_id>', methods=['POST'])
def permanent_delete_file(file_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    file_meta = db.files.find_one({
        '_id': ObjectId(file_id),
        'username': session['username'],
        'deleted': True
    })
    if not file_meta:
        flash("File not found.", "error")
        return redirect(url_for('restore_items'))
    try:
        fs.delete(file_meta['gridfs_id'])
        db.files.delete_one({'_id': file_meta['_id']})
        flash("File permanently deleted.", "success")
    except Exception as e:
        flash(f"Error permanently deleting file: {str(e)}", "error")
    return redirect(url_for('restore_items'))

# Permanently delete all files in Restore Items.
@app.route('/delete_all_restore', methods=['POST'])
def delete_all_restore():
    if 'username' not in session:
        return redirect(url_for('login'))
    deleted_files = list(db.files.find({
        'username': session['username'],
        'deleted': True
    }))
    for file in deleted_files:
        try:
            fs.delete(file['gridfs_id'])
        except Exception as e:
            print(f"Error deleting GridFS file: {e}")
        db.files.delete_one({'_id': file['_id']})
    flash("All restore items have been permanently deleted.", "success")
    return redirect(url_for('restore_items'))


@app.route('/download/<filename>', methods=['GET', 'POST'])
def download_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    user = db.users.find_one({'username': session['username']})
    if 'file_password' not in user:
        flash("File password not set.", "error")
        return redirect(url_for('set_file_password'))
    if request.method == 'GET':
        return render_template('enter_file_password.html', filename=filename, action_url=url_for('download_file', filename=filename))
    else:
        file_password = request.form.get('file_password')
        if not check_password_hash(user['file_password'], file_password):
            flash("Incorrect file password.", "error")
            return redirect(url_for('download_file', filename=filename))
        file_meta = db.files.find_one({'username': session['username'], 'filename': filename})
        if not file_meta:
            flash("File metadata not found.", "error")
            return redirect(url_for('list_files'))
        file_id = file_meta['gridfs_id']
        encrypted_data = fs.get(file_id).read()
        try:
            decrypted_data = decrypt_data(encrypted_data, file_password)
            mime, _ = mimetypes.guess_type(filename)
            if mime is None:
                mime = 'application/octet-stream'
            # Encode the decrypted data in Base64
            decrypted_data_base64 = base64.b64encode(decrypted_data).decode('utf-8')
            # Render the file view template that extends base.html
            return render_template("file_view.html", filename=filename, decrypted_data_base64=decrypted_data_base64, mime=mime, back_url=url_for('list_files'))
        except Exception as e:
            flash("Decryption failed: " + str(e), "error")
            return redirect(url_for('download_file', filename=filename))
        
@app.route('/share', methods=['GET', 'POST'])
def share():
    """
    Sender shares a file with a recipient.
    The shared_files document is created with status 'pending'.
    (For demo purposes, the sender's plaintext file password is stored.)
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    user_files = list(db.files.find({'username': session['username']}))
    if request.method == 'POST':
        recipient_username = request.form.get('recipient_username')
        file_password = request.form.get('file_password')
        filename = request.form.get('filename')
        recipient = db.users.find_one({'username': recipient_username})
        if not recipient:
            flash("Recipient is not registered.", "error")
            return render_template('share.html', user_files=user_files)
        sender = db.users.find_one({'username': session['username']})
        if 'file_password' not in sender or not check_password_hash(sender['file_password'], file_password):
            flash("Invalid file password.", "error")
            return render_template('share.html', user_files=user_files)
        file_meta = db.files.find_one({'username': session['username'], 'filename': filename})
        if not file_meta:
            flash("File not found.", "error")
            return render_template('share.html', user_files=user_files)
        shared_file_id = ObjectId()
        db.shared_files.insert_one({
            '_id': shared_file_id,
            'sender': session['username'],
            'recipient_username': recipient_username,
            'filename': filename,
            'gridfs_id': file_meta['gridfs_id'],
            'status': 'pending',
            'sender_file_password': file_password, 
            'read_pending': False,
            'read_approved': False
        })
        flash(f"File shared with {recipient_username}.", "success")
    return render_template('share.html', user_files=user_files)

@app.route('/received_files')
def received_files():
    if 'username' not in session:
        return redirect(url_for('login'))
    rec_files = list(db.shared_files.find({'recipient_username': session['username']}))
    # Mark notifications as read
    db.shared_files.update_many(
        {'recipient_username': session['username'], 'status': 'pending', 'read_pending': False},
        {'$set': {'read_pending': True}}
    )
    db.shared_files.update_many(
        {'recipient_username': session['username'], 'status': 'approved', 'read_approved': False},
        {'$set': {'read_approved': True}}
    )
    return render_template('received_files.html', received_files=rec_files)


@app.route('/request_enter_file_password/<shared_file_id>', methods=['GET', 'POST'])
def request_enter_file_password(shared_file_id):
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        file_password = request.form.get('file_password')
        shared_file = db.shared_files.find_one({'_id': ObjectId(shared_file_id)})
        if not shared_file:
            flash("Shared file not found.", "error")
            return redirect(url_for('received_files'))
        receiver = db.users.find_one({'username': session['username']})
        if receiver and 'file_password' in receiver and check_password_hash(receiver['file_password'], file_password):
            db.shared_files.update_one({'_id': ObjectId(shared_file_id)}, {'$set': {'status': 'in_progress'}})
            notif_id = ObjectId()
            db.access_requests.insert_one({
                '_id': notif_id,
                'sender': shared_file['sender'],
                'recipient_username': shared_file['recipient_username'],
                'filename': shared_file['filename'],
                'shared_file_id': shared_file_id,
                'status': 'pending',
                'read': False
            })
            flash("Access request sent to the sender.", "success")
            return redirect(url_for('received_files'))
        else:
            flash("Invalid file password.", "error")
            return redirect(url_for('request_enter_file_password', shared_file_id=shared_file_id))
    return render_template('request_enter_file_password.html', shared_file_id=shared_file_id)

@app.route('/notifications')
def notifications():
    if 'username' not in session:
        return redirect(url_for('login'))
    sender = session['username']
    notifs = list(db.access_requests.find({'sender': sender}))
    # Optionally, mark all unread notifications as read
    db.access_requests.update_many({'sender': sender, 'read': False}, {'$set': {'read': True}})
    return render_template('notifications.html', notifications=notifs)

@app.route('/allow_access/<notification_id>', methods=['POST'])
def allow_access(notification_id):
    """
    Sender approves an access request: update status to 'approved'.
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    notif = db.access_requests.find_one({'_id': ObjectId(notification_id)})
    shared_file_id = notif['shared_file_id']
    db.shared_files.update_one({'_id': ObjectId(shared_file_id)}, {'$set': {'status': 'approved'}})
    db.access_requests.delete_one({'_id': ObjectId(notification_id)})
    flash("Access approved.", "success")
    return redirect(url_for('notifications'))

@app.route('/deny_access/<notification_id>', methods=['POST'])
def deny_access(notification_id):
    """
    Sender denies an access request: update status back to 'pending'.
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    notif = db.access_requests.find_one({'_id': ObjectId(notification_id)})
    shared_file_id = notif['shared_file_id']
    db.shared_files.update_one({'_id': ObjectId(shared_file_id)}, {'$set': {'status': 'pending'}})
    db.access_requests.delete_one({'_id': ObjectId(notification_id)})
    flash("Access request denied.", "success")
    return redirect(url_for('notifications'))

import base64
from io import BytesIO
import mimetypes

@app.route('/download_file_with_status_check/<filename>', methods=['GET', 'POST'])
def download_file_with_status_check(filename):
    """
    For a shared file that has been approved, the receiver is prompted for their file password.
    After verifying it, the file is decrypted using the sender's stored file password and
    rendered within the base template.
    """
    if 'username' not in session:
        return redirect(url_for('login'))
    
    shared_file = db.shared_files.find_one({
        'filename': filename,
        'recipient_username': session['username']
    })
    if not shared_file:
        abort(404)
    
    status = shared_file.get('status')
    if status == 'pending':
        return redirect(url_for('request_enter_file_password', shared_file_id=shared_file['_id']))
    elif status == 'in_progress':
        flash("Access request already sent. Wait for sender approval.", "info")
        return redirect(url_for('received_files'))
    elif status == 'approved':
        if request.method == 'GET':
            return render_template('enter_receiver_password.html',
                                   filename=filename,
                                   action_url=url_for('download_file_with_status_check', filename=filename))
        else:
            receiver_file_password = request.form.get('file_password')
            receiver = db.users.find_one({'username': session['username']})
            if not receiver or 'file_password' not in receiver or not check_password_hash(receiver['file_password'], receiver_file_password):
                flash("Incorrect receiver file password.", "error")
                return redirect(url_for('download_file_with_status_check', filename=filename))
            sender_file_password = shared_file.get('sender_file_password')
            file_obj = fs.find_one({"filename": filename, "owner": shared_file['sender']})
            if not file_obj:
                flash("Encrypted file not found in GridFS.", "error")
                return redirect(url_for('list_files'))
            encrypted_data = file_obj.read()
            try:
                decrypted_data = decrypt_data(encrypted_data, sender_file_password)
                mime, _ = mimetypes.guess_type(filename)
                if mime is None:
                    mime = 'application/octet-stream'
                # Encode the decrypted data in Base64 so it can be embedded as a data URL.
                decrypted_data_base64 = base64.b64encode(decrypted_data).decode('utf-8')
                # Render a template that extends your base layout.
                return render_template("received_file_view.html",
                                       filename=filename,
                                       decrypted_data_base64=decrypted_data_base64,
                                       mime=mime,
                                       back_url=url_for('received_files'))
            except Exception as e:
                flash("Decryption failed: " + str(e), "error")
                return redirect(url_for('received_files'))
    else:
        abort(404)

from flask import send_file, abort, flash, redirect, url_for, session, make_response
from io import BytesIO
import mimetypes

@app.route('/download_actual_file/<filename>')
def download_actual_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    
    user = db.users.find_one({'username': session['username']})
    # Try fetching file metadata from user's own files
    file_meta = db.files.find_one({'username': session['username'], 'filename': filename})
    if file_meta:
        file_password = user.get('file_password')
        if not file_password:
            flash("File password not set.", "error")
            return redirect(url_for('set_file_password'))
        file_id = file_meta.get('gridfs_id')
        try:
            file_obj = fs.get(file_id)
        except Exception:
            abort(404)
    else:
        # Otherwise, check for a shared file
        shared_file = db.shared_files.find_one({'filename': filename, 'recipient_username': session['username']})
        if not shared_file:
            flash("File not found.", "error")
            return redirect(url_for('list_files'))
        file_password = shared_file.get('sender_file_password')
        file_obj = fs.find_one({"filename": filename, "owner": shared_file['sender']})
        if not file_obj:
            flash("File not found in storage.", "error")
            return redirect(url_for('list_files'))
    
    encrypted_data = file_obj.read()
    try:
        decrypted_data = decrypt_data(encrypted_data, file_password)
        mime, _ = mimetypes.guess_type(filename)
        if mime is None:
            mime = 'application/octet-stream'
        return send_file(
            BytesIO(decrypted_data),
            mimetype=mime,
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        flash("Decryption failed: " + str(e), "error")
        return redirect(url_for('list_files'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/get_file/<filename>')
def get_file(filename):
    if 'username' not in session:
        return redirect(url_for('login'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ---------------------- Application Entry Point ---------------------- #

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(host="0.0.0.0",port=5000,debug=True)


