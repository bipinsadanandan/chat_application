from flask import render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from app import app, db
from models import User, Message, EmailVerification
from crypto_utils import CryptoManager
from email_utils import EmailManager
from firebase_utils import FirebaseManager
import logging

logger = logging.getLogger(__name__)
email_manager = EmailManager(app)
firebase_manager = FirebaseManager()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return render_template('register.html')
        
        # Check if user exists
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'danger')
            return render_template('register.html')
        
        try:
            # Generate RSA keypair
            keypair = CryptoManager.generate_rsa_keypair()
            
            # Create user
            user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                public_key=keypair['public_key'],
                private_key=keypair['private_key']
            )
            
            db.session.add(user)
            db.session.commit()
            
            # Send verification email
            verification = EmailVerification(user_id=user.id)
            db.session.add(verification)
            db.session.commit()
            
            if email_manager.send_otp_email(email, verification.otp_code, username):
                flash('Registration successful! Please check your email for verification code.', 'success')
                session['temp_user_id'] = user.id
                return redirect(url_for('verify_email'))
            else:
                flash('Registration successful, but email verification failed. Please contact support.', 'warning')
                return redirect(url_for('login'))
                
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            flash('Registration failed. Please try again.', 'danger')
            
    return render_template('register.html')

@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    if 'temp_user_id' not in session:
        flash('Invalid verification session.', 'danger')
        return redirect(url_for('register'))
    
    if request.method == 'POST':
        otp_code = request.form.get('otp_code')
        user_id = session['temp_user_id']
        
        verification = EmailVerification.query.filter_by(
            user_id=user_id, 
            otp_code=otp_code, 
            is_used=False
        ).first()
        
        if not verification:
            flash('Invalid verification code.', 'danger')
            return render_template('verify_email.html')
        
        if verification.is_expired():
            flash('Verification code expired. Please register again.', 'danger')
            return redirect(url_for('register'))
        
        # Mark user as verified
        user = User.query.get(user_id)
        user.is_verified = True
        verification.is_used = True
        
        db.session.commit()
        
        session.pop('temp_user_id', None)
        flash('Email verified successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('verify_email.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password_hash, password):
            if not user.is_verified:
                flash('Please verify your email before logging in.', 'warning')
                return render_template('login.html')
            
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    # Get recent messages
    recent_messages = Message.query.filter_by(recipient_id=user.id).order_by(Message.timestamp.desc()).limit(5).all()
    unread_count = Message.query.filter_by(recipient_id=user.id, is_read=False).count()
    
    return render_template('dashboard.html', user=user, recent_messages=recent_messages, unread_count=unread_count)

@app.route('/send-message', methods=['GET', 'POST'])
def send_message():
    if 'user_id' not in session:
        flash('Please log in to send messages.', 'warning')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        recipient_username = request.form.get('recipient_username')
        subject = request.form.get('subject')
        message_content = request.form.get('message_content')
        
        if not recipient_username or not message_content:
            flash('Recipient and message content are required.', 'danger')
            return render_template('send_message.html')
        
        # Find recipient
        recipient = User.query.filter_by(username=recipient_username).first()
        if not recipient:
            flash('Recipient not found.', 'danger')
            return render_template('send_message.html')
        
        if recipient.id == session['user_id']:
            flash('You cannot send a message to yourself.', 'danger')
            return render_template('send_message.html')
        
        try:
            # Encrypt message
            encrypted_content, encrypted_key = CryptoManager.encrypt_message(
                message_content, 
                recipient.public_key
            )
            
            # Create message record
            message = Message(
                sender_id=session['user_id'],
                recipient_id=recipient.id,
                encrypted_content=encrypted_content,
                encrypted_key=encrypted_key,
                subject=subject
            )
            
            db.session.add(message)
            db.session.commit()
            
            # Store backup in Firebase
            firebase_manager.store_message_backup({
                'id': message.id,
                'sender_id': message.sender_id,
                'recipient_id': message.recipient_id,
                'timestamp': message.timestamp.isoformat()
            })
            
            # Send notification email
            sender = User.query.get(session['user_id'])
            email_manager.send_message_notification(recipient.email, sender.username)
            
            flash('Message sent successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            logger.error(f"Error sending message: {str(e)}")
            flash('Failed to send message. Please try again.', 'danger')
    
    return render_template('send_message.html')

@app.route('/messages')
def messages():
    if 'user_id' not in session:
        flash('Please log in to view messages.', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    # Get all messages for user (sent and received)
    sent_messages = Message.query.filter_by(sender_id=user.id).order_by(Message.timestamp.desc()).all()
    received_messages = Message.query.filter_by(recipient_id=user.id).order_by(Message.timestamp.desc()).all()
    
    # Decrypt received messages
    decrypted_messages = []
    for msg in received_messages:
        try:
            decrypted_content = CryptoManager.decrypt_message(
                msg.encrypted_content,
                msg.encrypted_key,
                user.private_key
            )
            decrypted_messages.append({
                'message': msg,
                'decrypted_content': decrypted_content,
                'sender': msg.sender
            })
            
            # Mark as read
            if not msg.is_read:
                msg.is_read = True
                
        except Exception as e:
            logger.error(f"Error decrypting message {msg.id}: {str(e)}")
            decrypted_messages.append({
                'message': msg,
                'decrypted_content': '[Decryption Error]',
                'sender': msg.sender
            })
    
    db.session.commit()
    
    return render_template('messages.html', 
                         sent_messages=sent_messages, 
                         decrypted_messages=decrypted_messages)

@app.route('/api/users/search')
def search_users():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify({'users': []})
    
    users = User.query.filter(
        User.username.ilike(f'%{query}%'),
        User.is_verified == True,
        User.id != session['user_id']
    ).limit(10).all()
    
    return jsonify({
        'users': [{'username': user.username, 'email': user.email} for user in users]
    })

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500
