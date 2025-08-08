import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import logging

logger = logging.getLogger(__name__)

class EmailManager:
    def __init__(self, app=None):
        self.app = app
        
    def send_otp_email(self, recipient_email, otp_code, username):
        """Send OTP verification email"""
        try:
            sender_email = os.environ.get('MAIL_USERNAME')
            sender_password = os.environ.get('MAIL_PASSWORD')
            
            if not sender_email or not sender_password:
                logger.error("Email credentials not configured")
                return False
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = recipient_email
            msg['Subject'] = "SecureChat - Email Verification"
            
            # Email body
            body = f"""
            <html>
            <body>
                <h2>Email Verification - SecureChat</h2>
                <p>Hello {username},</p>
                <p>Thank you for registering with SecureChat. To complete your registration, please use the following OTP code:</p>
                <h3 style="color: #007bff; font-family: monospace; letter-spacing: 3px;">{otp_code}</h3>
                <p>This code will expire in 10 minutes.</p>
                <p>If you did not create this account, please ignore this email.</p>
                <br>
                <p>Best regards,<br>SecureChat Team</p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(sender_email, sender_password)
            text = msg.as_string()
            server.sendmail(sender_email, recipient_email, text)
            server.quit()
            
            logger.info(f"OTP email sent successfully to {recipient_email}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending OTP email: {str(e)}")
            return False
    
    def send_message_notification(self, recipient_email, sender_username):
        """Send notification about new encrypted message"""
        try:
            sender_email = os.environ.get('MAIL_USERNAME')
            sender_password = os.environ.get('MAIL_PASSWORD')
            
            if not sender_email or not sender_password:
                logger.error("Email credentials not configured")
                return False
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = recipient_email
            msg['Subject'] = "SecureChat - New Encrypted Message"
            
            # Email body
            body = f"""
            <html>
            <body>
                <h2>New Message - SecureChat</h2>
                <p>You have received a new encrypted message from {sender_username}.</p>
                <p>Please log in to SecureChat to read your message.</p>
                <br>
                <p>Best regards,<br>SecureChat Team</p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(sender_email, sender_password)
            text = msg.as_string()
            server.sendmail(sender_email, recipient_email, text)
            server.quit()
            
            logger.info(f"Message notification sent to {recipient_email}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending message notification: {str(e)}")
            return False
