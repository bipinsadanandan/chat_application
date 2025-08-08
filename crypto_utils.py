from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import base64
import os
import logging

logger = logging.getLogger(__name__)

class CryptoManager:
    @staticmethod
    def generate_rsa_keypair():
        """Generate RSA key pair (2048 bits)"""
        try:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()
            
            # Serialize private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return {
                'private_key': private_pem.decode('utf-8'),
                'public_key': public_pem.decode('utf-8')
            }
        except Exception as e:
            logger.error(f"Error generating RSA keypair: {str(e)}")
            raise
    
    @staticmethod
    def generate_fernet_key():
        """Generate a new Fernet key for symmetric encryption"""
        return Fernet.generate_key()
    
    @staticmethod
    def encrypt_with_fernet(message, key):
        """Encrypt message with Fernet (symmetric)"""
        try:
            f = Fernet(key)
            encrypted_message = f.encrypt(message.encode())
            return base64.b64encode(encrypted_message).decode()
        except Exception as e:
            logger.error(f"Error encrypting with Fernet: {str(e)}")
            raise
    
    @staticmethod
    def decrypt_with_fernet(encrypted_message, key):
        """Decrypt message with Fernet (symmetric)"""
        try:
            f = Fernet(key)
            encrypted_data = base64.b64decode(encrypted_message.encode())
            decrypted_message = f.decrypt(encrypted_data)
            return decrypted_message.decode()
        except Exception as e:
            logger.error(f"Error decrypting with Fernet: {str(e)}")
            raise
    
    @staticmethod
    def encrypt_with_rsa(data, public_key_pem):
        """Encrypt data with RSA public key"""
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            encrypted_data = public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return base64.b64encode(encrypted_data).decode()
        except Exception as e:
            logger.error(f"Error encrypting with RSA: {str(e)}")
            raise
    
    @staticmethod
    def decrypt_with_rsa(encrypted_data, private_key_pem):
        """Decrypt data with RSA private key"""
        try:
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None
            )
            encrypted_bytes = base64.b64decode(encrypted_data.encode())
            decrypted_data = private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_data
        except Exception as e:
            logger.error(f"Error decrypting with RSA: {str(e)}")
            raise
    
    @staticmethod
    def encrypt_message(message, recipient_public_key):
        """
        Hybrid encryption: Use Fernet for message, RSA for Fernet key
        Returns: (encrypted_message, encrypted_key)
        """
        try:
            # Generate Fernet key
            fernet_key = CryptoManager.generate_fernet_key()
            
            # Encrypt message with Fernet
            encrypted_message = CryptoManager.encrypt_with_fernet(message, fernet_key)
            
            # Encrypt Fernet key with RSA
            encrypted_key = CryptoManager.encrypt_with_rsa(fernet_key, recipient_public_key)
            
            return encrypted_message, encrypted_key
        except Exception as e:
            logger.error(f"Error in hybrid encryption: {str(e)}")
            raise
    
    @staticmethod
    def decrypt_message(encrypted_message, encrypted_key, private_key):
        """
        Hybrid decryption: Decrypt Fernet key with RSA, then message with Fernet
        """
        try:
            # Decrypt Fernet key with RSA
            fernet_key = CryptoManager.decrypt_with_rsa(encrypted_key, private_key)
            
            # Decrypt message with Fernet
            decrypted_message = CryptoManager.decrypt_with_fernet(encrypted_message, fernet_key)
            
            return decrypted_message
        except Exception as e:
            logger.error(f"Error in hybrid decryption: {str(e)}")
            raise
