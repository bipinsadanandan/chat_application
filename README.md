# chat_application
code &amp; docs
# Overview

SecureChat is an end-to-end encrypted messaging platform built with Flask that provides secure communication between users. The application implements a hybrid encryption approach using RSA for key exchange and Fernet (AES-based) for message content encryption. Users must verify their email addresses before accessing the platform, and the system generates unique RSA key pairs for each user to ensure secure message transmission.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Backend Architecture
The application is built using Flask with SQLAlchemy ORM for database operations. The core architecture follows a modular design with separate utility classes for different functionalities:

- **Flask Application**: Main application server with session-based authentication
- **Database Layer**: SQLAlchemy with SQLite as default database (configurable via environment variables)
- **Encryption Layer**: Custom `CryptoManager` class handling RSA key generation and Fernet encryption/decryption
- **Email Layer**: `EmailManager` class for SMTP-based email delivery
- **Firebase Integration**: Placeholder `FirebaseManager` for future cloud backup functionality

## Database Schema
The application uses three main database models:
- **User**: Stores user credentials, RSA key pairs, and verification status
- **Message**: Contains encrypted message content, encrypted symmetric keys, and metadata
- **EmailVerification**: Manages OTP-based email verification with expiration

## Encryption Strategy
The system implements a hybrid encryption approach:
1. **RSA Encryption**: 2048-bit key pairs for secure key exchange
2. **Fernet Encryption**: Symmetric encryption for fast message content protection
3. **Key Management**: Private keys stored encrypted in database, public keys shared for message encryption

## Frontend Architecture
The frontend uses Bootstrap 5 with a dark theme and Font Awesome icons. Templates follow a base-template pattern with:
- **Responsive Design**: Mobile-friendly interface with Bootstrap components
- **Interactive Elements**: Collapsible message views and form validations
- **Security Indicators**: Visual feedback for encryption status and security features

## Authentication & Authorization
- **Session-based Authentication**: Flask sessions for user state management
- **Email Verification**: OTP-based verification system with 10-minute expiration
- **Password Security**: Werkzeug password hashing for credential storage

# External Dependencies

## Core Framework Dependencies
- **Flask**: Web application framework with SQLAlchemy integration
- **SQLAlchemy**: ORM for database operations with connection pooling
- **Werkzeug**: WSGI utilities and security functions

## Cryptographic Libraries
- **pycryptodome**: RSA key generation and PKCS1_OAEP encryption
- **cryptography**: Fernet symmetric encryption implementation

## Email Services
- **SMTP Integration**: Gmail SMTP server for email delivery
- **Environment Variables**: MAIL_USERNAME, MAIL_PASSWORD, MAIL_SERVER configuration

## Database Systems
- **SQLite**: Default database for development
- **PostgreSQL**: Production database support via DATABASE_URL environment variable

## Cloud Services (Planned)
- **Firebase**: Placeholder integration for message backup and cloud storage
- **Environment Variables**: FIREBASE_SERVICE_ACCOUNT_KEY, FIREBASE_PROJECT_ID

## Frontend Libraries
- **Bootstrap 5**: UI framework with dark theme support
- **Font Awesome**: Icon library for user interface elements
- **Custom CSS/JS**: Additional styling and encryption utilities
