import hashlib
import secrets
import time
import json
import os


class SimpleAuthenticator:
    """
    Simple authentication system for SecureFileX.
    Uses username/password with hashed storage and session tokens.
    """
    
    def __init__(self, users_file='users.json'):
        self.users_file = users_file
        self.active_tokens = {}  # token -> (username, expiry_time)
        self.token_lifetime = 3600  # 1 hour in seconds
        self.load_users()
    
    def load_users(self):
        """Load users from file or create default admin user."""
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    self.users = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.users = {}
        else:
            # Create default admin user
            self.users = {}
            self.add_user('admin', 'admin123')  # Default credentials
            print("Created default user: admin/admin123")
    
    def save_users(self):
        """Save users to file."""
        try:
            with open(self.users_file, 'w') as f:
                json.dump(self.users, f, indent=2)
        except IOError as e:
            print(f"Error saving users: {e}")
    
    def hash_password(self, password, salt=None):
        """Hash a password with salt."""
        if salt is None:
            salt = secrets.token_hex(16)
        
        # Combine password and salt, then hash
        combined = (password + salt).encode('utf-8')
        hashed = hashlib.sha256(combined).hexdigest()
        return hashed, salt
    
    def add_user(self, username, password):
        """Add a new user."""
        if username in self.users:
            return False, "User already exists"
        
        hashed_password, salt = self.hash_password(password)
        self.users[username] = {
            'password_hash': hashed_password,
            'salt': salt,
            'created_at': time.time()
        }
        self.save_users()
        return True, "User created successfully"
    
    def authenticate(self, username, password):
        """Authenticate a user and return a session token."""
        if username not in self.users:
            return False, None, "Invalid username or password"
        
        user_data = self.users[username]
        hashed_password, _ = self.hash_password(password, user_data['salt'])
        
        if hashed_password == user_data['password_hash']:
            # Generate session token
            token = secrets.token_urlsafe(32)
            expiry_time = time.time() + self.token_lifetime
            self.active_tokens[token] = (username, expiry_time)
            
            return True, token, "Authentication successful"
        else:
            return False, None, "Invalid username or password"
    
    def validate_token(self, token):
        """Validate a session token."""
        if token not in self.active_tokens:
            return False, None, "Invalid token"
        
        username, expiry_time = self.active_tokens[token]
        
        if time.time() > expiry_time:
            # Token expired
            del self.active_tokens[token]
            return False, None, "Token expired"
        
        return True, username, "Token valid"
    
    def logout(self, token):
        """Logout a user by invalidating their token."""
        if token in self.active_tokens:
            del self.active_tokens[token]
            return True, "Logged out successfully"
        return False, "Invalid token"
    
    def cleanup_expired_tokens(self):
        """Remove expired tokens."""
        current_time = time.time()
        expired_tokens = [
            token for token, (_, expiry_time) in self.active_tokens.items()
            if current_time > expiry_time
        ]
        
        for token in expired_tokens:
            del self.active_tokens[token]
        
        return len(expired_tokens)
    
    def list_users(self):
        """List all usernames (for admin purposes)."""
        return list(self.users.keys())
    
    def remove_user(self, username):
        """Remove a user."""
        if username in self.users:
            del self.users[username]
            self.save_users()
            
            # Invalidate all tokens for this user
            tokens_to_remove = [
                token for token, (user, _) in self.active_tokens.items()
                if user == username
            ]
            for token in tokens_to_remove:
                del self.active_tokens[token]
            
            return True, "User removed successfully"
        return False, "User not found"


class AuthenticationMixin:
    """Mixin class to add authentication capabilities to servers."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.authenticator = SimpleAuthenticator()
    
    def require_authentication(self, conn, aes_cipher):
        """Require client authentication before proceeding."""
        # Send authentication request
        auth_request = {
            'status': 'auth_required',
            'message': 'Please provide username and password'
        }
        self.send_response(conn, aes_cipher, auth_request)
        
        # Receive authentication credentials
        encrypted_auth = conn.recv(4096)
        if not encrypted_auth:
            return False, None, "No authentication data received"
        
        try:
            auth_data = json.loads(aes_cipher.decrypt(encrypted_auth).decode())
            username = auth_data.get('username')
            password = auth_data.get('password')
            
            if not username or not password:
                self.send_response(conn, aes_cipher, {
                    'status': 'auth_failed',
                    'message': 'Username and password required'
                })
                return False, None, "Missing credentials"
            
            # Authenticate user
            success, token, message = self.authenticator.authenticate(username, password)
            
            if success:
                self.send_response(conn, aes_cipher, {
                    'status': 'auth_success',
                    'token': token,
                    'message': message
                })
                return True, token, username
            else:
                self.send_response(conn, aes_cipher, {
                    'status': 'auth_failed',
                    'message': message
                })
                return False, None, message
                
        except Exception as e:
            self.send_response(conn, aes_cipher, {
                'status': 'auth_failed',
                'message': f'Authentication error: {e}'
            })
            return False, None, str(e)
    
    def validate_session(self, token):
        """Validate a session token."""
        return self.authenticator.validate_token(token)