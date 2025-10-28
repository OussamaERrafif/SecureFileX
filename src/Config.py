import json
import os
import logging
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class ServerConfig:
    """Server configuration settings."""
    host: str = 'localhost'
    port: int = 12345
    upload_dir: str = 'uploads'
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    session_timeout: int = 3600  # 1 hour
    max_connections: int = 10
    log_level: str = 'INFO'
    require_authentication: bool = True


@dataclass
class ClientConfig:
    """Client configuration settings."""
    default_host: str = 'localhost'
    default_port: int = 12345
    chunk_size: int = 8192
    connection_timeout: int = 30
    retry_attempts: int = 3
    log_level: str = 'INFO'


@dataclass
class SecurityConfig:
    """Security configuration settings."""
    rsa_key_size: int = 2048
    aes_key_size: int = 32  # 256-bit
    password_min_length: int = 6
    max_login_attempts: int = 3
    lockout_duration: int = 300  # 5 minutes
    hash_algorithm: str = 'sha256'


class ConfigManager:
    """
    Configuration manager for SecureFileX.
    Handles loading, saving, and validating configuration settings.
    """
    
    def __init__(self, config_file='config.json'):
        self.config_file = config_file
        self.server_config = ServerConfig()
        self.client_config = ClientConfig()
        self.security_config = SecurityConfig()
        
        self.load_config()
    
    def load_config(self):
        """Load configuration from file."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                
                # Load server config
                if 'server' in config_data:
                    server_data = config_data['server']
                    self.server_config = ServerConfig(**{
                        k: v for k, v in server_data.items() 
                        if k in ServerConfig.__annotations__
                    })
                
                # Load client config
                if 'client' in config_data:
                    client_data = config_data['client']
                    self.client_config = ClientConfig(**{
                        k: v for k, v in client_data.items() 
                        if k in ClientConfig.__annotations__
                    })
                
                # Load security config
                if 'security' in config_data:
                    security_data = config_data['security']
                    self.security_config = SecurityConfig(**{
                        k: v for k, v in security_data.items() 
                        if k in SecurityConfig.__annotations__
                    })
                
                print(f"Configuration loaded from {self.config_file}")
                
            except (json.JSONDecodeError, TypeError, ValueError) as e:
                print(f"Error loading config: {e}. Using defaults.")
                self.save_config()  # Save default config
        else:
            print("No config file found. Creating default configuration.")
            self.save_config()
    
    def save_config(self):
        """Save current configuration to file."""
        config_data = {
            'server': asdict(self.server_config),
            'client': asdict(self.client_config),
            'security': asdict(self.security_config)
        }
        
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            print(f"Configuration saved to {self.config_file}")
        except IOError as e:
            print(f"Error saving config: {e}")
    
    def update_server_config(self, **kwargs):
        """Update server configuration."""
        for key, value in kwargs.items():
            if hasattr(self.server_config, key):
                setattr(self.server_config, key, value)
        self.save_config()
    
    def update_client_config(self, **kwargs):
        """Update client configuration."""
        for key, value in kwargs.items():
            if hasattr(self.client_config, key):
                setattr(self.client_config, key, value)
        self.save_config()
    
    def update_security_config(self, **kwargs):
        """Update security configuration."""
        for key, value in kwargs.items():
            if hasattr(self.security_config, key):
                setattr(self.security_config, key, value)
        self.save_config()
    
    def validate_config(self):
        """Validate configuration settings."""
        errors = []
        
        # Validate server config
        if self.server_config.port < 1 or self.server_config.port > 65535:
            errors.append("Server port must be between 1 and 65535")
        
        if self.server_config.max_file_size < 1:
            errors.append("Max file size must be positive")
        
        if self.server_config.session_timeout < 60:
            errors.append("Session timeout must be at least 60 seconds")
        
        # Validate client config
        if self.client_config.chunk_size < 1024:
            errors.append("Chunk size should be at least 1024 bytes")
        
        if self.client_config.connection_timeout < 5:
            errors.append("Connection timeout should be at least 5 seconds")
        
        # Validate security config
        if self.security_config.rsa_key_size < 2048:
            errors.append("RSA key size should be at least 2048 bits")
        
        if self.security_config.aes_key_size not in [16, 24, 32]:
            errors.append("AES key size must be 16, 24, or 32 bytes")
        
        if self.security_config.password_min_length < 4:
            errors.append("Password minimum length should be at least 4")
        
        return errors
    
    def get_log_level(self, component='server'):
        """Get log level for a component."""
        if component == 'server':
            return getattr(logging, self.server_config.log_level.upper(), logging.INFO)
        elif component == 'client':
            return getattr(logging, self.client_config.log_level.upper(), logging.INFO)
        else:
            return logging.INFO
    
    def print_config(self):
        """Print current configuration."""
        print("\n=== SecureFileX Configuration ===")
        print("\nServer Configuration:")
        for key, value in asdict(self.server_config).items():
            print(f"  {key}: {value}")
        
        print("\nClient Configuration:")
        for key, value in asdict(self.client_config).items():
            print(f"  {key}: {value}")
        
        print("\nSecurity Configuration:")
        for key, value in asdict(self.security_config).items():
            print(f"  {key}: {value}")
        print()


# Global config instance
config = ConfigManager()


def get_config():
    """Get the global configuration manager."""
    return config


if __name__ == "__main__":
    # Configuration management CLI
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == 'show':
            config.print_config()
        elif sys.argv[1] == 'validate':
            errors = config.validate_config()
            if errors:
                print("Configuration errors:")
                for error in errors:
                    print(f"  - {error}")
            else:
                print("Configuration is valid")
        else:
            print("Usage: python Config.py [show|validate]")
    else:
        config.print_config()