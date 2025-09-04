import logging
import os
from datetime import datetime


class SecureFileXLogger:
    """
    Logging system for SecureFileX with different log levels and file rotation.
    """
    
    def __init__(self, name='SecureFileX', log_dir='logs', log_level=logging.INFO):
        self.name = name
        self.log_dir = log_dir
        self.log_level = log_level
        
        # Create logs directory if it doesn't exist
        os.makedirs(log_dir, exist_ok=True)
        
        # Setup logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(log_level)
        
        # Avoid adding multiple handlers if logger already exists
        if not self.logger.handlers:
            self._setup_handlers()
    
    def _setup_handlers(self):
        """Setup console and file handlers."""
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler for general logs
        log_file = os.path.join(self.log_dir, f'{self.name.lower()}.log')
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(self.log_level)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Security events handler (separate file)
        security_file = os.path.join(self.log_dir, 'security.log')
        self.security_handler = logging.FileHandler(security_file)
        self.security_handler.setLevel(logging.WARNING)
        self.security_handler.setFormatter(formatter)
    
    def info(self, message, **kwargs):
        """Log info message."""
        self.logger.info(message, **kwargs)
    
    def warning(self, message, **kwargs):
        """Log warning message."""
        self.logger.warning(message, **kwargs)
    
    def error(self, message, **kwargs):
        """Log error message."""
        self.logger.error(message, **kwargs)
    
    def debug(self, message, **kwargs):
        """Log debug message."""
        self.logger.debug(message, **kwargs)
    
    def critical(self, message, **kwargs):
        """Log critical message."""
        self.logger.critical(message, **kwargs)
    
    def security_event(self, event_type, message, username=None, ip_address=None):
        """Log security-related events."""
        security_msg = f"SECURITY [{event_type}] {message}"
        if username:
            security_msg += f" | User: {username}"
        if ip_address:
            security_msg += f" | IP: {ip_address}"
        
        # Log to both main logger and security file
        self.logger.warning(security_msg)
        self.security_handler.emit(
            logging.LogRecord(
                name=self.name,
                level=logging.WARNING,
                pathname='',
                lineno=0,
                msg=security_msg,
                args=(),
                exc_info=None
            )
        )
    
    def file_operation(self, operation, filename, username=None, success=True, file_size=None):
        """Log file operations."""
        status = "SUCCESS" if success else "FAILED"
        msg = f"FILE_OP [{operation}] {filename} - {status}"
        if username:
            msg += f" | User: {username}"
        if file_size:
            msg += f" | Size: {file_size} bytes"
        
        if success:
            self.info(msg)
        else:
            self.warning(msg)
    
    def connection_event(self, event_type, ip_address, username=None):
        """Log connection events."""
        msg = f"CONNECTION [{event_type}] from {ip_address}"
        if username:
            msg += f" | User: {username}"
        
        self.info(msg)


# Global logger instance
logger = SecureFileXLogger()


def get_logger(name='SecureFileX'):
    """Get a logger instance."""
    return SecureFileXLogger(name)