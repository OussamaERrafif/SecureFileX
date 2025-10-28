# SecureFileX Usage Examples

This document provides detailed usage examples and screenshots for SecureFileX.

## Table of Contents

- [Quick Start](#quick-start)
- [Server Operations](#server-operations)
- [Client Operations](#client-operations)
- [Interactive Mode Examples](#interactive-mode-examples)
- [Configuration Examples](#configuration-examples)
- [User Management Examples](#user-management-examples)
- [Troubleshooting](#troubleshooting)

## Quick Start

### Starting the Server

The simplest way to start the server:

```bash
python securefx.py server
```

Output:
```
Configuration loaded from config.json
Server initialized - Upload dir: /path/to/SecureFileX/uploads
File Transfer Server listening on localhost:12345
Upload directory: /path/to/SecureFileX/uploads
```

### Connecting with the Client

Start the interactive client:

```bash
python securefx.py client
```

Output:
```
Starting SecureFileX Client...
Connected to server at localhost:12345
Authentication required
Username: admin
Password: 
✓ Authentication successful
Authenticated as user: admin

SecureFileX Client - Welcome admin
Commands:
  upload <file_path>     - Upload a file
  download <filename>    - Download a file
  list                   - List available files
  message <text>         - Send a text message
  quit                   - Exit client

SecureFileX> 
```

## Server Operations

### Starting Server on Custom Host/Port

```bash
python securefx.py server --host 0.0.0.0 --port 8080
```

This starts the server on all interfaces (0.0.0.0) on port 8080.

### Validating Configuration Before Starting

```bash
python securefx.py server --validate-config
```

Output:
```
Configuration loaded from config.json
Configuration is valid
```

### Custom Upload Directory

```bash
python securefx.py server --upload-dir /custom/path/uploads
```

## Client Operations

### Uploading a File

#### Non-Interactive Upload

```bash
python securefx.py client --upload myfile.txt
```

Output:
```
Starting SecureFileX Client...
Connected to server at localhost:12345
Authentication required
Username: admin
Password: 
✓ Authentication successful
Authenticated as user: admin
Uploading myfile.txt (1024 bytes)
File hash: a1b2c3d4e5f6...
Upload progress: 100.0%
✓ File myfile.txt uploaded and verified successfully
```

#### Interactive Upload

```
SecureFileX> upload test.txt
Uploading test.txt (2048 bytes)
File hash: 1a2b3c4d5e6f...
Upload progress: 100.0%
✓ File test.txt uploaded and verified successfully
```

### Downloading a File

#### Non-Interactive Download

```bash
python securefx.py client --download myfile.txt
```

Output:
```
Starting SecureFileX Client...
Connected to server at localhost:12345
Authentication required
Username: admin
Password: 
✓ Authentication successful
Authenticated as user: admin
Downloading myfile.txt...
File size: 1.00 KB
File hash: a1b2c3d4e5f6...
Download progress: 100.0%
✓ File myfile.txt downloaded and verified successfully
```

#### Interactive Download

```
SecureFileX> download test.txt
Downloading test.txt...
File size: 2.00 KB
File hash: 1a2b3c4d5e6f...
Download progress: 100.0%
✓ File test.txt downloaded and verified successfully
```

### Listing Available Files

#### Non-Interactive List

```bash
python securefx.py client --list
```

Output:
```
Starting SecureFileX Client...
Connected to server at localhost:12345
Authentication required
Username: admin
Password: 
✓ Authentication successful
Authenticated as user: admin

Available files (3):
Filename                                 Size           
-------------------------------------------------------
test.txt                                 2.00 KB        
document.pdf                             1.50 MB        
image.png                                512.00 KB      
```

#### Interactive List

```
SecureFileX> list

Available files (3):
Filename                                 Size           
-------------------------------------------------------
test.txt                                 2.00 KB        
document.pdf                             1.50 MB        
image.png                                512.00 KB      
```

### Connecting to Remote Server

```bash
python securefx.py client --host 192.168.1.100 --port 8080
```

## Interactive Mode Examples

### Complete Session Example

```
$ python securefx.py client
Starting SecureFileX Client...
Connected to server at localhost:12345
Authentication required
Username: admin
Password: 
✓ Authentication successful
Authenticated as user: admin

SecureFileX Client - Welcome admin
Commands:
  upload <file_path>     - Upload a file
  download <filename>    - Download a file
  list                   - List available files
  message <text>         - Send a text message
  quit                   - Exit client

SecureFileX> list

Available files (2):
Filename                                 Size           
-------------------------------------------------------
existing_file.txt                        1.50 KB        
data.csv                                 10.25 MB       

SecureFileX> upload new_file.txt
Uploading new_file.txt (4096 bytes)
File hash: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
Upload progress: 100.0%
✓ File new_file.txt uploaded and verified successfully

SecureFileX> download existing_file.txt
Downloading existing_file.txt...
File size: 1.50 KB
File hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Download progress: 100.0%
✓ File existing_file.txt downloaded and verified successfully

SecureFileX> message Hello from SecureFileX!
✓ Message sent

SecureFileX> quit
Server: goodbye
```

### Sending Messages

```
SecureFileX> message This is a secure message
✓ Message sent
```

## Configuration Examples

### Viewing Current Configuration

```bash
python securefx.py config --show
```

Output:
```
=== SecureFileX Configuration ===

Server Configuration:
  host: localhost
  port: 12345
  upload_dir: uploads
  max_file_size: 104857600
  session_timeout: 3600
  max_connections: 10
  log_level: INFO
  require_authentication: True

Client Configuration:
  default_host: localhost
  default_port: 12345
  chunk_size: 8192
  connection_timeout: 30
  retry_attempts: 3
  log_level: INFO

Security Configuration:
  rsa_key_size: 2048
  aes_key_size: 32
  password_min_length: 6
  max_login_attempts: 3
  lockout_duration: 300
  hash_algorithm: sha256
```

### Validating Configuration

```bash
python securefx.py config --validate
```

Output:
```
Configuration loaded from config.json
Configuration is valid ✓
```

## User Management Examples

### Creating a New User

#### Interactive User Creation

```bash
python securefx.py user create
Username: newuser
Password: 
Confirm password: 
✓ User created successfully
```

#### Non-Interactive User Creation

```bash
python securefx.py user create johndoe --password secure_password
✓ User created successfully
```

### Listing All Users

```bash
python securefx.py user list
```

Output:
```
Registered users:
  - admin
  - johndoe
  - alice
```

## Troubleshooting

### Connection Refused

**Problem:**
```
Client error: Connection failed: [Errno 111] Connection refused
```

**Solution:**
- Ensure the server is running
- Check the host and port are correct
- Verify firewall settings allow the connection

### Authentication Failed

**Problem:**
```
✗ Authentication failed
```

**Solution:**
- Verify username and password are correct
- Check users.json file exists
- Default credentials are: admin/admin123

### File Too Large

**Problem:**
```
Error: File too large (150000000 bytes). Max size: 104857600 bytes
```

**Solution:**
- Increase `max_file_size` in config.json
- Compress the file before uploading

### File Integrity Verification Failed

**Problem:**
```
✗ Download failed: File integrity verification failed
```

**Solution:**
- Network connection may be unstable
- Try downloading again
- Check if file was corrupted on server

### Permission Denied

**Problem:**
```
Error: Permission denied
```

**Solution:**
- Ensure upload directory has write permissions
- Run with appropriate user privileges
- Check directory exists and is accessible

## Advanced Usage

### Running Multiple Clients

You can run multiple clients simultaneously. Each client will have its own session:

Terminal 1:
```bash
python securefx.py client --port 12345
```

Terminal 2:
```bash
python securefx.py client --port 12345
```

### Custom Configuration File

Create a custom config file and use it:

```bash
cp config.json custom_config.json
# Edit custom_config.json as needed
# Then start server/client with your custom config
```

### Monitoring Logs

Monitor server activity:
```bash
tail -f logs/server.log
```

Monitor security events:
```bash
tail -f logs/security.log
```

Monitor client activity:
```bash
tail -f logs/client.log
```

## Performance Tips

1. **Large Files**: For very large files, consider increasing `chunk_size` in config.json
2. **Slow Networks**: Increase `connection_timeout` for unstable connections
3. **Multiple Transfers**: Increase `max_connections` to allow more simultaneous clients

## Security Best Practices

1. **Change Default Credentials**: Always change the default admin password
2. **Use Strong Passwords**: Ensure passwords meet minimum length requirements
3. **Secure Configuration**: Protect config.json file with appropriate permissions
4. **Monitor Logs**: Regularly check security.log for suspicious activity
5. **Update Regularly**: Keep dependencies up to date for security patches

## Example Scripts

### Automated Backup Script

```bash
#!/bin/bash
# backup.sh - Automated file backup to SecureFileX server

FILES_TO_BACKUP=(
    "/path/to/file1.txt"
    "/path/to/file2.pdf"
    "/path/to/data.csv"
)

for file in "${FILES_TO_BACKUP[@]}"; do
    python securefx.py client --upload "$file"
done
```

### Batch Download Script

```bash
#!/bin/bash
# download_all.sh - Download all files from server

# Get list of files (assumes you have authentication set up)
python securefx.py client --list | grep -v "Available files" | grep -v "Filename" | grep -v "---" | awk '{print $1}' | while read filename; do
    python securefx.py client --download "$filename"
done
```

---

For more information, see the [README.md](README.md) and [CONTRIBUTING.md](CONTRIBUTING.md) files.
