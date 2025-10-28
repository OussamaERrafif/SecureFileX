# SecureFileX GUI Documentation

## Overview

SecureFileX now includes comprehensive graphical user interfaces (GUIs) for both client and server operations, making secure file transfers even more accessible and user-friendly.

## GUI Components

### 1. GUI Launcher (`gui_launcher.py`)

A unified launcher that provides easy access to both client and server applications.

**Features:**
- Quick launch for client or server
- CLI help integration
- Clean, intuitive interface

**Usage:**
```bash
python gui_launcher.py
```

### 2. GUI Client (`gui_client.py`)

A full-featured client application with an intuitive graphical interface.

**Features:**
- **Connection Management**: Easy server connection with host/port configuration
- **User Authentication**: Secure login with username/password
- **File Upload**: Browse and upload files with progress tracking
- **File Download**: Download files from server with integrity verification
- **File Listing**: View all available files on the server
- **Quick Upload Zone**: Click-to-upload zone (drag-and-drop ready with tkinterdnd2)
- **Real-time Console**: View all operations and status messages
- **Progress Indicators**: Visual progress bars for file transfers
- **Settings Panel**: View and manage configuration
- **Status Indicators**: Connection and authentication status at a glance

**Key Components:**
- Server connection panel with status indicators
- Authentication panel with login controls
- File operations panel with upload/download/refresh buttons
- Server file list with double-click download
- Console output with color-coded messages
- Transfer progress bar

**Usage:**
```bash
python gui_client.py
```

### 3. GUI Server (`gui_server.py`)

A comprehensive server control panel for managing the SecureFileX server.

**Features:**
- **Server Configuration**: Configure host, port, upload directory, and limits
- **Server Control**: Start/stop server with one click
- **User Management**: Create users and list existing users
- **Client Monitoring**: View connected clients (when server is running)
- **File Statistics**: View number of files in upload directory
- **Log Viewer**: Access server logs from the GUI
- **Upload Directory**: Browse and open upload directory
- **Configuration Validation**: Validate settings before starting

**Key Components:**
- Server configuration panel
- Server status display with statistics
- Connected clients list
- Server logs console
- Control buttons (start/stop/refresh)

**Usage:**
```bash
python gui_server.py
```

## Installation

### Requirements

The GUI applications require Python's tkinter library, which is typically included with Python installations.

**For Windows:**
- Tkinter is usually included with Python

**For Linux (Ubuntu/Debian):**
```bash
sudo apt-get install python3-tk
```

**For macOS:**
- Tkinter is included with Python from python.org

**Optional Enhancement - Drag and Drop:**
For full drag-and-drop support in the client, install tkinterdnd2:
```bash
pip install tkinterdnd2
```

### Dependencies

The existing dependencies are sufficient for basic GUI operation:
```
cffi==1.16.0
cryptography==42.0.8
pycparser==2.22
```

## Quick Start Guide

### Using the Launcher

1. **Start the launcher:**
   ```bash
   python gui_launcher.py
   ```

2. **Choose your application:**
   - Click "Launch Server" to start the server control panel
   - Click "Launch Client" to start the client application

### Using the GUI Client

1. **Launch the client:**
   ```bash
   python gui_client.py
   ```

2. **Connect to server:**
   - Enter server host (default: localhost)
   - Enter server port (default: 12345)
   - Click "Connect"

3. **Authenticate:**
   - Enter username (default: admin)
   - Enter password (default: admin123)
   - Click "Login"

4. **Upload files:**
   - Click "Upload File" button
   - Select file from dialog
   - Watch progress bar

5. **Download files:**
   - Select file from server list
   - Click "Download File" button
   - Choose save location

### Using the GUI Server

1. **Launch the server:**
   ```bash
   python gui_server.py
   ```

2. **Configure server:**
   - Set host (default: localhost)
   - Set port (default: 12345)
   - Choose upload directory

3. **Start server:**
   - Click "Start Server"
   - Monitor status and connected clients

4. **Manage users:**
   - Use "Users" menu to create or list users
   - Manage authentication from the GUI

## Features Comparison

| Feature | CLI | GUI Client | GUI Server |
|---------|-----|------------|------------|
| File Upload | ✓ | ✓ | - |
| File Download | ✓ | ✓ | - |
| File Listing | ✓ | ✓ | - |
| User Authentication | ✓ | ✓ | - |
| Server Start/Stop | ✓ | - | ✓ |
| User Management | ✓ | - | ✓ |
| Configuration | ✓ | ✓ | ✓ |
| Visual Progress | - | ✓ | ✓ |
| Real-time Logs | - | ✓ | ✓ |
| Status Indicators | - | ✓ | ✓ |

## GUI Architecture

### Client Architecture
```
GUI Client Window
├── Menu Bar (File, Connection, Tools, Help)
├── Connection Frame (Host, Port, Connect/Disconnect)
├── Authentication Frame (Username, Password, Login)
├── File Operations Frame
│   ├── Action Buttons (Upload, Download, Refresh, Delete)
│   ├── Progress Bar
│   ├── Server File List
│   └── Quick Upload Zone
├── Console Frame (Colored output messages)
└── Status Bar (Current operation status)
```

### Server Architecture
```
GUI Server Window
├── Menu Bar (File, Server, Users, Tools, Help)
├── Server Configuration Frame (Host, Port, Upload Dir, Limits)
├── Server Status Frame (Status, Client Count, File Count)
├── Connected Clients Frame (List of active clients)
├── Server Logs Frame (Colored log messages)
├── Control Frame (Start, Stop, Refresh buttons)
└── Status Bar (Current operation status)
```

## Keyboard Shortcuts

### Client
- `Double-click on file`: Download file
- `Click on drop zone`: Upload file

### Server
- None currently (can be added in future versions)

## Troubleshooting

### GUI Won't Start

**Issue:** `ModuleNotFoundError: No module named 'tkinter'`

**Solution:** Install tkinter for your platform:
- **Linux:** `sudo apt-get install python3-tk`
- **Windows/macOS:** Usually included, try reinstalling Python

### Connection Issues

**Issue:** "Connection failed" error

**Solution:**
1. Ensure server is running
2. Check host and port settings
3. Verify firewall allows connections
4. Check server logs for errors

### Authentication Fails

**Issue:** "Authentication failed" error

**Solution:**
1. Verify username and password
2. Check if user exists (use server GUI to list users)
3. Create user if needed (server GUI → Users → Create User)

## Advanced Features

### Custom Configuration

The GUI applications respect the same `config.json` file used by the CLI. You can:
1. Edit `config.json` manually
2. Use Settings dialog in GUI
3. Use CLI: `python securefx.py config --show`

### Multiple Instances

You can run multiple clients simultaneously to connect to different servers or test concurrent operations.

### Security Considerations

- GUI applications use the same security as CLI (AES-256, RSA-2048, SHA-256)
- Session tokens are managed automatically
- Passwords are not stored, only entered when needed
- All network traffic is encrypted

## Future Enhancements

Planned features for future versions:
- [ ] Full drag-and-drop support (integrated tkinterdnd2)
- [ ] File transfer history
- [ ] Bandwidth monitoring and throttling
- [ ] Multi-file selection and batch operations
- [ ] Server-side file preview
- [ ] Theme customization
- [ ] Automatic reconnection
- [ ] Scheduled file transfers
- [ ] Remote server monitoring
- [ ] Database-backed user management

## Support

For issues, questions, or contributions:
- See main README.md
- Check EXAMPLES.md for detailed usage
- Review CONTRIBUTING.md for contribution guidelines

## License

Same as main project (MIT License)
