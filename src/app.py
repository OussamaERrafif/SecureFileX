import subprocess
import os
import time

def run_server():
    # Server process
    server_cmd = ['python', 'server.py']
    server_proc = subprocess.Popen(server_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return server_proc

def run_client(buffer_data):
    # Client process
    client_cmd = ['python', 'client.py', buffer_data]
    client_proc = subprocess.Popen(client_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return client_proc

if __name__ == "__main__":
    # Example buffer data
    buffer_data = b'Hello, server!'
    
    # Start server subprocess
    server_proc = run_server()
    
    # Wait a bit to ensure server is ready (optional)
    time.sleep(2)
    
    # Start client subprocess
    client_proc = run_client(buffer_data)
    
    # Wait for client process to finish
    client_proc.wait()
    
    # Read output from server process
    server_output, server_errors = server_proc.communicate()
    
    # Print server output
    if server_output:
        print("Server output:", server_output.decode())
    
    # Print server errors (if any)
    if server_errors:
        print("Server errors:", server_errors.decode())
