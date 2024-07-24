import os
import time
import json

class Logger:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self.ensure_log_directory_exists()

    def ensure_log_directory_exists(self):
        os.makedirs(os.path.dirname(self.log_file_path), exist_ok=True)

    def log(self, message):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        log_entry = {'message': f'[{timestamp}] {message}'}
        
        # Read existing logs
        if os.path.exists(self.log_file_path):
            with open(self.log_file_path, 'r') as file:
                try:
                    logs = json.load(file)
                except json.JSONDecodeError:
                    logs = []
        else:
            logs = []

        # Append the new log entry
        logs.append(log_entry)

        # Write the updated logs back to the file
        with open(self.log_file_path, 'w') as file:
            json.dump(logs, file, indent=4)
