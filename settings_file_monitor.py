import threading
import time
import os
from logger import Logger
from settings_loader import SettingsLoader
from intrusion_detection import IntrusionDetection

class SettingsFileMonitor(threading.Thread):
    def __init__(self, settings_loader: SettingsLoader, 
                 intrusion_detection: IntrusionDetection, logger: Logger, interval=5):
        """
        Initialize the SettingsFileMonitor with the required components and interval.

        Args:
            settings_loader (SettingsLoader): Instance to load settings.
            intrusion_detection (IntrusionDetection): Instance to update intrusion detection settings.
            logger (Logger): Instance for logging messages.
            interval (int, optional): Time interval (in seconds) to check for file changes. Default is 5 seconds.
        """
        threading.Thread.__init__(self)
        self.settings_loader = settings_loader
        self.intrusion_detection = intrusion_detection 
        self.interval = interval
        self.logger = logger
        self.last_modified = os.path.getmtime(self.settings_loader.json_file)
        self.daemon = True
        self._stop_event = threading.Event()

    def run(self):
        """
        Run the file monitoring loop to check for changes in the settings file.
        """
        while not self._stop_event.is_set():
            try:
                time.sleep(self.interval)
                current_modified = os.path.getmtime(self.settings_loader.json_file)
                if current_modified != self.last_modified:
                    self.last_modified = current_modified
                    self.logger.log("Detected settings file change, reloading settings...")
                    self.settings_loader.load_settings()
                    self.intrusion_detection.update_settings(self.settings_loader.get_settings())
            except Exception as e:
                print(f"Error occurred while monitoring rules: {e}")

    def stop(self):
        """
        Stop the file monitoring thread.
        """
        self._stop_event.set()