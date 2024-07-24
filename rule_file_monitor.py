import threading
import time
import os

class RuleFileMonitor(threading.Thread):
    def __init__(self, rule_loader, firewall, interval=5):
        threading.Thread.__init__(self)
        self.rule_loader = rule_loader
        self.firewall = firewall
        self.interval = interval
        self.last_modified = os.path.getmtime(self.rule_loader.json_file)
        self.daemon = True
        self._stop_event = threading.Event()

    def run(self):
        """
        Continuously monitor the rule file for changes and update the firewall rules accordingly.

        This method checks the modification time of the rule file at regular intervals.
        If a change is detected, it reloads the rules and updates the firewall.
        """
        while not self._stop_event.is_set():
            try:
                time.sleep(self.interval)
                current_modified = os.path.getmtime(self.rule_loader.json_file)
                if current_modified != self.last_modified:
                    self.last_modified = current_modified
                    self.firewall.logger.log("Detected rule file change, reloading rules...")
                    self.rule_loader.load_rules()
                    # Update the firewall with the new rules
                    self.firewall.update_rules(self.rule_loader.get_rules())
            except Exception as e:
                print(f"Error occurred while monitoring rules: {e}")

    def stop(self):
        """
        Stop the file monitoring thread.
        """
        self._stop_event.set()