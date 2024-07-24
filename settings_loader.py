import json

class SettingsLoader:
    def __init__(self, json_file):
        """
        Initialize the SettingsLoader with the path to the JSON file.

        Args:
            json_file (str): The path to the JSON file containing settings.
        """
        self.json_file = json_file
        self.settings_data = {}
        self.load_settings()

    def load_settings(self):
        """
        Load settings from the JSON file and store them in the settings_data dictionary.
        """
        with open(self.json_file, 'r') as f:
            self.settings_data = json.load(f)

    def get_settings(self):
        """
        Get the loaded settings.

        Returns:
            dict: The dictionary containing the settings data.
        """
        return self.settings_data
