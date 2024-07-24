from rule_loader import RuleLoader
from rule_file_monitor import RuleFileMonitor
from intrusion_detection import IntrusionDetection
from netfilterqueue import NetfilterQueue

from settings_file_monitor import SettingsFileMonitor
from settings_loader import SettingsLoader


from logger import Logger
from stateful_firewall import StatefulFirewall

def main():
    # Initializes
    logger = Logger('/home/ibrahhem/final-project/firewall/files/logs.json')
    rule_loader = RuleLoader('/home/ibrahhem/final-project/firewall/files/rules.json')
    settings_loader = SettingsLoader('/home/ibrahhem/final-project/firewall/files/settings.json')
    intrusion_detection = IntrusionDetection(**settings_loader.get_settings())
    firewall = StatefulFirewall(rule_loader.get_rules(), intrusion_detection, logger)
    rule_file_monitor = RuleFileMonitor(rule_loader, firewall)
    settings_file_monitor = SettingsFileMonitor(settings_loader, intrusion_detection, logger)

    # Start the file monitors thread
    rule_file_monitor.start()
    settings_file_monitor.start()

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, firewall.perform_stateful_inspection)  # Bind to queue number 1

    try:
        firewall.logger.log("Starting firewall...")
        nfqueue.run()
    except KeyboardInterrupt:
        firewall.logger.log("Stopping firewall...")
    finally:
        rule_file_monitor.stop()
        rule_file_monitor.join()
        settings_file_monitor.stop()
        settings_file_monitor.join()
        nfqueue.unbind()

if __name__ == "__main__":
    main()

