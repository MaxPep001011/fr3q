import os
import sys
import json
import logging
import traceback

# Default System Config (Global settings, not per-account)
DEFAULT_SYSTEM_CONFIG = {
    "log_level": "INFO"
}

def get_freq_dir():
    """Returns the base config directory: ~/.config/fr3q/"""
    home = os.path.expanduser("~")
    base = os.path.join(home, ".config", "fr3q")
    return base

def setup_logging(debug_mode: bool):
    """
    Configures logging to file. 
    Must have valid log path
    """
    log_dir = os.path.join(get_freq_dir(), "logs")
    os.makedirs(log_dir, exist_ok=True)

    #TODO:allow specific dir for logging
    log_file = os.path.join(log_dir, "std.log")
    
    level = logging.DEBUG if debug_mode else logging.INFO
    
    logging.basicConfig(
        filename=log_file,
        filemode="a",
        #format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        format="%(asctime)s [%(levelname)s] %(message)s",
        level=level
    )
    
    # Redirect uncaught exceptions to the log file
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        logging.critical("Uncaught Exception", exc_info=(exc_type, exc_value, exc_traceback))
    
    sys.excepthook = handle_exception

def ensure_directories():
    """
    Creates the necessary directory skeleton.
    ~/.config/fr3q/
    ├── accounts/
    ├── logs/
    └── system.json
    """
    base = get_freq_dir()
    accounts = os.path.join(base, "accounts")
    
    os.makedirs(base, exist_ok=True)
    os.makedirs(accounts, exist_ok=True)
    
    # Create system.json if missing
    sys_conf_path = os.path.join(base, "system.json")
    if not os.path.exists(sys_conf_path):
        with open(sys_conf_path, "w") as f:
            json.dump(DEFAULT_SYSTEM_CONFIG, f, indent=4)

def load_system_config():
    """Returns the dict from system.json"""
    path = os.path.join(get_freq_dir(), "system.json")
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return DEFAULT_SYSTEM_CONFIG