#BUG: IP:
#1. server shutdown updates client status to DISCONNECTED (sometimes) but client still shows purple @ and self.connected never changes to False???
#2. polled vault logs do not have real timestamps
#3. scroll offset does not increment correctly when chat logs wrap lines. implement line wrapping logic to account for wrapping 
#4. prevent vault creation of reserved name "GLOBAL"
#5. prevent duplicate connections (server should deny the duplicate tho leaves open for dos with spoofed header)
#TODO: IP: 
#1. add cmd to wipe stored messages for alias. also way to reset chat logs in vault.
#2. add way to see the date of messages
#3. add functionality for file/dir sending
#4. add tab screen for /whois (alias or key)(no scroll)
#5. add tab screen for /who (scroll)
#6. add tab screen for vault log viewer (scroll)
#7. add tab screen for policy viewing (scroll)
#
# ===================================================================================================================
# ===================================================  Version  =====================================================
# ===================================================================================================================
ptversion = "0.1.02"

import sys
import argparse
import logging
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import bootstrap
from core.engine import Engine
from ui.app import App

def parse_args():
    parser = argparse.ArgumentParser(description="FR3Q: Secure Messenger")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging to file")
    parser.add_argument("--dir", type=str, help="Override config directory (optional)")
    return parser.parse_args()

def main():
    args = parse_args()

    # Boot
    try:
        if args.dir:
            # TODO: Add logic to bootstrap to override get_freq_dir if needed
            pass
            
        bootstrap.ensure_directories()
        # Load global config
        sys_config = bootstrap.load_system_config()
        # Logging
        bootstrap.setup_logging(args.debug)
        logging.debug("########################### Logging session started ###########################")
        logging.info("----- FR3Q STARTED -----")
    except Exception as e:
        loggin.critical(f"Startup Error: {e}")
        print(f"Critical Startup Error: {e}")
        return

    # Init engine
    try:
        engine = Engine(sys_config, ptversion)
        logging.info("Engine initialized.")
    except Exception as e:
        logging.critical(f"Failed to initialize Engine: {e}")
        return

    # Launch UI
    try:
        app = App(engine)
        app.run()
    except Exception as e:
        logging.critical(f"UI Crashed: {e}")
        # Curses fried stdout (maybe)
        sys.stderr.write(f"Application crashed. See logs/debug.log for details.\nError: {e}\n")
    finally:
        # Shutdown
        logging.info("Shutting down...")
        engine.shutdown()
        logging.info("----- FR3Q STOPPED -----")
        logging.debug("########################### Logging session end ###########################")

if __name__ == "__main__":
    main()
