#!/usr/bin/env python3
# ===================================================================================================================
# ===================================================  Version  =====================================================
# ===================================================================================================================
ptversion = "0.0.6"

import sys
import argparse
import logging
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import bootstrap
from core.engine import Engine
from ui.app import App

def parse_args():
    parser = argparse.ArgumentParser(description="FR3Q: Secure P2P Messenger")
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
        bootstrap.setup_logging(args.debug)
        logging.debug("########################### Logging session started ###########################")
        logging.info("----- FR3Q STARTED -----")
        
        # Load global config
        sys_config = bootstrap.load_system_config()

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