#BUG: IP:
#2. polled vault logs do not have real timestamps
#3. server side conn close client still thinks connected (color is white)
#5. prevent duplicate connections (server should deny the duplicate tho leaves open for dos with spoofed header)
#6. policy blocks do not update ratchet state (counts towards missed msgs)
#7. file transfers are sometimes too quick for server to keep up for larger files. self.network returns None bc connection reset by server bc recv_exact ret none
#8. Pn in ratchet not getting incremented EVER
#
#
# ===================================================================================================================
# ===================================================  Version  =====================================================
# ===================================================================================================================
ptversion = "0.1.07"

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
    global ptversion
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
        if args.debug:
            ptversion += " DBG"
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
