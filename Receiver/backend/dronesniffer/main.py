import argparse
import atexit
import logging
import sys
import colorlog
import uvicorn

from api import app
from info_handler import setup_database
from settings import get_settings
from sniffers import sniff_manager

####
# Setup logging
####
formatter = colorlog.ColoredFormatter(
        fmt="%(log_color)s[%(levelname)-8s]%(reset)s %(white)s%(asctime)s -  %(cyan)s%(name)s%(reset)s - %(message_log_color)s%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        log_colors={
            'DEBUG':    'blue',
            'INFO':     'green',
            'WARNING':  'yellow',
            'ERROR':    'red',
            'CRITICAL': 'bold_red',
        },
        secondary_log_colors={
            'message': {
                'DEBUG':    'blue',
                'INFO':     'white',
                'WARNING':  'yellow',
                'ERROR':    'red',
                'CRITICAL': 'bold_red',
            }
        },
        style='%'
    )

handler = colorlog.StreamHandler()
handler.setFormatter(formatter)
root_logger = logging.getLogger()
root_logger.addHandler(handler)
root_logger.setLevel(logging.INFO)

### 
# Logger for this file
###
LOG = logging.getLogger(__name__)

def parse_args() -> argparse.Namespace:
    """
    Parses and returns arguments passed to script.

    Returns:
        Namespace: Parsed arguments.
    """
    arg_parser = argparse.ArgumentParser(prog="Super cool Drone Monitor System")
    arg_parser.add_argument("-p", "--port", help="port", type=int, default=80)
    arg_parser.add_argument("-f", "--file", help="pcap file name")
    arg_parser.add_argument("-l", "--lte", action="store_true", help="sniff on lte")
    return arg_parser.parse_args()


def shutdown() -> None:
    """
    Stops all services, handlers & connections on shutdown.
    """
    sniff_manager.shutdown()


def main():
    args = parse_args()
    port: int = args.port
    file: str = args.file
    lte: bool = args.lte
    lte = None ## Not implemented yet

    logging.info("Setting up database...")
    setup_database()

    # register shutdown manager
    atexit.register(shutdown)

    try:
        if file or lte:
            LOG.info(f"Started with file argument, starting parsing of {file}")
            sniff_manager.parse_file(file, lte=lte)

        LOG.info("Starting sniff manager...")
        settings = get_settings()
        sniff_manager.set_sniffing_interfaces(settings.interfaces)

        LOG.info(f"Starting API on port {port}...")
        uvicorn.run(app, host='0.0.0.0', port=port)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == '__main__':
    main()
