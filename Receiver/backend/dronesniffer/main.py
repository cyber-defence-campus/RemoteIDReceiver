import argparse
import logging
import sys
import colorlog
import uvicorn
import signal

from api.api import app
from info_handler import setup_database
from settings import get_settings
from sniffers import SniffManager
from packet_processor import process_packet
from parsing_queue import ParsingQueue

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


def shutdown(sniff_manager, parsing_queue) -> None:
    """
    Stops all services, handlers & connections on shutdown.
    """
    def stop_sniffing(signum, frame) -> None:
        LOG.info("Received shutdown signal, stopping sniffing...")
        sniff_manager.shutdown()

        LOG.info("Stopping parsing queue...")
        parsing_queue.stop()
    
    return stop_sniffing
    


def main():
    args = parse_args()
    port: int = args.port
    file: str = args.file
    lte: bool = args.lte
    lte = None ## Not implemented yet

    logging.info("Setting up database...")
    setup_database()

    
    # Parsing Queue.
    # Whenever a packet is received, it will be submitted to the queue
    # and processed by the worker threads.
    parsing_queue = ParsingQueue(process_packet_function=process_packet, num_workers=1000, max_queue_size=0)
    
    # setup sniff manager
    # whenever a message is sniffed, it will be passed to the parsing queue
    sniff_manager = SniffManager(on_packet_received=parsing_queue.submit)


    # setup signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, shutdown(sniff_manager, parsing_queue))
    signal.signal(signal.SIGTERM, shutdown(sniff_manager, parsing_queue))

    try:
        if file or lte:
            LOG.info(f"Started with file argument, starting parsing of {file}")
            sniff_manager.parse_file(file, lte=lte)
            parsing_queue.start()

        
        # Start sniffing on the interfaces 
        settings = get_settings()
        interfaces = settings.interfaces 
        sniff_manager.set_sniffing_interfaces(interfaces)

        LOG.info(f"Starting API on port {port}...")
        uvicorn.run(app, host='0.0.0.0', port=port)
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == '__main__':
    main()
