import threading
import time
import logging
from typing import Callable, List, Dict

LOG = logging.getLogger(__name__)

class TimeBuffer:
    
    __interval_s: int
    __on_flush: Callable[[List[Dict]], None]
    __buffer: List[Dict]
    __lock: threading.Lock
    __running: bool
    
    def __init__(self, interval_seconds: int, on_flush: Callable[[List[Dict]], None]):
        self.__interval_s = interval_seconds
        self.__on_flush = on_flush
        self.__buffer = []
        self.__lock = threading.Lock()
        self.__running = True

        self.thread = threading.Thread(target=self.__flush_loop, daemon=True)
        self.thread.start()

    def add(self, data: Dict):
        """Add data to the buffer."""
        with self.__lock:
            self.__buffer.append(data)

    def __flush_loop(self):
        while self.__running:
            time.sleep(self.__interval_s)
            self.flush()

    def flush(self):
        """Flush buffer and call on_flush callback."""
        with self.__lock:
            if not self.__buffer:
                return
            data_to_send = self.__buffer
            self.__buffer = []
        try:
            self.__on_flush(data_to_send)
        except Exception as e:
            logging.error(f"Error in on_flush callback: {e}")

    def stop(self):
        self.__running = False
        self.thread.join()