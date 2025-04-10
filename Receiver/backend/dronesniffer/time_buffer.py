import threading
import time
import logging
from typing import Callable, List, Dict

LOG = logging.getLogger(__name__)

class TimeBuffer:
    def __init__(self, interval_seconds: int, on_flush: Callable[[List[Dict]], None]):
        self.interval = interval_seconds
        self.on_flush = on_flush
        self.buffer = []
        self.lock = threading.Lock()
        self.running = True

        self.thread = threading.Thread(target=self._flush_loop, daemon=True)
        self.thread.start()

    def add(self, data: Dict):
        """Add data to the buffer."""
        with self.lock:
            self.buffer.append(data)

    def _flush_loop(self):
        while self.running:
            time.sleep(self.interval)
            self.flush()

    def flush(self):
        """Flush buffer and call on_flush callback."""
        with self.lock:
            if not self.buffer:
                return
            data_to_send = self.buffer
            self.buffer = []
        try:
            self.on_flush(data_to_send)
        except Exception as e:
            logging.error(f"Error in on_flush callback: {e}")

    def stop(self):
        self.running = False
        self.thread.join()