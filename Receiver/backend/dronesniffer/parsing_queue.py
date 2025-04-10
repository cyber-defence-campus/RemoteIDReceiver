import logging
import queue
from concurrent.futures import ThreadPoolExecutor
from scapy.all import Packet 

LOG = logging.getLogger(__name__)

class ParsingQueue:
    def __init__(self, process_packet_function, num_workers=4, max_queue_size=0):
        self.packet_queue = queue.Queue(maxsize=max_queue_size)
        self.executor = ThreadPoolExecutor(max_workers=num_workers)
        self._running = True
        self.process_packet_function = process_packet_function

    def submit(self, packet: Packet):
        try:
            LOG.debug(f"Submitting packet to queue: {packet}")
            self.packet_queue.put_nowait(packet)
        except queue.Full:
            LOG.warning("[!] Packet queue full. Dropping packet.")
        except Exception as e:
            LOG.error(f"Error submitting packet to queue: {e}")

    def _worker_loop(self):
        while self._running:
            packet = self.packet_queue.get()
            if packet is None:
                break
            try:
                LOG.debug(f"Processing packet: {packet}")
                self.process_packet_function(packet)
            except Exception as e:
                LOG.error(f"Error processing packet: {e}")
            finally:
                self.packet_queue.task_done()

    def start(self):
        for _ in range(self.executor._max_workers):
            self.executor.submit(self._worker_loop)

    def stop(self):
        LOG.info("Stopping parsing queue and waiting for all packets to be processed")
        # Wait for the queue to be empty
        self.packet_queue.join()
        
        # Signal workers to stop
        self._running = False
        for _ in range(self.executor._max_workers):
            self.packet_queue.put(None)
            
        # Wait for all workers to finish
        self.executor.shutdown(wait=True)
        LOG.info("Parsing queue stopped successfully")
        