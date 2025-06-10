import logging
import queue
from concurrent.futures import ThreadPoolExecutor

LOG = logging.getLogger(__name__)

class LimitedThreadPoolExecutor(ThreadPoolExecutor):
    def __init__(self, max_queue_size=50, *args, **kwargs):
        super(LimitedThreadPoolExecutor, self).__init__(*args, **kwargs)
        self._work_queue = queue.Queue(maxsize=max_queue_size)