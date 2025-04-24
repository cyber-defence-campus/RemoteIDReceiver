import unittest
from unittest.mock import MagicMock
from time_buffer import TimeBuffer
import time

class TestTimeBuffer(unittest.TestCase):
    def setUp(self):
        # Mock the on_flush callback function
        self.mock_on_flush = MagicMock()
        self.time_buffer = TimeBuffer(interval_seconds=1, on_flush=self.mock_on_flush)

    def test_add_data(self):
        data = {'key': 'value'}
        self.time_buffer.add(data)
        self.assertIn(data, self.time_buffer.buffer)

    def test_flush_buffer(self):
        data = {'key': 'value'}
        self.time_buffer.add(data)
        self.time_buffer.flush()
        self.mock_on_flush.assert_called_with([data])
        self.assertEqual(len(self.time_buffer.buffer), 0)

    def test_stop_buffer(self):
        self.time_buffer.stop()
        self.assertFalse(self.time_buffer.running)

    def test_flush_loop(self):
        data = {'key': 'value'}
        self.time_buffer.add(data)
        time.sleep(1.5)  # Wait for the flush loop to trigger
        self.mock_on_flush.assert_called_with([data])

if __name__ == '__main__':
    unittest.main() 