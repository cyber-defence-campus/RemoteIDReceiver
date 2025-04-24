import unittest
from unittest.mock import MagicMock
from scapy.all import Packet
from parsing_queue import ParsingQueue

class TestParsingQueue(unittest.TestCase):
    def setUp(self):
        # Mock the packet processing function
        self.mock_process_packet = MagicMock()
        self.parsing_queue = ParsingQueue(self.mock_process_packet, num_workers=2, max_queue_size=10)

    def test_submit_packet(self):
        packet = Packet()
        self.parsing_queue.submit(packet)
        self.assertFalse(self.parsing_queue.packet_queue.empty())

    def test_process_packet(self):
        packet = Packet()
        self.parsing_queue.submit(packet)
        self.parsing_queue.start()
        self.parsing_queue.stop()
        self.mock_process_packet.assert_called_with(packet)

    def test_stop_queue(self):
        self.parsing_queue.start()
        self.parsing_queue.stop()
        self.assertFalse(self.parsing_queue._running)

    def test_full_queue(self):
        # Fill the queue to its maximum capacity
        for _ in range(10):
            self.parsing_queue.submit(Packet())
        
        # Attempt to submit another packet
        with self.assertLogs('parsing_queue', level='WARNING') as log:
            self.parsing_queue.submit(Packet())
            
        # Check that a warning was logged
        self.assertTrue(any("Packet queue full. Dropping packet." in message for message in log.output))

if __name__ == '__main__':
    unittest.main()
