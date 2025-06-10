import unittest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from datetime import datetime
from api.dji_api import router
from models.direct_remote_id import DjiMessage

class TestDjiApi(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(router)
    
    @patch('api.dji_api.Session')
    def test_get_all_dji_messages_no_filter(self, mock_session):
        # Setup mock session and query
        mock_session_instance = MagicMock()
        mock_query = MagicMock()
        mock_ordered_query = MagicMock()
        mock_session.return_value.__enter__.return_value = mock_session_instance
        mock_session_instance.query.return_value = mock_query
        mock_query.order_by.return_value = mock_ordered_query
        
        # Create test data
        test_time = datetime.now()
        mock_ordered_query.all.return_value = [
            DjiMessage(
                id=1,
                message_type=1,
                version=1,
                sender_id="test_sender_1",
                received_at=test_time,
                serial_number="SN12345",
                dji_longitude=20.0,
                dji_latitude=10.0,
                dji_height=50.0,
                dji_x_speed=5.0,
                dji_y_speed=3.0,
                dji_yaw=45.0,
                dji_pilot_latitude=11.0,
                dji_pilot_longitude=21.0
            ),
            DjiMessage(
                id=2,
                message_type=1,
                version=1,
                sender_id="test_sender_2",
                received_at=test_time,
                serial_number="SN67890",
                dji_longitude=22.0,
                dji_latitude=12.0,
                dji_height=60.0,
                dji_x_speed=6.0,
                dji_y_speed=4.0,
                dji_yaw=50.0,
                dji_pilot_latitude=13.0,
                dji_pilot_longitude=23.0
            )
        ]
        
        # Test API endpoint
        response = self.client.get("/api/dji/all")
        
        # Verify response status code
        self.assertEqual(response.status_code, 200)
        
        # Verify response content
        data = response.json()
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]["id"], 1)
        self.assertEqual(data[0]["sender_id"], "test_sender_1")
        self.assertEqual(data[0]["serial_number"], "SN12345")
        self.assertEqual(data[0]["dji_latitude"], 10.0)
        self.assertEqual(data[0]["dji_longitude"], 20.0)
        self.assertEqual(data[1]["id"], 2)
        self.assertEqual(data[1]["sender_id"], "test_sender_2")
        
        # Verify query was called correctly
        mock_session_instance.query.assert_called_once_with(DjiMessage)
        mock_query.filter.assert_not_called()
        mock_query.order_by.assert_called_once()
    
    @patch('api.dji_api.Session')
    def test_get_all_dji_messages_with_filter(self, mock_session):
        # Setup mock session and query
        mock_session_instance = MagicMock()
        mock_query = MagicMock()
        mock_filtered_query = MagicMock()
        mock_ordered_query = MagicMock()
        mock_session.return_value.__enter__.return_value = mock_session_instance
        mock_session_instance.query.return_value = mock_query
        mock_query.filter.return_value = mock_filtered_query
        mock_filtered_query.order_by.return_value = mock_ordered_query
        
        # Create test data
        test_time = datetime.now()
        mock_ordered_query.all.return_value = [
            DjiMessage(
                id=1,
                message_type=1,
                version=1,
                sender_id="test_sender_1",
                received_at=test_time,
                serial_number="SN12345",
                dji_longitude=20.0,
                dji_latitude=10.0,
                dji_height=50.0,
                dji_x_speed=5.0,
                dji_y_speed=3.0,
                dji_yaw=45.0,
                dji_pilot_latitude=11.0,
                dji_pilot_longitude=21.0
            )
        ]
        
        # Test API endpoint
        response = self.client.get("/api/dji/all?sender_id=test_sender_1")
        
        # Verify response status code
        self.assertEqual(response.status_code, 200)
        
        # Verify response content
        data = response.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["id"], 1)
        self.assertEqual(data[0]["sender_id"], "test_sender_1")
        self.assertEqual(data[0]["serial_number"], "SN12345")
        
        # Verify query was called correctly
        mock_session_instance.query.assert_called_once_with(DjiMessage)
        mock_query.filter.assert_called_once()
        mock_filtered_query.order_by.assert_called_once()
    
    @patch('api.dji_api.Session')
    def test_get_all_dji_messages_empty_result(self, mock_session):
        # Setup mock session and query
        mock_session_instance = MagicMock()
        mock_query = MagicMock()
        mock_ordered_query = MagicMock()
        mock_session.return_value.__enter__.return_value = mock_session_instance
        mock_session_instance.query.return_value = mock_query
        mock_query.order_by.return_value = mock_ordered_query
        mock_ordered_query.all.return_value = []
        
        # Test API endpoint
        response = self.client.get("/api/dji/all")
        
        # Verify response status code
        self.assertEqual(response.status_code, 200)
        
        # Verify response content is an empty list
        self.assertEqual(response.json(), [])
        
        # Verify query was called correctly
        mock_session_instance.query.assert_called_once_with(DjiMessage)


if __name__ == '__main__':
    unittest.main() 