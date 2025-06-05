import unittest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from datetime import datetime
from api.ads_stan_api import router
from models.direct_remote_id import BasicIdMessage, LocationMessage, SelfIdMessage, SystemMessage, OperatorMessage

class TestAdsStanApi(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(router)
    
    @patch('api.ads_stan_api.Session')
    def test_get_basic_id_messages(self, mock_session):
        # Setup mock session and query
        mock_session_instance = MagicMock()
        mock_query = MagicMock()
        mock_session.return_value.__enter__.return_value = mock_session_instance
        mock_session_instance.query.return_value = mock_query
        mock_query.all.return_value = [
            BasicIdMessage(sender_id="test_sender_1", uas_id="uas_id_1", received_at=datetime.now()),
            BasicIdMessage(sender_id="test_sender_2", uas_id="uas_id_2", received_at=datetime.now())
        ]
        
        # Test API endpoint
        response = self.client.get("/api/ads_stan/basic_id")
        
        # Verify response status code
        self.assertEqual(response.status_code, 200)
        
        # Verify response content
        data = response.json()
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]["sender_id"], "test_sender_1")
        self.assertEqual(data[1]["sender_id"], "test_sender_2")
        
        # Verify query was called correctly
        mock_session_instance.query.assert_called_once_with(BasicIdMessage)
    
    @patch('api.ads_stan_api.Session')
    def test_get_location_messages(self, mock_session):
        # Setup mock session and query
        mock_session_instance = MagicMock()
        mock_query = MagicMock()
        mock_session.return_value.__enter__.return_value = mock_session_instance
        mock_session_instance.query.return_value = mock_query
        mock_query.all.return_value = [
            LocationMessage(sender_id="test_sender_1", latitude=10.0, longitude=20.0, received_at=datetime.now()),
            LocationMessage(sender_id="test_sender_2", latitude=11.0, longitude=21.0, received_at=datetime.now())
        ]
        
        # Test API endpoint
        response = self.client.get("/api/ads_stan/location")
        
        # Verify response status code
        self.assertEqual(response.status_code, 200)
        
        # Verify response content
        data = response.json()
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]["sender_id"], "test_sender_1")
        self.assertEqual(data[0]["latitude"], 10.0)
        self.assertEqual(data[0]["longitude"], 20.0)
        
        # Verify query was called correctly
        mock_session_instance.query.assert_called_once_with(LocationMessage)
    
    @patch('api.ads_stan_api.Session')
    def test_get_self_id_messages(self, mock_session):
        # Setup mock session and query
        mock_session_instance = MagicMock()
        mock_query = MagicMock()
        mock_session.return_value.__enter__.return_value = mock_session_instance
        mock_session_instance.query.return_value = mock_query
        mock_query.all.return_value = [
            SelfIdMessage(sender_id="test_sender_1", description="Test Drone", description_type=1, received_at=datetime.now())
        ]
        
        # Test API endpoint
        response = self.client.get("/api/ads_stan/self_id")
        
        # Verify response status code
        self.assertEqual(response.status_code, 200)
        
        # Verify response content
        data = response.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["sender_id"], "test_sender_1")
        self.assertEqual(data[0]["description"], "Test Drone")
        
        # Verify query was called correctly
        mock_session_instance.query.assert_called_once_with(SelfIdMessage)
    
    @patch('api.ads_stan_api.Session')
    def test_get_system_messages(self, mock_session):
        # Setup mock session and query
        mock_session_instance = MagicMock()
        mock_query = MagicMock()
        mock_session.return_value.__enter__.return_value = mock_session_instance
        mock_session_instance.query.return_value = mock_query
        mock_query.all.return_value = [
            SystemMessage(
                sender_id="test_sender_1", 
                ua_category=1, 
                ua_class=2, 
                classification_type=1,
                location_source=2,
                pilot_latitude=10.0,
                pilot_longitude=20.0,
                received_at=datetime.now()
            )
        ]
        
        # Test API endpoint
        response = self.client.get("/api/ads_stan/system")
        
        # Verify response status code
        self.assertEqual(response.status_code, 200)
        
        # Verify response content
        data = response.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["sender_id"], "test_sender_1")
        self.assertEqual(data[0]["pilot_latitude"], 10.0)
        self.assertEqual(data[0]["pilot_longitude"], 20.0)
        
        # Verify query was called correctly
        mock_session_instance.query.assert_called_once_with(SystemMessage)
    
    @patch('api.ads_stan_api.Session')
    def test_get_operator_messages(self, mock_session):
        # Setup mock session and query
        mock_session_instance = MagicMock()
        mock_query = MagicMock()
        mock_session.return_value.__enter__.return_value = mock_session_instance
        mock_session_instance.query.return_value = mock_query
        mock_query.all.return_value = [
            OperatorMessage(
                sender_id="test_sender_1", 
                operator_id="op123", 
                operator_id_type=1,
                received_at=datetime.now()
            )
        ]
        
        # Test API endpoint
        response = self.client.get("/api/ads_stan/operator")
        
        # Verify response status code
        self.assertEqual(response.status_code, 200)
        
        # Verify response content
        data = response.json()
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["sender_id"], "test_sender_1")
        self.assertEqual(data[0]["operator_id"], "op123")
        
        # Verify query was called correctly
        mock_session_instance.query.assert_called_once_with(OperatorMessage)


if __name__ == '__main__':
    unittest.main() 