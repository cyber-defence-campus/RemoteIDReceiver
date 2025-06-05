import unittest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from models.dtomodels import MinimalDroneDto, Position, DroneDto, FlightPathPointDto
from typing import List
from api.drone_api import router, get_active_drones
from datetime import datetime, timedelta

class TestDroneApi(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(router)
        
    @patch('api.drone_api.drone_serive_ads')
    @patch('api.drone_api.drone_service_dji')
    def test_get_active_drones_api_endpoint(self, mock_dji_service, mock_ads_service):
        # Setup mock return values
        mock_ads_service.get_active_drone_senders.return_value = [
            MinimalDroneDto(sender_id="ads_drone1", position=Position(lat=10.0, lng=20.0))
        ]
        mock_dji_service.get_active_drone_senders.return_value = [
            MinimalDroneDto(sender_id="dji_drone1", position=Position(lat=12.0, lng=22.0))
        ]
        
        # Test the API endpoint
        response = self.client.get("/drones/active")
        
        # Verify response status code
        self.assertEqual(response.status_code, 200)
        
        # Verify response content
        data = response.json()
        self.assertEqual(len(data), 2)
        
        # Check that drone IDs are in the response
        drone_ids = [drone["sender_id"] for drone in data]
        self.assertIn("ads_drone1", drone_ids)
        self.assertIn("dji_drone1", drone_ids)
        
    @patch('api.drone_api.drone_serive_ads')
    @patch('api.drone_api.drone_service_dji')
    def test_get_active_drones_empty_result(self, mock_dji_service, mock_ads_service):
        # Setup mock return values for empty results
        mock_ads_service.get_active_drone_senders.return_value = []
        mock_dji_service.get_active_drone_senders.return_value = []
        
        # Call the function directly
        result = get_active_drones()
        
        # Verify the result is an empty list
        self.assertEqual(result, [])
        
        # Test the API endpoint
        response = self.client.get("/drones/active")
        
        # Verify response status code
        self.assertEqual(response.status_code, 200)
        
        # Verify response content is an empty list
        self.assertEqual(response.json(), [])
    
    @patch('api.drone_api.drone_serive_ads')
    @patch('api.drone_api.drone_service_dji')
    def test_get_all_drones(self, mock_dji_service, mock_ads_service):
        # Setup mock return values
        mock_ads_service.get_all_drone_senders.return_value = [
            MinimalDroneDto(sender_id="ads_drone1", position=Position(lat=10.0, lng=20.0)),
            MinimalDroneDto(sender_id="ads_drone2", position=Position(lat=11.0, lng=21.0))
        ]
        mock_dji_service.get_all_drone_senders.return_value = [
            MinimalDroneDto(sender_id="dji_drone1", position=Position(lat=12.0, lng=22.0))
        ]
        
        # Test the API endpoint
        response = self.client.get("/drones/all")
        
        # Verify response status code
        self.assertEqual(response.status_code, 200)
        
        # Verify response content
        data = response.json()
        self.assertEqual(len(data), 3)
        
        # Check that drone IDs are in the response
        drone_ids = [drone["sender_id"] for drone in data]
        self.assertIn("ads_drone1", drone_ids)
        self.assertIn("ads_drone2", drone_ids)
        self.assertIn("dji_drone1", drone_ids)
    
    @patch('api.drone_api.get_drone_service')
    def test_get_drone(self, mock_get_drone_service):
        # Setup mock service and return value
        mock_service = MagicMock()
        mock_service.get_drone_state.return_value = DroneDto(
            sender_id="test_drone-sender",
            serial_number="test_drone", 
            position=Position(lat=10.0, lng=20.0),
            pilot_position=Position(lat=11.0, lng=21.0),
            home_position=Position(lat=12.0, lng=22.0),
            rotation=45.0,
            altitude=100,
            height=50,
            x_speed=5.0,
            y_speed=3.0,
            z_speed=0.0
        )
        mock_get_drone_service.return_value = mock_service
        
        # Test the API endpoint
        response = self.client.get("/drones/test_drone-sender")
        
        # Verify response status code
        self.assertEqual(response.status_code, 200)
        
        # Verify the service was called with correct parameters
        mock_get_drone_service.assert_called_once_with("test_drone-sender")
        mock_service.get_drone_state.assert_called_once_with("test_drone-sender")
        
        # Verify response content
        data = response.json()
        self.assertEqual(data["serial_number"], "test_drone")
        self.assertEqual(data["position"]["lat"], 10.0)
        self.assertEqual(data["position"]["lng"], 20.0)
    
    @patch('api.drone_api.get_drone_service')
    @patch('api.drone_api.get_activity_offset')
    def test_get_flights(self, mock_get_activity_offset, mock_get_drone_service):
        # Setup mocks
        mock_service = MagicMock()
        mock_offset = timedelta(minutes=10)
        flight_times = [
            datetime(2023, 1, 1, 10, 0),
            datetime(2023, 1, 1, 14, 0)
        ]
        
        mock_service.get_drone_flight_start_times.return_value = flight_times
        mock_get_drone_service.return_value = mock_service
        mock_get_activity_offset.return_value = mock_offset
        
        # Test the API endpoint
        response = self.client.get("/drones/test_drone/flights")
        
        # Verify response status code
        self.assertEqual(response.status_code, 200)
        
        # Verify the service was called with correct parameters
        mock_get_drone_service.assert_called_once_with("test_drone")
        mock_service.get_drone_flight_start_times.assert_called_once_with("test_drone", mock_offset)
        
        # Verify response content - need to handle datetime serialization in the response
        data = response.json()
        self.assertEqual(len(data), 2)
    
    @patch('api.drone_api.get_drone_service')
    @patch('api.drone_api.get_activity_offset')
    def test_get_flight_history(self, mock_get_activity_offset, mock_get_drone_service):
        # Setup mocks
        mock_service = MagicMock()
        mock_offset = timedelta(minutes=10)
        flight_time = "2023-01-01T10:00:00"
        history_data: List[FlightPathPointDto] = [
            FlightPathPointDto(
                timestamp=datetime(2023, 1, 1, 10, 0, 0),
                position=Position(lat=10.0, lng=20.0),
                altitude=100
            ),
            FlightPathPointDto(
                timestamp=datetime(2023, 1, 1, 10, 1, 0),
                position=Position(lat=10.1, lng=20.1),
                altitude=101
            )
        ]
        
        mock_service.get_flight_history.return_value = history_data
        mock_get_drone_service.return_value = mock_service
        mock_get_activity_offset.return_value = mock_offset
        
        # Test the API endpoint
        response = self.client.get(f"/drones/test_drone/flights/{flight_time}")
        
        # Verify response status code
        self.assertEqual(response.status_code, 200)
        
        # Verify the service was called with correct parameters
        mock_get_drone_service.assert_called_once()
        mock_service.get_flight_history.assert_called_once()
        
        # Verify response content
        data = response.json()
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]["position"]["lat"], 10.0)
        self.assertEqual(data[1]["position"]["lat"], 10.1)
    

if __name__ == '__main__':
    unittest.main() 