import unittest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta, timezone
from services.drone_service_dji import DroneServiceDji
from models.direct_remote_id import DjiMessage, Base
from models.dtomodels import DroneDto, Position, MinimalDroneDto, FlightPathPointDto
from sqlmodel import create_engine, SQLModel

class TestDroneServiceDji(unittest.TestCase):
    def setUp(self):
        # Create an in-memory SQLite database
        self.engine = create_engine('sqlite:///:memory:')
        
        # Ensure all tables are created
        SQLModel.metadata.create_all(self.engine)
        Base.metadata.create_all(self.engine)

        # Create a configured "Session" class
        self.Session = sessionmaker(bind=self.engine)

        # Create a session
        self._session = self.Session()

        # Initialize the service with the in-memory engine
        self.service = DroneServiceDji(self.engine)

    def tearDown(self):
        # Close the session
        self._session.close()

    def test_get_all_drone_senders(self):
        # Add test data to the session
        self._session.add(DjiMessage(sender_id="sender1", dji_latitude=10.0, dji_longitude=20.0))
        self._session.add(DjiMessage(sender_id="sender2", dji_latitude=10.0, dji_longitude=20.0))
        self._session.commit()

        result = self.service.get_all_drone_senders()
        self.assertEqual(result[0].sender_id, "sender1")
        self.assertEqual(result[1].sender_id, "sender2")

    def test_get_active_drone_senders(self):
        # Add test data to the session
        now = datetime.now(timezone.utc)
        self._session.add(DjiMessage(sender_id="active_sender1", dji_latitude=10.0, dji_longitude=20.0, received_at=now))
        self._session.add(DjiMessage(sender_id="active_sender2", dji_latitude=10.0, dji_longitude=20.0, received_at=now - timedelta(seconds=2)))
        self._session.commit()

        result = self.service.get_active_drone_senders()
        self.assertEqual(result[0].sender_id, "active_sender1")
        self.assertEqual(result[1].sender_id, "active_sender2")

    def test_get_drone_state(self):
        # Add test data to the session
        self._session.add(DjiMessage(
            sender_id="drone1-sender",
            serial_number="drone1",
            dji_latitude=10.0,
            dji_longitude=20.0,
            dji_pilot_latitude=15.0,
            dji_pilot_longitude=25.0,
            dji_height=100,
            dji_x_speed=5,
            dji_y_speed=1,
            dji_yaw=45
        ))
        self._session.commit()

        result = self.service.get_drone_state("drone1-sender")
        expected = DroneDto(
            sender_id="drone1-sender",
            serial_number="drone1",
            position=Position(lat=10.0, lng=20.0),
            pilot_position=Position(lat=15.0, lng=25.0),
            home_position=None,
            rotation=45,
            altitude=100,
            height=100,
            x_speed=5,
            y_speed=1,
            z_speed=None,
            spoofed=True
        )
        self.assertEqual(result, expected)

    def test_get_drone_flight_start_times(self):
        # Add test data to the session
        self._session.add(DjiMessage(sender_id="drone2", received_at=datetime(2023, 1, 1, 12, 0, 0)))
        self._session.add(DjiMessage(sender_id="drone2", received_at=datetime(2023, 1, 1, 12, 5, 0)))
        self._session.add(DjiMessage(sender_id="drone2", received_at=datetime(2023, 1, 1, 12, 10, 0)))
        self._session.commit()

        result = self.service.get_drone_flight_start_times("drone2", timedelta(minutes=3))
        expected = [datetime(2023, 1, 1, 12, 0, 0), datetime(2023, 1, 1, 12, 5, 0), datetime(2023, 1, 1, 12, 10, 0)]
        self.assertEqual(result, expected)

    def test_get_drone_flight_start_times_with_large_timedelta(self):
        # Add test data to the session
        self._session.add(DjiMessage(sender_id="drone3", received_at=datetime(2023, 1, 1, 12, 0, 0)))
        self._session.add(DjiMessage(sender_id="drone3", received_at=datetime(2023, 1, 1, 12, 5, 0)))
        self._session.add(DjiMessage(sender_id="drone3", received_at=datetime(2023, 1, 1, 12, 10, 0)))
        self._session.commit()

        # Use a timedelta greater than the difference between the messages
        result = self.service.get_drone_flight_start_times("drone3", timedelta(minutes=15))
        expected = [datetime(2023, 1, 1, 12, 0, 0)]  # Only the first message should be considered a start time
        self.assertEqual(result, expected)
        
    def test_get_flight_history(self):
        # Add test data to the session
        self._session.add(DjiMessage(sender_id="drone1", received_at=datetime(2023, 1, 1, 12, 0, 0), dji_latitude=10.0, dji_longitude=20.0, dji_height=100))
        self._session.add(DjiMessage(sender_id="drone1", received_at=datetime(2023, 1, 1, 12, 1, 0), dji_latitude=10.1, dji_longitude=20.1, dji_height=101))
        self._session.add(DjiMessage(sender_id="drone1", received_at=datetime(2023, 1, 1, 12, 2, 0), dji_latitude=10.2, dji_longitude=20.2, dji_height=102))
        self._session.commit()

        result = self.service.get_flight_history("drone1", datetime(2023, 1, 1, 12, 0, 0), timedelta(minutes=3))
        
        expected = [
            FlightPathPointDto(
                timestamp=datetime(2023, 1, 1, 12, 0, 0),
                position=Position(lat=10.0, lng=20.0),
                altitude=100
            ),
            FlightPathPointDto(
                timestamp=datetime(2023, 1, 1, 12, 1, 0),
                position=Position(lat=10.1, lng=20.1),
                altitude=101
            ),
            FlightPathPointDto(
                timestamp=datetime(2023, 1, 1, 12, 2, 0),
                position=Position(lat=10.2, lng=20.2),
                altitude=102
            )
        ]
        self.assertEqual(result, expected)

    def test_get_flight_history_with_small_timedelta(self):
        # Add test data to the session
        self._session.add(DjiMessage(sender_id="drone4", received_at=datetime(2023, 1, 1, 12, 0, 0), dji_latitude=10.0, dji_longitude=20.0, dji_height=100))
        self._session.add(DjiMessage(sender_id="drone4", received_at=datetime(2023, 1, 1, 12, 5, 0), dji_latitude=10.1, dji_longitude=20.1, dji_height=101))
        self._session.add(DjiMessage(sender_id="drone4", received_at=datetime(2023, 1, 1, 12, 10, 0), dji_latitude=10.2, dji_longitude=20.2, dji_height=102))
        self._session.commit()
        
        result = self.service.get_flight_history("drone4", datetime(2023, 1, 1, 12, 0, 0), timedelta(seconds=1))
        
        expected = [
            FlightPathPointDto(
                timestamp=datetime(2023, 1, 1, 12, 0, 0),
                position=Position(lat=10.0, lng=20.0),
                altitude=100
            )
        ]
        self.assertEqual(result, expected)

    def test_exists(self):
        # Add test data to the session
        self._session.add(DjiMessage(sender_id="drone1"))
        self._session.commit()

        result = self.service.exists("drone1")
        self.assertTrue(result)

        result = self.service.exists("drone2")
        self.assertFalse(result)

if __name__ == '__main__':
    unittest.main() 