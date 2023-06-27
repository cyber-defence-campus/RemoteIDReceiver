import unittest
from datetime import datetime, timedelta

import api
import pytest
from info_handler import engine
from models import RemoteId, DroneDto, Position, HistoryDto
from pydantic import ValidationError
from sqlmodel import SQLModel, Session


@pytest.fixture
def drone_info_packet():
    return RemoteId(
        oui="12:12:12",
        serial_number="123456789ABCDEFG",
        lng="23.25",
        lat="55.25",
        altitude="412",
        height="1.5",
        pilot_lat="55.0",
        pilot_lng="23.0",
        mode=2,
        uuid="Test_User"
    )


class TestToDroneDTO:
    def test_packet_should_map(self, drone_info_packet):
        # Arrange
        packet = drone_info_packet

        # Act
        result = api.to_drone_dto(packet)

        # Assert
        assert result.serial_number == drone_info_packet.serial_number
        assert result.position.lat == drone_info_packet.lat
        assert result.pilot_position.lat == drone_info_packet.pilot_lat

    def test_drone_to_when_missing_arg_should_raise_error(self):
        # Arrange
        packet = RemoteId(
            serial_number="123456789ABCDEFG",
            pilot_lng="23.25",
            pilot_lat="55.25",
        )

        # Act & Assert
        with pytest.raises(ValidationError):
            api.to_drone_dto(packet)


class TestApi(unittest.TestCase):

    def setUp(self):
        SQLModel.metadata.drop_all(engine)
        SQLModel.metadata.create_all(engine)

        # add data
        now = datetime.now()
        old = datetime.now() - timedelta(days=30)
        self.now = now
        self.old = old
        with Session(engine) as session:
            session.add_all([
                # drone with multiple timestamps
                RemoteId(
                    serial_number="123",
                    oui="123",
                    uuid="123",
                    timestamp=now,
                    lat=12.34,
                    lng=42.12
                ), RemoteId(
                    serial_number="123",
                    oui="123",
                    uuid="123",
                    timestamp=now - timedelta(seconds=1),
                    lat=12.33,
                    lng=42.11
                ), RemoteId(
                    serial_number="123",
                    oui="123",
                    uuid="123",
                    timestamp=now - timedelta(seconds=2),
                    lat=12.32,
                    lng=42.10
                ), RemoteId(
                    serial_number="123",
                    oui="123",
                    uuid="123",
                    timestamp=now - timedelta(seconds=3),
                    lat=12.31,
                    lng=42.09
                ),
                # other drone with two timestamps slightly in the past and a flight in the past
                RemoteId(
                    serial_number="321",
                    oui="123",
                    uuid="123",
                    timestamp=now - timedelta(seconds=2),
                    lat=1.0,
                    lng=2.0,
                    pilot_lat=3.0,
                    pilot_lng=4.0
                ), RemoteId(
                    serial_number="321",
                    oui="123",
                    uuid="123",
                    timestamp=now - timedelta(seconds=3),
                    lat=1.1,
                    lng=2.1,
                    pilot_lat=3.1,
                    pilot_lng=4.1
                ), RemoteId(
                    serial_number="321",
                    oui="123",
                    uuid="123",
                    timestamp=now - timedelta(seconds=4),
                    lat=1.2,
                    lng=2.2,
                    pilot_lat=3.2,
                    pilot_lng=4.2
                ), RemoteId(
                    serial_number="321",
                    oui="123",
                    uuid="123",
                    timestamp=now - timedelta(seconds=5),
                    lat=1.3,
                    lng=2.3,
                    pilot_lat=3.3,
                    pilot_lng=4.3
                ), RemoteId(
                    serial_number="321",
                    oui="123",
                    uuid="123",
                    timestamp=old,
                    lat=1.0,
                    lng=1.1
                ), RemoteId(
                    serial_number="321",
                    oui="123",
                    uuid="123",
                    timestamp=old - timedelta(seconds=3),
                    lat=2.0,
                    lng=2.1
                ),
                # two old drones that should no longer be considered active
                RemoteId(
                    serial_number="222",
                    oui="123",
                    uuid="123",
                    timestamp=now - timedelta(minutes=10) - timedelta(microseconds=1),
                    lat=12.32,
                    lng=42.10
                ), RemoteId(
                    serial_number="223",
                    oui="123",
                    uuid="123",
                    timestamp=now - timedelta(days=3),
                    lat=12.31,
                    lng=42.09
                ),
            ])
            session.commit()

    def test_get_active_drones(self):
        actual = api.get_active_drones()
        self.assertEqual([
            DroneDto(
                serial_number="123",
                position=Position(lat=12.34, lng=42.12)
            ), DroneDto(
                serial_number="321",
                position=Position(lat=1.0, lng=2.0),
                pilot_position=Position(lat=3.0, lng=4.0)
            )
        ], actual)

    def test_get_all_drones(self):
        actual = api.get_all_drones()
        self.assertEqual([
            DroneDto(
                serial_number="123",
                position=Position(lat=12.34, lng=42.12)
            ), DroneDto(
                serial_number="222",
                position=Position(lat=12.32, lng=42.10)
            ), DroneDto(
                serial_number="223",
                position=Position(lat=12.31, lng=42.09)
            ), DroneDto(
                serial_number="321",
                position=Position(lat=1.0, lng=2.0),
                pilot_position=Position(lat=3.0, lng=4.0)
            )
        ], actual)

    def test_get_history(self):
        actual = api.get_history("321")
        self.assertEqual([
            HistoryDto(
                timestamp=self.now - timedelta(seconds=5),
                pos=Position(lat=1.3, lng=2.3),
                pilot_pos=Position(lat=3.3, lng=4.3)
            ), HistoryDto(
                timestamp=self.now - timedelta(seconds=4),
                pos=Position(lat=1.2, lng=2.2),
                pilot_pos=Position(lat=3.2, lng=4.2)
            ), HistoryDto(
                timestamp=self.now - timedelta(seconds=3),
                pos=Position(lat=1.1, lng=2.1),
                pilot_pos=Position(lat=3.1, lng=4.1)
            ), HistoryDto(
                timestamp=self.now - timedelta(seconds=2),
                pos=Position(lat=1.0, lng=2.0),
                pilot_pos=Position(lat=3.0, lng=4.0)
            )
        ], actual)

    def test_get_flights(self):
        actual = api.get_flights("321")
        self.assertEqual([
            self.old - timedelta(seconds=3),
            self.now - timedelta(seconds=5)
        ], actual)

    def test_get_flight_history(self):
        flight = self.old - timedelta(seconds=3)
        actual = api.get_flight_history("321", flight)
        self.assertEqual([
            HistoryDto(
                timestamp=flight,
                pos=Position(lat=2.0, lng=2.1),
                pilot_pos=None
            ), HistoryDto(
                timestamp=self.old,
                pos=Position(lat=1.0, lng=1.1),
                pilot_pos=None
            )
        ], actual)


if __name__ == "__main__":
    unittest.main()
