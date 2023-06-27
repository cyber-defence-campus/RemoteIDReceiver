import pytest
from models.settings import Settings
from pydantic import ValidationError


class TestSettings:

    @pytest.mark.parametrize(
        "gmaps_key,activity_offset,drone_size,perf_mode",
        [
            ("abc", 1, 1, True),
            ("def", 60, 10, False),
            ("sdfkjskljfklsjk", 30, 5, False),
            (None, 1, 1, True),
        ]
    )
    def test_valid_settings(self, gmaps_key, activity_offset, drone_size, perf_mode):
        settings = Settings(
            google_maps_api_key=gmaps_key,
            activity_offset_in_m=activity_offset,
            drone_size_in_rem=drone_size,
            performance_mode=perf_mode
        )
        assert settings.google_maps_api_key == gmaps_key
        assert settings.activity_offset_in_m == activity_offset
        assert settings.drone_size_in_rem == drone_size

    def test_defaults(self):
        settings = Settings(google_maps_api_key="abc")
        assert settings.google_maps_api_key == "abc"
        assert settings.activity_offset_in_m == 10
        assert settings.drone_size_in_rem == 5
        assert settings.performance_mode is False

    @pytest.mark.parametrize("gmaps_key", ["", " ", "\t", "\n"])
    def test_invalid_gmaps_key(self, gmaps_key):
        with pytest.raises(ValidationError):
            Settings(google_maps_api_key=gmaps_key)

    @pytest.mark.parametrize("activity_offset", [-1, 0, 61])
    def test_invalid_activity_offset(self, activity_offset):
        with pytest.raises(ValidationError):
            Settings(activity_offset_in_m=activity_offset)

    @pytest.mark.parametrize("drone_size", [-1, 0, 11])
    def test_invalid_drone_size(self, drone_size):
        with pytest.raises(ValidationError):
            Settings(drone_size_in_rem=drone_size)
