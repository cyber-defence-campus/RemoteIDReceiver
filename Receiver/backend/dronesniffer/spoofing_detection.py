from geopy import distance

from models import Position


def is_spoofed(drone_pos: Position, operator_pos: Position) -> bool:
    """
    Checks if two positions are further away from each other than 15 km (defined by CYD). Also, it checks if one of
    the position is empty, which results in the function returning True.

    Args:
        drone_pos (Position): Location of drone.
        operator_pos (Position): Location of operator.

    Returns:
        bool: True, if location may be spoofed, otherwise False.

    """
    if not drone_pos.lng or not drone_pos.lat or not operator_pos.lng or not operator_pos.lat:
        return False
    distance_km = distance.geodesic((drone_pos.lat, drone_pos.lng), (operator_pos.lat, operator_pos.lng)).km
    if distance_km > 15:
        return True
    return False
