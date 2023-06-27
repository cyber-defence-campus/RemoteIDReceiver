import numpy as np
from lte.packetizer import find_packet_candidate_time
from lte.helpers import estimate_offset, fshift, resample


class SpectrumCapture:
    """Class for storing raw captures and providing coarsely packetized Drone ID frames"""
    raw_data: np.array
    sampling_rate: float
    packets: list

    def __init__(self, raw_data=None, Fs=50e6, p_type="droneid", legacy=False):
        """Read capture from file"""
        self.legacy = legacy
        self.raw_data = raw_data
        self.sampling_rate = Fs
        self.packet_type = p_type
        self._packetize_coarse()

    def _packetize_coarse(self):
        """Packetize input data"""
        droneid_found = False

        self.packets, cfo = find_packet_candidate_time(self.raw_data, self.sampling_rate,
                                                       packet_type=self.packet_type, legacy=self.legacy)

        if len(self.packets) > 0:
            droneid_found = True

        if not droneid_found:
            print("Could not verify DroneID packet!")

    def get_packet_samples(self, pktnum=0):
        """Return a Drone ID frame with center frequency corrected and resampled to 15.36 MHz."""
        if pktnum >= len(self.packets):
            raise ValueError("Only %i packets available but you requested packet %i" % (len(self.packets), pktnum))

        packet_data = self.packets[pktnum].copy()

        # correct frequency offset
        print(f"get_packet_samples pkt={pktnum}")
        offset, success = estimate_offset(packet_data, self.sampling_rate)
        if success:
            packet_data = fshift(packet_data, -1.0 * offset, self.sampling_rate)
        else:
            return ValueError("Cannot estimate carrier offset for packet %i" % (pktnum))

        if self.packet_type == "droneid" or self.packet_type == "beacon":
            resample_rate = 15.36e6
        elif self.packet_type == "c2":
            resample_rate = 1.92e6

        # resample to LTE freq
        if self.sampling_rate > resample_rate + .1e6:
            packet_data = resample(packet_data, self.sampling_rate, resample_rate)
        elif self.sampling_rate < resample_rate - .1e6:
            raise ValueError("Your sampling rate is too low")

        return packet_data
