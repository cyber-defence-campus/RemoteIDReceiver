#!/usr/bin/env python3

import numpy as np
import scipy.signal as signal
from lte.helpers import estimate_offset


def find_packet_candidate_time(raw_data, Fs, packet_type="droneid", legacy=False):
    """Find packets with the right length by looking at signal power"""
    # for Mavic 2: around 576e-6 => symbol 0 missing
    # 8 * 72e-7

    if packet_type == "droneid":
        if legacy:
            min_packet_len_t = 565e-6
            max_packet_len_t = 600e-6
        else:
            min_packet_len_t = 630e-6
            max_packet_len_t = 665e-6
    elif packet_type == "c2":
        min_packet_len_t = 500e-6
        max_packet_len_t = 520e-6
    elif packet_type == "beacon":
        min_packet_len_t = 490e-6
        max_packet_len_t = 540e-6
    elif packet_type == "pairing":
        min_packet_len_t = 490e-6
        max_packet_len_t = 540e-6
    elif packet_type == "video":
        min_packet_len_t = 630e-6
        max_packet_len_t = 665e-6

    print("Packet Type:", packet_type)
    start_offset = 3 * 15e-6
    end_offset = 3 * 15e-6

    f, t, Zxx = signal.stft(raw_data, Fs, nfft=64, nperseg=64)
    res_abs = np.max(np.abs(Zxx), axis=0)
    noise_floor = np.mean(np.abs(Zxx))

    # get things above the noise floor
    above_level = res_abs > 1.15 * noise_floor

    # search for chunks above noise floor that fit the packet length
    signal_length_min_samples = int(min_packet_len_t / (t[1] - t[0]))  # packet duration to samples
    signal_length_max_samples = int(max_packet_len_t / (t[1] - t[0]))  # packet duration to samples
    peaks, properties = signal.find_peaks(above_level, width=[signal_length_min_samples, signal_length_max_samples],
                                          wlen=100 * signal_length_max_samples)

    packets = []
    center_freq_offset = 0

    for i, _ in enumerate(peaks):
        start = properties["left_bases"][i] * (t[1] - t[0])  # samples to time
        end = properties["right_bases"][i] * (t[1] - t[0])
        length = properties["widths"][i] * (t[1] - t[0])

        packet_data = raw_data[int((start - start_offset) * Fs):int((end + end_offset) * Fs)]

        # estimate center frequency offset (only successful if packet is 10 MHz)
        center_freq_offset, found = estimate_offset(packet_data, Fs)

        if not found:
            continue

        print(center_freq_offset)
        print("Packet #%i, start %f, end %f, length %f, cfo %f" % (i, start, end, length, center_freq_offset))
        packets.append(packet_data)

    return packets, center_freq_offset
