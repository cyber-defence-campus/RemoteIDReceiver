#!/usr/bin/env python3

import argparse
import logging
from threading import Event

import numpy as np

from info_handler import save_drone_info
from lte.SpectrumCapture import SpectrumCapture
from lte.Packet import Packet
from lte.qpsk import Decoder
from parsers import DjiParser


def lte_sniffer(stop_event: Event,
                input_file: str = None,
                sample_rate: float = None,
                legacy: bool = None,
                disable_zc_detection: bool = None):
    """Decode capture file"""
    if not input_file:
        logging.error("Input file is missing.")
        return
    if not sample_rate:
        sample_rate = 50e6
    if not legacy:
        legacy = False
    if not disable_zc_detection:
        disable_zc_detection = True

    raw = np.memmap(input_file, mode='r', dtype="<f").astype(np.float32).view(np.complex64)

    packets_decoded = 0
    crc_error = 0

    drone_coords = []
    app_coords = []

    chunk_samples = int(500e-3 * sample_rate)  # in seconds
    chunks = len(raw) // chunk_samples + 1

    for i in range(chunks):
        print("Drone-ID Frame Detection")

        capture = SpectrumCapture(raw[i * chunk_samples:(i + 1) * chunk_samples],
                                  Fs=sample_rate, legacy=legacy)
        print(f"\nFound {len(capture.packets)} Drone-ID RF frames in spectrum capture.")

        for packet_num, _ in enumerate(capture.packets):
            if stop_event.is_set():
                logging.info("Script interrupted.")
                return
            remote_id = None

            print(f"################## Decoding Frame {packet_num + 1}/{len(capture.packets)} ##################")

            # get a Drone ID frame, resampled and with coarse center frequency correction.
            packet_data = capture.get_packet_samples(pktnum=packet_num)

            try:
                packet = Packet(packet_data, enable_zc_detection=not disable_zc_detection,
                                legacy=legacy)
            except Exception as error:
                print(f"Demodulation FAILED (Frame {packet_num + 1}): {error}")
                continue

            # symbol data with corrections applied
            symbols = packet.get_symbol_data(skip_zc=True)
            decoder = Decoder(symbols)

            # brute force QPSK alignment
            for phase_corr in range(4):
                decoder.raw_data_to_symbol_bits(phase_corr)
                droneid_duml = decoder.magic()

                try:
                    remote_id = DjiParser.parse_version_2_lte(droneid_duml, DjiParser.oui[0])
                except Exception as err:
                    print("---- EXCEPTION while Parsing ----")
                    print(err)
                    continue

                if not remote_id:
                    continue

                print(f"## Drone-ID Payload ##")
                print(remote_id)

                drone_lat = remote_id.lat
                drone_lon = remote_id.lng
                app_lat = remote_id.pilot_lat
                app_lon = remote_id.pilot_lng
                height = remote_id.height
                # congrats, you received a valid Drone-ID packet
                packets_decoded += 1

                if drone_lat != 0.0 and drone_lon != 0.0:
                    drone_coords.append((drone_lat, drone_lon, height))

                if app_lat != 0.0 and app_lon != 0.0:
                    app_coords.append((app_lat, app_lon))

                # we're done for this packet
                break

            if not remote_id:
                print(f"Frame {packet_num + 1}/{len(capture.packets)}: Decoding failed.")
            else:
                save_drone_info(remote_id)

    print("\n\n")
    print(f"Frame detection: {len(capture.packets)} candidates")
    print(f"Decoder: {packets_decoded + crc_error} total, CRC OK: {packets_decoded} ({crc_error} CRC errors)")

    print("Drone Coordinates:")
    for coords in drone_coords:
        print(coords)

    print("App Coordinates:")
    for coords in app_coords:
        print(coords)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input-file', default="./resources/mini2_sm", help="Binary Sample Input")
    parser.add_argument('-s', '--sample-rate', default="50e6", type=float, help="Sample Rate")
    parser.add_argument('-l', '--legacy', default=False, action="store_true",
                        help="Support of legacy drones (Mavic Pro, Mavic 2)")
    parser.add_argument('-z', '--disable-zc-detection', default=True, action="store_false",
                        help="Disable per-symbol ZC sequence detection (faster)")
    args = parser.parse_args()

    lte_sniffer(args.input_file, args.sample_rate, args.legacy, args.disable_zc_detection)
