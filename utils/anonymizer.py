#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# anonymizer.py
#
# based on https://github.com/adriangranados/dot11anonymizer/

import argparse
import inspect
import logging
import logging.config
import os
import platform
import struct
import sys
import zlib
import textwrap

from scapy.all import Dot11, Dot11Elt, PcapReader, PcapWriter, RadioTap, scapy, Dot11FCS

__version__ = "1"


def setup_logger(args) -> logging.Logger:
    """ Configure and set logging levels """
    if args.logging:
        if args.logging == "debug":
            logging_level = logging.DEBUG
        if args.logging == "warning":
            logging_level = logging.WARNING
    else:
        logging_level = logging.INFO

    default_logging = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "standard": {"format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"}
        },
        "handlers": {
            "default": {
                "level": logging_level,
                "formatter": "standard",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
            }
        },
        "loggers": {"": {"handlers": ["default"], "level": logging_level}},
    }
    logging.config.dictConfig(default_logging)


def setup_parser() -> argparse:
    """ Set default values and handle arg parser """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(
            """
            a pcap anonymizer created for the WLAN Pi
            """
        ),
    )
    parser.add_argument(
        metavar="<INPUT_FILE>", dest="input_file", help="pcap to anonymize"
    )
    parser.add_argument(
        "--logging",
        help="change logging output",
        nargs="?",
        choices=("debug", "warning"),
    )
    parser.add_argument(
        "--skip",
        dest="skip",
        action="store_true",
        default=False,
        help="skip anonymizing ssid",
    )
    parser.add_argument("--version", "-V", action="version", version=f"{__version__}")
    return parser


def anonymize_mac(address: str, hash: dict) -> str:
    """
    Anonymize MAC address and return string
    """
    anonymized = None
    if address:
        if address != "ff:ff:ff:ff:ff:ff":
            anonymized = hash.get(address)
            if anonymized:
                pass
            else:
                anonymized = address[:8] + ":00:00:00"
                hash[address] = anonymized
    return anonymized


def anonymize_ssid(ssid: str, ssid_number: int, hash: dict) -> str:
    anonymized_ssid = ssid

    if ssid:
        anonymized_ssid = hash.get(ssid)
        if not anonymized_ssid:
            ssid_number += 1
            anonymized_ssid = "WLANPI_" + str(ssid_number)
            hash[ssid] = anonymized_ssid

    return anonymized_ssid


def anonymize_file(input_file: str, output_file: str) -> None:
    logger = logging.getLogger(inspect.stack()[0][3])
    logger.info(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    with PcapReader(input_file) as reader:

        writer = PcapWriter(output_file, sync=True)

        ssid_number = 0
        address_hash = {}
        ssid_hash = {}

        has_fcs = False

        for frame in reader:

            if frame.haslayer(Dot11):
                if frame.haslayer(Dot11FCS):
                    has_fcs = True
                    frame_fcs = frame.fcs
                    logger.info("frame_fcs: %s", frame_fcs)

                    crc_bytes = struct.pack(
                        "I", zlib.crc32(bytes(frame.payload)[:-4]) & 0xFFFF_FFFF
                    )
                    crc_int = hex(int.from_bytes(crc_bytes, byteorder="little"))
                    logger.info("crc_int: %s", crc_int)

                    fcs_match = frame_fcs == crc_int
                    logger.info("fcs_match: %s", fcs_match)

                else:
                    logger.warning("input frame has no fcs")
                    frame_fcs = 0

                # raw_fcs = struct.unpack("I", bytes(frame.payload)[-4:])[0]
                # matches frame.fcs

                # anonymize mac addresses
                frame[Dot11].addr1 = anonymize_mac(frame.addr1, address_hash)
                frame[Dot11].addr2 = anonymize_mac(frame.addr2, address_hash)
                frame[Dot11].addr3 = anonymize_mac(frame.addr3, address_hash)

                # anonymize SSID and address fields (this code seems problematic in py3)
                if args.skip:
                    logger.info("skipping anonymizing SSID: %s", args.skip)
                else:
                    dot11elt = frame.getlayer(Dot11Elt)
                    while dot11elt:
                        logger.info("ie: %s", dot11elt.ID)
                        if dot11elt.ID == 0:
                            ssid = anonymize_ssid(dot11elt.info, ssid_number, ssid_hash)
                            dot11elt.len = len(ssid)
                            dot11elt.info = ssid
                        dot11elt = dot11elt.payload.getlayer(Dot11Elt)

                if has_fcs:
                    if fcs_match:
                        # if fcs and crc originally matched, recompute new valid fcs:
                        fcs = struct.pack(
                            "I", zlib.crc32(bytes(frame.payload)[:-4]) & 0xFFFF_FFFF
                        )
                    else:
                        # otherwise throw garbage in the fcs which will not validate
                        fcs = b"\x00\x00\x00\x00"
                    logger.info(
                        "new fcs: %s", hex(int.from_bytes(fcs, byteorder="little"))
                    )
                    # write anonymized packet
                    writer.write(RadioTap(bytes(frame)[:-4] + fcs))
                else:
                    writer.write(RadioTap(bytes(frame)))
                logger.info("done")


if __name__ == "__main__":
    parser = setup_parser()
    args = parser.parse_args()
    setup_logger(args)
    logger = logging.getLogger(inspect.stack()[0][3])

    logger.debug("%s version %s", __name__.split(".")[0], __version__)
    logger.debug("python platform version is %s", platform.python_version())
    logger.debug("scapy version is %s", scapy.__version__)
    logger.debug("args: %s", args)
    logger.info("input file: %s", args.input_file)
    output_file = os.path.splitext(args.input_file)[0] + "-anonymized.pcap"
    logger.info("output file: %s", output_file)
    logger.warning("THIS SEEMS BROKE ON SCAPY 2.4.4!!! VERIFY BEFORE TRUSTING!!!")
    anonymize_file(args.input_file, output_file)
