# -*- coding: utf-8 -*-

"""
profiler2.profiler
~~~~~~~~~~~~~~~~~~

profiler code goes here, separate from fake ap code.
"""

# standard library imports
import inspect, logging


class AnalyzeFrame(object):
    client_assoc_hash = {}

    def __init__(self):
        self.log = logging.getLogger(inspect.stack()[0][1].split("/")[-1])

    def assoc_req(self, frame):
        if frame.addr2 not in self.client_assoc_hash.keys():
            self.client_assoc_hash[frame.addr2] = frame
            self.log.debug(f"assoc: {self.client_assoc_hash.keys()}")
            self.analyze_assoc(frame)
        else:
            self.log.debug(f"{frame.addr2} was already seen")

    def analyze_assoc(self, frame):
        self.log.debug(
            f"addr1 (TA): {frame.addr1} addr2 (RA): {frame.addr2} addr3 (SA): {frame.addr3} addr4 (DA): {frame.addr4}"
        )
        print("hexdump of frame:\n")
        # hexdump(frame)
