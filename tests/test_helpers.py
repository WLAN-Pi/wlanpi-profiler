import logging
import argparse
import sys

sys.path.insert(0, "../")

from helloscapy.helpers import setup_logger


def test_setup_logger():
    h = setup_logger(argparse.ArgumentParser())
    assert isinstance(h, logging.Logger)
