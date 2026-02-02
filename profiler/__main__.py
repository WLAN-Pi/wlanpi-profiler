# profiler : a Wi-Fi client capability analyzer tool
# Copyright : (c) 2024 Josh Schmelzle
# License : BSD-3-Clause
# Maintainer : josh@joshschmelzle.com

"""
profiler
~~~~~~~~

Wi-Fi client capabilities analyzer for the WLAN Pi
"""

import os
import platform
import sys
import warnings

# Suppress cryptography deprecation warnings from scapy's IPsec module
# (TripleDES moving to cryptography.hazmat.decrepit)
# Must filter before any scapy imports occur
try:
    from cryptography.utils import CryptographyDeprecationWarning

    warnings.filterwarnings(
        "ignore",
        message="TripleDES has been moved",
        category=CryptographyDeprecationWarning,
    )
except ImportError:
    pass


# Suppress BrokenPipeError when output is piped and pipe closes (e.g., | grep)
# This is expected Unix behavior, not an error
def handle_broken_pipe():
    """Install handler to suppress BrokenPipeError traceback"""
    import signal

    # Ignore SIGPIPE (write to closed pipe)
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def main():
    """Set up args and start the profiler manager"""
    # Handle BrokenPipeError gracefully when output is piped
    handle_broken_pipe()

    from . import helpers, manager

    parser = helpers.setup_parser()
    args = parser.parse_args()

    if args.command == "test":
        import subprocess

        if os.geteuid() != 0:
            print("ERROR: On device tests require root privileges")
            print("Run with: sudo profiler test")
            sys.exit(1)

        import profiler.tests.hardware.ondevice

        tests_path = os.path.dirname(profiler.tests.hardware.ondevice.__file__)

        if not os.path.isdir(tests_path):
            print(f"ERROR: Hardware tests not found at: {tests_path}")
            sys.exit(1)

        print(f"Running hardware tests from: {tests_path}")
        print("=" * 70)

        # Determine Python executable (should be in virtualenv)
        python_exe = sys.executable

        print("\n=== Device installation & interface tests ===\n")
        result = subprocess.run(
            [
                python_exe,
                "-m",
                "pytest",
                "-v",
                f"{tests_path}/test_health_checks.py",
                f"{tests_path}/test_interface_staging.py",
            ],
            cwd=os.path.dirname(tests_path),
        )

        print("\n" + "=" * 70)
        print("Test Summary:")
        print("=" * 70)
        if result.returncode == 0:
            print("Hardware installation & interface tests - PASSED")
            print("\n🥧 All hardware tests passed!")
            sys.exit(0)
        else:
            print("Hardware installation & interface tests - FAILED")
            sys.exit(1)

    # Check platform requirements based on mode
    if "linux" not in sys.platform:
        # Pcap analysis mode _should work_ cross-platform
        if not hasattr(args, "pcap_analysis") or not args.pcap_analysis:
            sys.exit(
                f"{os.path.basename(__file__)}: Live capture requires Linux and a capable NIC. "
                "Use --pcap <file.pcap> for offline analysis on Windows/macOS."
            )

    try:
        manager.start(args)
    except BrokenPipeError:
        # occurs when output is piped (e.g., | grep) and pipe closes
        # suppress the error
        sys.exit(0)


def init():
    """Handle main init"""

    # hard set no support for python < v3.9
    if sys.version_info < (3, 9):  # noqa: UP036
        sys.exit(
            f"{os.path.basename(__file__)} requires Python version 3.9 or higher...\nyou are trying to run with Python version {platform.python_version()}...\nexiting..."
        )

    if __name__ == "__main__":
        sys.exit(main())


init()
