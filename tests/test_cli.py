# test_cli.py

import pytest
import subprocess
import signal
import pathlib
from profiler2 import helpers
import sys

insertion = 'profiler'

no_input_flags = [
    '--hostname_ssid',
    '--noAP',
    '--no11ax',
    '--no11r',
    '--oui_update',
    '--version',
    '-V',
    '-h',
    '--help',
    '--11r',
    '--11ax',
]

debug_types = ['debug', 'warning']


@pytest.fixture(scope='module')
def load_pcap():
    pcap = pathlib.Path(__file__).parent / 'pcaps' / 'iPhone11ProMax.pcap_randomized.pcap'
    return(pcap)


def test_menu_file(tmp_path, load_pcap):
    f = tmp_path / "dummy.txt"
    f.write_text('')
    output = subprocess.Popen([insertion, '--pcap', load_pcap, '--menu_file', f], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output.wait(15)
    except subprocess.TimeoutExpired:
        output.send_signal(signal.SIGINT)
        output.wait()
    print(f.read_text())
    assert 'Status' in f.read_text(), '"Status" not in file contents'
    assert output.returncode == 0, "Program did not exit cleanly"


def test_files_root(tmp_path, load_pcap):
    output = subprocess.Popen([insertion, '--pcap', load_pcap, '--files_root', tmp_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output.wait(15)
    except subprocess.TimeoutExpired:
        output.send_signal(signal.SIGINT)
        output.wait()
    files = [path.name for path in pathlib.Path(tmp_path).rglob('*.*')]
    assert files, "Files not found"
    assert output.returncode == 0, "Program did not exit cleanly"


def test_pcap_file(load_pcap):
    output = subprocess.Popen([insertion, '--pcap', load_pcap], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output.wait(15)
    except subprocess.TimeoutExpired:
        output.send_signal(signal.SIGINT)
        output.wait()
    assert output.returncode == 0, "Program did not exit cleanly"


@pytest.fixture()
def setup_interface():
    # log.info("start interface prep...")
    if not helpers.prep_interface('wlan0', "monitor", '6'):
        # if not helpers.prep_interface(interface, "monitor", channel):
        # log.error("failed to prep interface")
        print("exiting...")
        sys.exit(-1)
        # log.info("done prep interface...")


def test_no_prep(setup_interface):
    output = subprocess.Popen([insertion, '--noprep'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output.wait(15)
    except subprocess.TimeoutExpired:
        output.send_signal(signal.SIGINT)
        output.wait()
    assert output.returncode == 0, "Program did not exit cleanly"


def test_config_input():
    config_ini = pathlib.Path(__file__).parent / '..' / 'profiler2' / 'config.ini'
    output = subprocess.Popen([insertion, '--config', config_ini], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output.wait(15)
    except subprocess.TimeoutExpired:
        output.send_signal(signal.SIGINT)
        output.wait()
    assert output.returncode == 0, "Program did not exit cleanly"


def test_clean_input():
    """Please don't judge me for this...."""
    ugly = '( sleep 20; echo "y\n" ) | sudo profiler --clean'
    output = subprocess.Popen(ugly, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        output.wait(22)
    except subprocess.TimeoutExpired:
        output.send_signal(signal.SIGINT)
        output.wait()
    assert output.returncode == 0, "Program did not exit cleanly"


@pytest.mark.parametrize('flag', no_input_flags)
def test_cli_no_args(flag):
    output = subprocess.Popen([insertion, flag], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output.wait(15)
    except subprocess.TimeoutExpired:
        output.send_signal(signal.SIGINT)
        output.wait()
    assert output.returncode == 0, "Program did not exit cleanly with {flag}"


def test_channel_flag():
    output = subprocess.Popen([insertion, '-c 3'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output.wait(15)
    except subprocess.TimeoutExpired:
        output.send_signal(signal.SIGINT)
        output.wait()
    assert output.returncode == 0, "Program did not exit cleanly"


def test_ssid_flag():
    output = subprocess.Popen([insertion, '-s', ' pytest'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output.wait(15)
    except subprocess.TimeoutExpired:
        output.send_signal(signal.SIGINT)
        output.wait()
    assert output.returncode == 0, "Program did not exit cleanly"


@pytest.mark.parametrize('debug', debug_types)
def test_logging_flag(debug):
    output = subprocess.Popen([insertion, '--logging', debug], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output.wait(15)
    except subprocess.TimeoutExpired:
        output.send_signal(signal.SIGINT)
        output.wait()
    assert output.returncode == 0, "Program did not exit cleanly"


def test_interface_flag():
    output = subprocess.Popen([insertion, '-i', 'wlan0'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        output.wait(15)
    except subprocess.TimeoutExpired:
        output.send_signal(signal.SIGINT)
        output.wait()
    assert output.returncode == 0, "Program did not exit cleanly"
