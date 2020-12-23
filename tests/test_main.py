# -*- coding: utf-8 -*-

import mock


def test_init():
    from profiler2 import __main__

    with mock.patch.object(__main__, "main", return_value=42):
        with mock.patch.object(__main__, "__name__", "__main__"):
            with mock.patch.object(__main__.sys, "exit") as mock_exit:
                __main__.init()

                assert mock_exit.call_args[0][0] == 42
