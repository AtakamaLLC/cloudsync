# pylint: disable=missing-docstring

import sys
import pytest
from cloudsync.command.main import main


def test_main(capsys):
    sys.argv = ["cloudsync", "debug", "--help"]

    ex = None
    try:
        main()
    except SystemExit as e:
        ex = e

    assert ex.code == 0

    rd = capsys.readouterr()

    assert "usage" in rd.out.lower()
    assert rd.err == ""

@pytest.mark.parametrize("arg", [["badcommand"], []])
def test_main_badcmd(capsys, arg):
    sys.argv = ["cloudsync"] + arg

    ex = None
    try:
        main()
    except SystemExit as e:
        ex = e

    # raise an error
    assert ex.code > 0

    rd = capsys.readouterr()

    # show some usage
    assert "usage" in rd.err.lower()


def test_main_disp(capsys):
    sys.argv = ["cloudsync", "debug"]

    ex = None
    try:
        main()
    except SystemExit as e:
        ex = e

    if ex:
        assert ex.code == 0

    rd = capsys.readouterr()

    assert rd.out == ""
    assert rd.err == ""


def test_main_err(capsys):
    sys.argv = "cloudsync sync -v fozay:55 refo:66".split(" ")

    ex = None
    try:
        main()
    except SystemExit as e:
        ex = e

    if ex:
        assert ex.code > 0

    rd = capsys.readouterr()

    assert rd.err != ""
    # verbose logs a traceback on failz
    assert "aceback" in rd.err
