import sys
import logging

from cloudsync.command.main import main


def test_main(capsys):
    sys.argv = ["cloudsync", "debug", "--help"]

    ex = None
    try:
        main()
    except SystemExit as e:
        ex = e

    assert ex.code == 0

    out = capsys.readouterr().out
    err = capsys.readouterr().err

    assert "usage" in out.lower()
    assert err == ""


def test_main_badcmd(capsys):
    sys.argv = ["cloudsync", "badcommand"]

    ex = None
    try:
        main()
    except SystemExit as e:
        ex = e

    # raise an error
    assert ex.code > 0

    err = capsys.readouterr().err

    # show some usage
    assert "usage" in err.lower()


def test_main_disp(capsys):
    sys.argv = ["cloudsync", "debug"]

    ex = None
    try:
        main()
    except SystemExit as e:
        ex = e

    if ex:
        assert ex.code == 0

    out = capsys.readouterr().out
    err = capsys.readouterr().err

    assert out == ""
    assert err == ""
