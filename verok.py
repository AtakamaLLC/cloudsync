#!/usr/bin/env python
from __future__ import print_function

import sys
import re

COMPONENT_MIN = 3
COMPONENT_MAX = 3                           # not including allowed label
COMPONENT_INT_MAX = 65535
ALLOWED_LABELS = ('a', 'b', 'dev')          # see pep, don't modify
PRERELEASE_USES_DASH = False                # 1.2.3-b5 or 1.2.3b5, pick one


def verok(ver):
    try:
        return _verok(ver)
    except AssertionError as e:
        raise ValueError(str(e))


def _verok(ver):
    # cannot use packaging.version
    # because it allows malleable versions:
    #     ie: 1.2.3b6 == 1.2.3-beta6, 1.02 == 1.2
    # which is not ok here

    ver = ver.strip()

    # in python land, dev tags have dots
    # but this crappy parser doesn't support them
    ver.replace(".dev", "dev")

    if ver[0] == "v":
        ver = ver[1:]

    tup = ver.split(".")

    assert len(tup) >= COMPONENT_MIN, "Not enough components"
    assert len(tup) <= COMPONENT_MAX, "Too many components"

    last = tup[len(tup) - 1]

    if re.search('[a-z]', last, re.I):
        label = None
        if PRERELEASE_USES_DASH and "-" not in last:
            assert False, "Dash required for release tag"

        if (not PRERELEASE_USES_DASH) and "-" in last:
            assert False, "No dash between version and release tag"

        for lab in sorted(ALLOWED_LABELS, key=lambda x: -len(x)):
            if PRERELEASE_USES_DASH:
                lab = "-" + lab

            if lab in last:
                label = lab
                v, relnum = last.split(label)
                tup = tup[:-1] + [v, relnum]
                break

        assert label, "Invalid release tag in last component '%s'" % last

    for i, e in enumerate(tup):
        try:
            ie = int(e)
        except ValueError:
            raise ValueError("Component '%s' invalid" % e)

        if str(ie) != e:
            raise ValueError("Component '%s' is not a simple integer" % e)

        if ie <= -1 or ie > COMPONENT_INT_MAX:
            raise ValueError("Component '%s' out of range" % ie)

    if tup == ['0'] * len(tup):
        raise ValueError("All components cannot be zero")

    return ver


if __name__ == "__main__":
    try:
        ver = sys.argv[1]
        print(verok(ver))
    except ValueError as e:
        print(e, file=sys.stderr)
        sys.exit(1)

