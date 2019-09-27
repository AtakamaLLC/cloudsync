#!/usr/bin/env python

import sys
import re

COMPONENT_MIN = 3
COMPONENT_MAX = 3                           # not including allowed label
COMPONENT_INT_MAX = 65535
ALLOWED_LABELS = ('a', 'b', 'dev')          # see pep, don't modify

def verok(ver):
    ver = ver.strip()

    if ver[0] == "v":
        ver = ver[1:]

    tup = ver.split(".")

    assert len(tup) >= COMPONENT_MIN, "Not enough components"
    assert len(tup) <= COMPONENT_MAX, "Too many components"

    last = tup[len(tup) - 1]

    if re.search('[a-z]', last, re.I):
        label = None
        for l in sorted(ALLOWED_LABELS, key=lambda x: -len(x)):
            if l in last:
                label = l
                v, relnum = last.split(label)
                tup = tup[:-1] + [v, relnum]
                break
        assert label, "Invalid letter in component '%s'" % last

    for i, e in enumerate(tup):
        try:
            ie = int(e)
        except ValueError:
            raise ValueError("Component '%s' invalid" % e)

        if ie == 0 and i != 0:
            raise ValueError("Component '%s' out of range" % ie)

        if ie <= -1 or ie > COMPONENT_INT_MAX:
            raise ValueError("Component '%s' out of range" % ie)

    return ver

if __name__ == "__main__":
    try:
        ver = sys.argv[1]
        print(verok(ver))
    except (AssertionError, ValueError) as e:
        print(e, file=sys.stderr)
        sys.exit(1)

