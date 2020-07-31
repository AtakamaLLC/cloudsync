#!/usr/bin/env python3
from typing import List, Set, Any, Optional, Tuple
import sys
import toml
from pprint import pprint

def _find_difference(left: Set[Any], right: Set[Any]) -> Optional[Tuple[Set[Any], Set[Any]]]:
    left_only = left - right
    right_only = right - left

    if left_only or right_only:
        return left_only, right_only

    return None


def main() -> int:
    with open("pyproject.toml") as f:
        data = toml.load(f)

    requires_extra = data["tool"]["flit"]["metadata"]["requires-extra"]

    deps = set()

    for k, v in requires_extra.items():
        if k == "all":
            continue

        deps.update(v)

    extra_all_deps = set(requires_extra["all"])

    diff = _find_difference(deps, extra_all_deps)
    if diff:
        extras_only, all_only = diff
        print("Mismatched dependencies between individual extras and cloudsync[all]")
        print("Individual features require:", deps)
        print("[all] requires:", extra_all_deps)
        print()

        print("Missing from [all]:", extras_only)
        print("Only in [all]", all_only)

        return 1

    return 0



if __name__ == "__main__":
    sys.exit(main())
