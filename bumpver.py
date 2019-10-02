#!/usr/bin/env python3
"""
Yet another bersion bumper

    - Uses PEP style versions, instead of semver style
    - Supports git tag push
    - Supports "interactive" mode
"""

import sys
import re
import subprocess
import argparse

from packaging.version import Version

from cmd import Cmd

MAJOR = 0
MINOR = 1
PATCH = 2

assert sys.version_info > (3, 0), "Python interpreter version 3 or greater"

def quit(code=1):
    sys.exit(code)


def run(cmd, dry=False):
    if type(cmd) is str:
        cmd = cmd.split(" ")
    print("#run#", "'" + ("' '".join(cmd)) + "'")
    if dry:
        return "<dry run>"
    return subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode().strip()


def pip_install(package):
    return run([sys.executable, "-m", "pip", "install", package])

# todo... figure out the package info either from setup.py or pyproject.toml or from command-line arg
package = "cloudsync"

try:
    pip_install("%s==" % package)
except subprocess.CalledProcessError as e:
    x = e.output.decode("utf8")

branch = run("git rev-parse --abbrev-ref HEAD")

run("git fetch")
diff = run("git diff origin/%s" % branch)

if diff:
    print("Current branch has differences from remote, aborting.")
    quit()

match = re.search(r"(\d[a-z0-9. ,]+)\)", x)

versions = match[1]
version_list = versions.split(",")
latest = version_list[-1].strip()

vorig = Version(latest)

print("Current branch is %s" % branch)
print("Latest public version is %s" % vorig)

def bump(v, part):
    if type(v) is str:
        v = Version(v)

    if type(part) is str:
        if v.pre:
            num = v.pre[1] + 1
        elif v.post:
            num = v.post[1] + 1
        else:
            num = 1
        return Version(v.base_version + part + str(num))

    t = v.base_version
    vlist = t.split(".")
    vlist[part] = str(int(vlist[part])+1)
    for i in range(part+1, len(vlist)):
        vlist[i] = "0"

    vnew = ".".join(vlist)
    vsuffix = ""
    if v.pre:
        vsuffix += "".join(v.pre)
    elif v.post:
        vsuffix += "".join(v.post)
    elif v.dev:
        vsuffix += "".join(v.dev)
    return Version(vnew + vsuffix)


def apply_version(vorig, v2, *, dry, msg=None):
    if v2 <= vorig:
        print("No changes to apply")
    else:
        print("Branch 'origin/%s' will be tagged with '%s'" % (branch, v2))

        if msg is None:
            print("Enter a commit message (empty message will abort): ")
            msg = sys.stdin.readline().strip()

        if not msg:
            print("Not continuing with empty commit message")
            return

        print(run(["git", "tag", "-a", "v" + str(v2), "-m", msg], dry=dry))
        print(run("git push --tags", dry=dry))
        quit(0)


class MyPrompt(Cmd):
    def __init__(self, vinfo, **kws):
        self.vinfo = vinfo
        self._prompt()
        super().__init__(**kws)
        self.onecmd("help")

    def cmdloop(self):
        while True:
            try:
                return super().cmdloop()
            except Exception as e:
                print("# error #", e)

    def postcmd(self, stop, line):
        self._prompt()
        return stop

    def do_major(self, inp):
        """Bump major version"""
        self.vinfo = bump(self.vinfo, 0)

    def do_set(self, inp):
        self.vinfo = Version(inp.strip())

    def do_minor(self, inp):
        """Bump minor version"""
        self.vinfo = bump(self.vinfo, 1)

    def do_patch(self, inp):
        """Bump patch (mini) version"""
        self.vinfo = bump(self.vinfo, 2)

    def do_beta(self, inp):
        """Beta prelease, starting from current"""
        self.vinfo = bump(self.vinfo, "b")

    def do_alpha(self, inp):
        """Alpha prelease, starting from current"""
        self.vinfo = bump(self.vinfo, "a")

    def do_label(self, inp):
        """Labeled release, specify argument
        eg: label dev
        """
        if inp:
            self.vinfo = bump(self.vinfo, inp)

    def do_apply(self, inp):
        """Apply changes and push version label to github
        "apply dry' will print without doing.
        """

        dry = False
        if inp[0:3].lower() == "dry":
            print("Dry run")
            dry = True

        apply_version(vorig, self.vinfo, dry=dry)

    def _prompt(self):
        self.prompt = "(" + str(self.vinfo) + ") # "

    def do_quit(self, inp):
        """Exit without applying changes"""
        return True

    def emptyline(self):
        pass

    do_EOF = do_quit

def main():
    parser = argparse.ArgumentParser(description='Bump version')


    parser.add_argument('--major', action="store_true")
    parser.add_argument('--minor', action="store_true")
    parser.add_argument('--apply', action="store_true")
    parser.add_argument('-m', '--message', action="store", required=True)
    parser.add_argument('-p', '--patch', action="store_true")

    args = parser.parse_args()

    if args.major or args.minor or args.apply or args.patch:
        if not args.apply:
            print("# dry run #")
        vinfo = vorig
        if args.major:
            vinfo = bump(vinfo, MAJOR)
        if args.minor:
            vinfo = bump(vinfo, MINOR)
        if args.patch:
            vinfo = bump(vinfo, PATCH)
        msg = args.message
        apply_version(vorig, vinfo, dry=not args.apply, msg=msg)
    else:
        MyPrompt(vorig).cmdloop()


if __name__ == "__main__":
    main()

def test_bump1():
    v = "1.2.3"
    assert str(bump(v, MAJOR)) == "2.0.0"
    assert str(bump(v, MINOR)) == "1.3.0"
    assert str(bump(v, PATCH)) == "1.2.4"
    assert str(bump(v, "b")) == "1.2.3b1"
    assert str(bump("1.2.3b1", "a")) == "1.2.3a2"

