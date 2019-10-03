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
from cmd import Cmd
from packaging.version import Version

import toml

MAJOR = 0
MINOR = 1
PATCH = 2

assert sys.version_info > (3, 0), "Python interpreter version 3 or greater"


def run(cmd, dry=False):
    if type(cmd) is str:
        cmd = cmd.split(" ")
    print("#%srun#" % ("dry " if dry else ""), " ".join(["'"+c+"'" if ' ' in c else c for c in cmd]))
    if dry:
        return "<dry run>"
    return subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode().strip()


def pip_install(package):
    return run([sys.executable, "-m", "pip", "install", package])


def collect_info(args):
    latest_git = run("git describe --abbrev=0")

    # todo... figure out the package info either from setup.py or pyproject.toml or from command-line arg
    package = args.package

    # support flit
    if not package:
        try:
            with open("pyproject.toml") as f:
                res = toml.load(f)
                try:
                    package = res["tool"]["bumpver"]["module"]
                except KeyError:
                    pass
                if not package:
                    try:
                        package = res["tool"]["flit"]["metadata"]["module"]
                    except KeyError:
                        pass
                if not package:
                    try:
                        package = res["tool"]["poetry"]["name"]
                    except KeyError:
                        pass
        except FileNotFoundError:
            pass

    if not package:
        try:
            run([sys.executable, "setup.py", "--name"])
        except subprocess.CalledProcessError:
            pass

    latest = latest_git

    if package:
        print("Searching pip for public versions of '%s'" % package)
        try:
            pip_install("%s==" % package)
        except subprocess.CalledProcessError as e:
            x = e.output.decode("utf8")
            match = re.search(r"(\d[a-z0-9. ,]+)\)", x)
            versions = match[1]
            version_list = versions.split(",")
            latest_pub = version_list[-1].strip()
            latest = str(max(Version(latest_pub), Version(latest_git)))
            print("Latest version is '%s'" % latest)
    else:
        print("WARNING: Unable to find package name, not searching public versions")

    print("Collecting branch information")

    branch = run("git rev-parse --abbrev-ref HEAD")

    run("git fetch")
    diff = run("git diff origin/%s" % branch)

    vorig = Version(latest)

    print("Current branch is %s" % branch)
    print("Latest public version is %s" % vorig)

    if diff and not args.unsafe:
        print("Current branch has differences from remote, aborting.")
        sys.exit(1)

    return (package, branch, vorig)

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


def apply_version(branch, vorig, v2, *, dry, msg=None):
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
        sys.exit(0)


class MyPrompt(Cmd):
    def __init__(self, branch, vinfo, args, **kws):
        self.branch = branch
        self.vorig = vinfo
        self.vinfo = vinfo
        self.args = args
        self._prompt()
        super().__init__(**kws)
        self.onecmd("help")

    def cmdloop(self, intro=None):
        while True:
            try:
                return super().cmdloop(intro)
            except Exception as e:
                print("# error #", e)

    def postcmd(self, stop, line):
        self._prompt()
        return stop

    def do_major(self, unused_inp):
        """Bump major version"""
        self.vinfo = bump(self.vinfo, 0)

    def do_set(self, inp):
        """Set to specified version"""
        self.vinfo = Version(inp.strip())

    def do_minor(self, unused_inp):
        """Bump minor version"""
        self.vinfo = bump(self.vinfo, 1)

    def do_patch(self, unused_inp):
        """Bump patch (mini) version"""
        self.vinfo = bump(self.vinfo, 2)

    def do_beta(self, unused_inp):
        """Beta prelease, starting from current"""
        self.vinfo = bump(self.vinfo, "b")

    def do_alpha(self, unused_inp):
        """Alpha prelease, starting from current"""
        self.vinfo = bump(self.vinfo, "a")

    def do_label(self, inp):
        """Labeled release, specify argument
        eg: label dev
        """
        if inp:
            self.vinfo = bump(self.vinfo, inp)

    def do_dry(self, unused_inp):
        """Pretend to apply changes and push version label to github
        """
        apply_version(self.branch, self.vorig, self.vinfo, dry=True)

    def do_apply(self, unused_inp):
        """Apply changes, push version label to github, and exit
        """
        apply_version(self.branch, self.vorig, self.vinfo, dry=False)

    def _prompt(self):
        self.prompt = "(" + str(self.vinfo) + ") # "

    @staticmethod
    def do_quit(unused_inp):
        """Exit without applying changes"""
        return True

    def emptyline(self):
        pass

    do_EOF = do_quit

def main():
    parser = argparse.ArgumentParser(description='Bump version')

    parser.add_argument('--unsafe', action="store_true")
    parser.add_argument('--major', action="store_true")
    parser.add_argument('--minor', action="store_true")
    parser.add_argument('--patch', action="store_true")
    parser.add_argument('--apply', action="store_true")
    parser.add_argument('-m', '--message', action="store")
    parser.add_argument('--package', action="store")

    args = parser.parse_args()

    if args.major or args.minor or args.apply or args.patch:
        if not args.message:
            print("-m or --message is required")
            sys.exit(1)
        if not args.apply:
            print("#dry run#")
        (_package, branch, vorig) = collect_info(args)
        vinfo = vorig
        if args.major:
            vinfo = bump(vinfo, MAJOR)
        if args.minor:
            vinfo = bump(vinfo, MINOR)
        if args.patch:
            vinfo = bump(vinfo, PATCH)
        msg = args.message
        apply_version(branch, vorig, vinfo, dry=not args.apply, msg=msg)
    else:
        (_package, branch, vorig) = collect_info(args)
        MyPrompt(branch, vorig, args).cmdloop()


if __name__ == "__main__":
    main()

def test_bump1():
    v = "1.2.3"
    assert str(bump(v, MAJOR)) == "2.0.0"
    assert str(bump(v, MINOR)) == "1.3.0"
    assert str(bump(v, PATCH)) == "1.2.4"
    assert str(bump(v, "b")) == "1.2.3b1"
    assert str(bump("1.2.3b1", "a")) == "1.2.3a2"

