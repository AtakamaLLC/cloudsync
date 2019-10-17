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


class XVersion(Version):
    def __init__(self, v):
        super().__init__(str(v))
        self.dot_dev = bool(".dev" in str(v))

    def __str__(self):
        ret = super().__str__()
        if not self.dot_dev:
            if self.dev:
                ret = ret.replace(".dev", "dev")
        return ret


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

    # support flit, poetry and others that use configs
    if not package:
        try:
            with open("pyproject.toml") as f:
                res = toml.load(f)
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

    # support my own config
    config = {}
    try:
        with open("pyproject.toml") as f:
            res = toml.load(f)
            config.update(res["tool"]["vernum"])
    except (FileNotFoundError, KeyError):
        pass

    try:
        with open("vernum.cfg") as f:
            res = toml.load(f)
            config.update(res)
    except FileNotFoundError:
        pass

    if not package:
        package = config.get("module")

    if not package:
        try:
            run([sys.executable, "setup.py", "--name"])
        except subprocess.CalledProcessError:
            pass

    latest = latest_git

    print("Latest git ver is %s" % Version(latest))

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
            gver = Version(latest_git)
            pver = Version(latest_pub)
            if gver >= pver:
                src = "git"
                latest = str(gver)
            else:
                assert pver > gver
                src = "pip"
                latest = str(pver)
            print("Latest version from %s is '%s'" % (src, latest))
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

    config["package"] = package
    config["branch"] = branch
    config["version"] = latest

    return config


def validate(vsrc, rules={}):
    default_int_max = 65535
    default_max = 5
    default_min = 2
    default_labels = ["a", "b", "dev", "post", "pre"]

    vsrc = vsrc.strip(" ")
    v = XVersion(vsrc)

    if len(v.release) > rules.get("component_max", default_max):
        raise ValueError("Too many components in '%s'" % v)

    if len(v.release) < rules.get("component_min", default_min):
        raise ValueError("Too few components in '%s'" % v)

    labs = rules.get("allowed_labels", default_labels)

    if v.pre and v.pre[0] not in labs:
        raise ValueError("Disallowed label '%s'" % v.pre[0])

    int_max = rules.get("component_int_max", default_int_max)
    for comp in v.release:
        if comp > int_max:
            raise ValueError("Component '%s' too large" % comp)
    if v.pre and v.pre[1] > int_max:
        raise ValueError("Component '%s' too large" % v.pre[1])
    if v.post and v.post > int_max:
        raise ValueError("Component '%s' too large" % v.post)
    if v.dev and v.dev > int_max:
        raise ValueError("Component '%s' too large" % v.dev)

    dev_uses_dot = rules.get("dev_uses_dot", None)
    if v.dev and dev_uses_dot is not None:
        if v.dot_dev and not dev_uses_dot:
            raise ValueError("Version '%s' should use dev, not .dev" % vsrc)
        if not v.dot_dev and dev_uses_dot:
            raise ValueError("Version '%s' should use .dev, not dev" % vsrc)

#    default_pre_uses_dash = False
#    pre_uses_dash = rules.get("pre_uses_dash", default_pre_uses_dash)
#    if v.pre:
#        if v.pre and not dev_uses_dot:
#            raise ValueError("Version '%s' should use dev, not .dev" % vsrc)
#        if not v.dot_dev and dev_uses_dot:
#            raise ValueError("Version '%s' should use .dev, not dev" % vsrc)

    return str(v)


def bump(v, part):
    v = XVersion(v)

    if type(part) is str:
        dot = ""
        if v.pre:
            num = v.pre[1]
        elif v.post:
            num = v.post
        elif v.dev:
            num = v.dev
            if v.dot_dev:
                dot = "."
        else:
            num = 0

        num += 1
        return XVersion(v.base_version + dot + part + str(num))

    t = v.base_version
    vlist = t.split(".")
    vlist[part] = str(int(vlist[part])+1)
    for i in range(part+1, len(vlist)):
        vlist[i] = "0"

    def strs(a):
        return [str(e) for e in a]

    vnew = ".".join(vlist)
    vsuffix = ""
    if v.pre:
        vsuffix += "".join(strs(v.pre))
    elif v.post:
        vsuffix += str(v.post)
    elif v.dev:
        dot = ""
        if v.dot_dev:
            dot = "."
        vsuffix += dot + "dev" + str(v.dev)

    return XVersion(vnew + vsuffix)


def apply_version(branch, vorig, v2, *, dry, msg=None):
    if v2 == vorig:
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
    def __init__(self, config, args, **kws):
        self.config = config
        self.branch = config["branch"]
        self.vorig = XVersion(config["version"])
        self.vinfo = self.vorig
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
        self.vinfo = XVersion(validate(inp.strip(), self.config))

    def do_minor(self, unused_inp):
        """Bump minor version"""
        self.vinfo = bump(self.vinfo, 1)

    def do_patch(self, unused_inp):
        """Bump patch (mini) version"""
        self.vinfo = bump(self.vinfo, 2)

    def do_beta(self, unused_inp):
        """Beta prelease, starting from current"""
        self.vinfo = bump(self.vinfo, "b")

    def do_dev(self, unused_inp):
        """Dev release, starting from current"""
        self.vinfo = bump(self.vinfo, "dev")

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

    parser.add_argument("-v", '--validate', action="store")
    parser.add_argument('--unsafe', action="store_true")
    parser.add_argument('--major', action="store_true")
    parser.add_argument('--minor', action="store_true")
    parser.add_argument('--patch', action="store_true")
    parser.add_argument('--apply', action="store_true")
    parser.add_argument('-m', '--message', action="store")
    parser.add_argument('--package', action="store")

    args = parser.parse_args()

    if args.validate:
        args.unsafe = True
        config = collect_info(args)
        vorig = XVersion(config["version"])
        vnew = XVersion(args.validate)
        try:
            validate(args.validate, config)
        except ValueError as e:
            print(e)
            sys.exit(1)

        if vnew <= vorig:
            print("Version '%s' is less than current '%s'", vnew, vorig)
            sys.exit(2)
        print("OK")
        sys.exit(0)

    if args.major or args.minor or args.apply or args.patch:
        if not args.message:
            print("-m or --message is required")
            sys.exit(1)
        if not args.apply:
            print("#dry run#")
        config = collect_info(args)

        branch = config["branch"]
        vorig = XVersion(config["version"])

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
        config = collect_info(args)
        MyPrompt(config, args).cmdloop()


if __name__ == "__main__":
    main()


class assert_raises:
    def __init__(self, ex):
        self.ex = ex

    def __enter__(self):
        return self

    def __exit__(self, typ, val, tb):
        return issubclass(self.ex, typ)


def test_bump1():
    v = "1.2.3"
    print("t1")
    assert str(bump(v, MAJOR)) == "2.0.0"
    print("t2")
    assert str(bump(v, MINOR)) == "1.3.0"
    print("t3")
    assert str(bump(v, PATCH)) == "1.2.4"
    print("t4")
    assert str(bump(v, "b")) == "1.2.3b1"
    print("t5")
    assert str(bump("1.2.3b1", "a")) == "1.2.3a2"
    print("t6")
    assert str(bump("1.2.3b1", PATCH)) == "1.2.4b1"

    # allow dev syntax to be either pep-compliant or "consistent with other labels"
    print("t7")
    assert str(bump("1.2.3dev1", PATCH)) == "1.2.4dev1"
    print("t8")
    assert str(bump("1.2.3.dev1", PATCH)) == "1.2.4.dev1"
    print("t9")
    assert str(bump("1.2.3.dev1", "dev")) == "1.2.3.dev2"


def test_val1():
    for v in ("1.2.4", "1.3", "1.2b1", "1.4dev1", "1.4.dev1", "9.2.post4"):
        assert validate(v, {"dev_uses_dot": None})

    for v in ("1.2.65536", "1", "1.2.3.4.5.6.7.8", "1.4c1", "4.6post9999999", "1.4dev1"):
        with assert_raises(ValueError):
            assert validate(v, {"dev_uses_dot": True})

