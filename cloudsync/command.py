import argparse
import os

def main():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('command', type=str, help='Command to run')
    parser.add_argument('args', nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if args.command == "test":
        test_main()
        return

    raise NotImplementedError()

def test_main():
    import cloudsync.tests.integration.test_provider as provider_test_module

    tests = []
    for ent in dir(provider_test_module):
        if ent.startswith("test_"):
            tests += [ent]


if __name__ == "__main__":
    import sys
    sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),".."))
    main()

