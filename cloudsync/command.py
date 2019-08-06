import argparse
import os


def main():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('command', type=str, help='Command to run')
    parser.add_argument('args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    raise NotImplementedError()


if __name__ == "__main__":
    import sys
    sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    main()
