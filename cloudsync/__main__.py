"""
Used when running cloudsync as a command-line utility
"""

from cloudsync.command import main

if __name__ == "__main__":
    import sys
    import os
    sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    main()
