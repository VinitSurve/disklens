"""Allow ``python -m disklens``."""

import sys

from disklens.cli import main

if __name__ == "__main__":
    sys.exit(main())
