"""Entry point for ``python -m iamtk``."""

import sys


def _run() -> int:
    from .cli import main

    try:
        return main()
    except BrokenPipeError:  # e.g. piped into `head`
        return 0


if __name__ == "__main__":
    sys.exit(_run())
