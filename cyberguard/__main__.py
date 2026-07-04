"""Allow ``python -m cyberguard`` to launch the CLI."""

from cyberguard.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
