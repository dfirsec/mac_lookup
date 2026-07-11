"""Compatibility entry point for the MAC Lookup command-line application."""

from mac_lookup_core.cli import main
from rich import print as rprint
from rich.style import Style
from rich.text import Text

BANNER = r"""
         __  ______   ______   __                __
        /  |/  /   | / ____/  / /   ____  ____  / /____  ______
       / /|_/ / /| |/ /      / /   / __ \/ __ \/ //_/ / / / __ \
      / /  / / ___ / /___   / /___/ /_/ / /_/ / ,< / /_/ / /_/ /
     /_/  /_/_/  |_\____/  /_____/\____/\____/_/|_|\__,_/ .___/
                                                       /_/
"""


def print_banner() -> None:
    """Print the application banner."""
    banner_text = Text.from_markup(BANNER)
    banner_text.stylize(Style(color="cyan", bold=True))
    rprint(banner_text)


if __name__ == "__main__":
    print_banner()
    main()
