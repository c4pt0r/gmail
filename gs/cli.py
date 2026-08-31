#!/usr/bin/env python3
"""
Command line interface for gs — a Google Suite CLI (Gmail, Calendar, Drive).

`cli` is the top-level click group. It registers sibling subgroups (auth, gmail,
calendar, drive). Authentication and global options live on the top group and are
stored in ``ctx.obj`` (which click propagates to nested subcommands) so every
command can build a Config from them.
"""

import os
import sys

import click

from . import __version__


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__)
# Authentication options (shared by all subcommands)
@click.option(
    "--credentials", type=click.Path(exists=True), help="OAuth2 credentials file path"
)
@click.option(
    "--auth-token",
    type=click.Path(exists=True),
    help="Service account authentication token file path",
)
@click.option(
    "--cached-auth-token",
    type=click.Path(),
    default=lambda: os.path.expanduser("~/.gs/tokens"),
    help="Cached authentication token file path",
)
@click.option(
    "--force-headless",
    is_flag=True,
    help="Force headless authentication mode (console-based)",
)
@click.option(
    "--ignore-token",
    is_flag=True,
    help="Ignore cached authentication token and force re-authentication",
)
# Global options
@click.option(
    "--config-file", type=click.Path(exists=True), help="Configuration file path"
)
@click.option("--verbose", "-v", is_flag=True, help="Verbose output mode")
@click.option("--quiet", is_flag=True, help="Quiet mode, only output JSON")
@click.option("--log-file", type=click.Path(), help="Log file path")
@click.pass_context
def cli(ctx, **kwargs):
    """gs - a command-line tool for Google Suite (Gmail, Calendar, Drive).

    \b
    Examples:
        gs auth login --credentials credentials.json
        gs gmail tail --from "noreply@github.com"
        gs gmail send --to a@b.com --subject Hi --body hello --attach f.pdf
        gs calendar events --from today --to +7d
        gs drive ls
        gs drive upload report.pdf
    """
    ctx.ensure_object(dict)
    ctx.obj.update(kwargs)


# Register sibling subgroups
from .commands.auth import auth  # noqa: E402
from .commands.calendar import calendar  # noqa: E402
from .commands.drive import drive  # noqa: E402
from .commands.gmail_group import gmail  # noqa: E402

for _group in (auth, gmail, calendar, drive):
    cli.add_command(_group)


def main():
    """Entry point that maps interrupts and auth failures to clean exits."""
    from .auth import NotAuthenticatedError

    try:
        cli(standalone_mode=True)
    except KeyboardInterrupt:
        click.echo("\nStopped by user", err=True)
        sys.exit(0)
    except NotAuthenticatedError as e:
        click.echo(str(e), err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
