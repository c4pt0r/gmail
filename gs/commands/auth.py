"""`gs auth` — manage authentication (login, logout, status)."""

import click

from . import get_auth


@click.group()
def auth():
    """Manage Google authentication for gs."""


@auth.command("login")
@click.option(
    "--credentials", type=click.Path(exists=True), help="OAuth2 credentials file"
)
@click.option(
    "--auth-token", type=click.Path(exists=True), help="Service account key file"
)
@click.option("--force-headless", is_flag=True, help="Console-based auth (no browser)")
@click.option(
    "--callback-url",
    metavar="URL",
    help="Finish a headless login: the URL the browser was redirected to "
    "(a bare authorization code also works)",
)
@click.pass_context
def auth_login(ctx, credentials, auth_token, force_headless, callback_url):
    """Authenticate and cache a token (covers Gmail, Calendar, and Drive)."""
    a = get_auth(
        ctx,
        credentials=credentials,
        auth_token=auth_token,
        force_headless=force_headless,
    )
    if callback_url:
        a.complete_login(callback_url)
    else:
        a.login()
    # Confirm by reading the profile.
    profile = a.service("gmail", "v1").users().getProfile(userId="me").execute()
    click.echo(f"Logged in as {profile.get('emailAddress')}")


@auth.command("logout")
@click.pass_context
def auth_logout(ctx):
    """Remove the cached token."""
    if get_auth(ctx).logout():
        click.echo("Logged out (cached token removed)")
    else:
        click.echo("No cached token to remove")


@auth.command("status")
@click.pass_context
def auth_status(ctx):
    """Show whether you're authenticated and as which account."""
    a = get_auth(ctx)
    creds = a.status()
    if not creds:
        click.echo("Not logged in. Run: gs auth login --credentials <file.json>")
        ctx.exit(1)
    profile = a.service("gmail", "v1").users().getProfile(userId="me").execute()
    click.echo(f"Logged in as {profile.get('emailAddress')}")
