"""User-facing errors. Every message names the next command to run."""

from __future__ import annotations

NEXT_INIT = "fortressgd init"
NEXT_DOCTOR = "fortressgd doctor"
NEXT_SECRET = "fortressgd secret generate"
NEXT_HELP = "fortressgd --help"


class UserError(Exception):
    """Config / usage error. CLI maps this to exit code 1."""

    def __init__(self, message: str, next_command: str = NEXT_DOCTOR) -> None:
        super().__init__(message)
        self.next_command = next_command

    def format(self) -> str:
        return "error: {0}\nRun: {1}".format(str(self), self.next_command)


class ConfigError(UserError):
    """Invalid or unknown keys in `.fortressgd.toml`."""
