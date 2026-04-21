"""Shared helpers: logging, AWS session creation, ARN parsing, action matching."""
from __future__ import annotations

import fnmatch
import logging
import re
from dataclasses import dataclass
from typing import Iterable, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from rich.logging import RichHandler


LOGGER_NAME = "privesc_finder"


def configure_logging(verbose: bool = False) -> logging.Logger:
    """Configure a Rich-backed logger and return it.

    Args:
        verbose: When True, set DEBUG level. Otherwise INFO.

    Returns:
        The configured module logger.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    if not logger.handlers:
        handler = RichHandler(rich_tracebacks=True, markup=True, show_path=False)
        handler.setLevel(level)
        formatter = logging.Formatter("%(message)s", datefmt="[%X]")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.propagate = False
    return logger


def get_logger() -> logging.Logger:
    """Return the package logger (configured or not)."""
    return logging.getLogger(LOGGER_NAME)


def build_session(
    profile: Optional[str] = None,
    region: Optional[str] = None,
) -> boto3.Session:
    """Build a boto3 Session for the given profile/region.

    Args:
        profile: AWS profile name from ~/.aws/credentials.
        region: Optional region override.

    Returns:
        Configured boto3.Session.
    """
    kwargs = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    return boto3.Session(**kwargs)


def build_iam_client(session: boto3.Session):
    """Construct an IAM client with sensible retry config."""
    config = Config(retries={"max_attempts": 5, "mode": "standard"})
    return session.client("iam", config=config)


def build_sts_client(session: boto3.Session):
    """Construct an STS client with sensible retry config."""
    config = Config(retries={"max_attempts": 5, "mode": "standard"})
    return session.client("sts", config=config)


@dataclass(frozen=True)
class ArnParts:
    """Parsed components of an AWS ARN."""

    partition: str
    service: str
    region: str
    account_id: str
    resource_type: str
    resource_id: str

    @property
    def is_user(self) -> bool:
        return self.service == "iam" and self.resource_type == "user"

    @property
    def is_role(self) -> bool:
        return self.service == "iam" and self.resource_type == "role"


_ARN_RE = re.compile(
    r"^arn:(?P<partition>[^:]+):(?P<service>[^:]+):(?P<region>[^:]*):"
    r"(?P<account>[^:]*):(?P<resource>.+)$"
)


def parse_arn(arn: str) -> ArnParts:
    """Parse an AWS ARN into structured parts.

    Handles both ``service:resource_type/resource_id`` and
    ``service:resource_type:resource_id`` formats.

    Raises:
        ValueError: if the ARN is malformed.
    """
    match = _ARN_RE.match(arn)
    if not match:
        raise ValueError(f"Invalid ARN: {arn!r}")
    resource = match.group("resource")
    if "/" in resource:
        resource_type, _, resource_id = resource.partition("/")
    elif ":" in resource:
        resource_type, _, resource_id = resource.partition(":")
    else:
        resource_type, resource_id = "", resource
    return ArnParts(
        partition=match.group("partition"),
        service=match.group("service"),
        region=match.group("region"),
        account_id=match.group("account"),
        resource_type=resource_type,
        resource_id=resource_id,
    )


def action_matches(pattern: str, action: str) -> bool:
    """Return True if ``pattern`` (an IAM action with optional ``*``/``?``) matches ``action``.

    Both inputs are matched case-insensitively, mirroring IAM's behavior.
    """
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def actions_grant(
    granted_actions: Iterable[str],
    required_action: str,
) -> bool:
    """Check if any of ``granted_actions`` covers ``required_action``.

    Wildcards in granted actions are honored (e.g. ``iam:*`` covers ``iam:CreateUser``).
    """
    for granted in granted_actions:
        if action_matches(granted, required_action):
            return True
    return False


def expand_actions(actions) -> list[str]:
    """Normalize the ``Action`` field of a statement into a list of strings.

    A statement's Action can be a single string, a list of strings, or absent.
    """
    if actions is None:
        return []
    if isinstance(actions, str):
        return [actions]
    if isinstance(actions, list):
        return [a for a in actions if isinstance(a, str)]
    return []


def expand_resources(resources) -> list[str]:
    """Normalize the ``Resource`` field of a statement into a list of strings."""
    if resources is None:
        return ["*"]
    if isinstance(resources, str):
        return [resources]
    if isinstance(resources, list):
        return [r for r in resources if isinstance(r, str)]
    return ["*"]


def safe_call(func, *args, **kwargs):
    """Invoke an AWS API call and return ``None`` for AccessDenied / NoSuchEntity errors.

    The tool is designed to operate with read-only IAM access, so denied calls
    should degrade gracefully rather than crash. Other errors propagate.
    """
    logger = get_logger()
    try:
        return func(*args, **kwargs)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {
            "AccessDenied",
            "AccessDeniedException",
            "UnauthorizedOperation",
            "NoSuchEntity",
            "NoSuchEntityException",
        }:
            logger.debug("Skipping %s due to %s", func.__name__, code)
            return None
        raise
    except BotoCoreError as exc:
        logger.warning("BotoCore error in %s: %s", func.__name__, exc)
        return None
