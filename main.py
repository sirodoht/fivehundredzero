import logging
import re
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, EmailStr, Field

logger = logging.getLogger(__name__)

app = FastAPI()


class PostmarkHeader(BaseModel):
    Name: str
    Value: str


class PostmarkInbound(BaseModel):
    """
    Minimal schema for Postmark inbound webhook payloads.
    https://postmarkapp.com/developer/webhooks/webhooks-overview
    """

    From: EmailStr
    To: EmailStr
    Subject: Optional[str] = ""
    TextBody: Optional[str] = ""
    Headers: List[PostmarkHeader] = Field(default_factory=list)


class User:
    def __init__(
        self, *, email: str, username: str, has_premium_features: bool
    ) -> None:
        self.email = email
        self.username = username
        self.has_premium_features = has_premium_features


class Post:
    def __init__(
        self,
        *,
        title: str,
        slug: str,
        body: str,
        owner: User,
        published_at: Optional[datetime],
    ) -> None:
        self.title = title
        self.slug = slug
        self.body = body
        self.owner = owner
        self.published_at = published_at

    def get_proper_url(self) -> str:
        return f"{self.owner.username}.{CANONICAL_HOST}/posts/{self.slug}"


# Configuration placeholders. Wire these to your settings/env in real usage.
CANONICAL_HOST = "example.com"
DEFAULT_FROM_EMAIL = "no-reply@example.com"
SCHEME = "https://"

# Simple in-memory stores used for the example implementation.
_users: List[User] = [
    User(email="alice@example.com", username="alice", has_premium_features=True),
    User(email="bob@example.com", username="bob", has_premium_features=False),
]
_posts_by_user: Dict[str, List[Post]] = {}


def _slugify(title: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", title).strip("-").lower() or "post"
    return slug


def _next_slug_for_user(title: str, user: User) -> str:
    existing = {p.slug for p in _posts_by_user.get(user.username, [])}
    base = _slugify(title)
    if base not in existing:
        return base
    idx = 2
    while f"{base}-{idx}" in existing:
        idx += 1
    return f"{base}-{idx}"


def _find_user_by_email(email: str) -> Optional[User]:
    matches = [u for u in _users if u.email.lower() == email.lower()]
    if not matches:
        return None
    if len(matches) > 1:
        raise ValueError("multiple users with same email")
    return matches[0]


def _save_post(*, title: str, body: str, is_draft: bool, owner: User) -> Post:
    slug = _next_slug_for_user(title, owner)
    post = Post(
        title=title,
        slug=slug,
        body=body,
        owner=owner,
        published_at=None if is_draft else datetime.utcnow(),
    )
    _posts_by_user.setdefault(owner.username, []).append(post)
    return post


def _send_email(
    *, subject: str, body: str, to: str, in_reply_to: Optional[str]
) -> None:
    headers = {}
    if in_reply_to:
        headers["In-Reply-To"] = in_reply_to
        headers["References"] = in_reply_to
    logger.info(
        "Sending email",
        extra={"to": to, "subject": subject, "headers": headers, "body": body},
    )


def _notify_admins(message: str) -> None:
    logger.error("Admin notification: %s", message)


def _extract_header(headers: List[PostmarkHeader], name: str) -> Optional[str]:
    for header in headers:
        if header.Name.lower() == name.lower():
            return header.Value
    return None


@app.post("/webhooks/postmark", response_class=PlainTextResponse)
async def postmark_webhook(payload: PostmarkInbound) -> PlainTextResponse:
    headers = payload.Headers

    spam_status = any(
        header.Name.lower() == "x-spam-status" and header.Value.lower() == "yes"
        for header in headers
    )
    if spam_status:
        return PlainTextResponse(status_code=200)

    message_id = _extract_header(headers, "message-id")

    try:
        user = _find_user_by_email(payload.From)
    except ValueError:
        _notify_admins(
            f"Multiple users with same email in inbound post: {payload.From}"
        )
        return PlainTextResponse(status_code=500)

    if user is None:
        return PlainTextResponse(status_code=200)

    try:
        to_local, to_domain = payload.To.split("@", 1)
    except ValueError:
        return PlainTextResponse(status_code=200)

    if to_local not in ("post", "draft"):
        return PlainTextResponse(status_code=200)

    if to_domain != f"{user.username}.{CANONICAL_HOST}":
        return PlainTextResponse(status_code=200)

    is_draft = to_local == "draft"

    post = _save_post(
        title=payload.Subject or "(no subject)",
        body=payload.TextBody or "",
        is_draft=is_draft,
        owner=user,
    )

    _send_email(
        subject=payload.Subject or "",
        body=SCHEME + post.get_proper_url(),
        to=payload.From,
        in_reply_to=message_id,
    )

    return PlainTextResponse(status_code=200)
