import base64
import datetime
import json
import logging
import os
import uuid

import httpx
import jwt
from django.conf import settings
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST


@csrf_exempt
@require_POST
def postmark_webhook(request):
    """
    Handle Postmark webhooks.
    See: https://postmarkapp.com/developer/webhooks/webhooks-overview
    """

    data = json.loads(request.body)
    from_email = data.get("From")
    to_email = data.get("To")
    subject = data.get("Subject")
    text_body = data.get("TextBody")
    header_list = data.get("Headers", [])

    # get message id from headers
    message_id = None
    for header in header_list:
        if header.get("Name").lower() == "message-id":
            message_id = header.get("Value")
            break

    # check spam status
    spam_status = False
    for header in header_list:
        if (
            header.get("Name") == "X-Spam-Status"
            and header.get("Value").lower() == "yes"
        ):
            spam_status = True
            break

    logging.info(
        "Postmark webhook payload: from=%s to=%s subject=%s spam=%s message_id=%s text_body=%s headers=%s",
        from_email,
        to_email,
        subject,
        spam_status,
        message_id,
        text_body,
        header_list,
    )

    if spam_status:
        return HttpResponse(status=200)

    _create_pr_with_test_file(
        from_email=from_email,
        to_email=to_email,
        subject=subject,
        text_body=text_body,
    )

    return HttpResponse(status=200)


@csrf_exempt
@require_GET
def health(_request):
    return HttpResponse("ok", status=200)


def _get_github_token():
    token = getattr(settings, "GITHUB_TOKEN", None) or os.getenv("GITHUB_TOKEN")
    if token:
        return token
    return _get_installation_token()


def _normalize_private_key(raw_key: str) -> str:
    # Allow env vars with literal "\n" sequences.
    return raw_key.replace("\\n", "\n")


def _get_installation_token():
    app_id = getattr(settings, "GITHUB_APP_ID", None) or os.getenv("GITHUB_APP_ID")
    installation_id = getattr(settings, "GITHUB_INSTALLATION_ID", None) or os.getenv(
        "GITHUB_INSTALLATION_ID"
    )
    private_key = getattr(settings, "GITHUB_APP_PRIVATE_KEY", None) or os.getenv(
        "GITHUB_APP_PRIVATE_KEY"
    )

    if not (app_id and installation_id and private_key):
        logging.error(
            "GitHub App credentials missing; set GITHUB_APP_ID, GITHUB_INSTALLATION_ID, and GITHUB_APP_PRIVATE_KEY."
        )
        return None

    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "iat": now - datetime.timedelta(seconds=60),
        "exp": now + datetime.timedelta(minutes=9),
        "iss": app_id,
    }

    try:
        signed_jwt = jwt.encode(
            payload,
            _normalize_private_key(private_key),
            algorithm="RS256",
        )
    except Exception as exc:  # pragma: no cover - defensive logging
        logging.error("Failed to sign GitHub App JWT: %s", exc)
        return None

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {signed_jwt}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "fivehundredzero-postmark",
    }

    try:
        resp = httpx.post(
            f"https://api.github.com/app/installations/{installation_id}/access_tokens",
            headers=headers,
            timeout=10,
        )
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        try:
            detail = exc.response.json()
        except ValueError:
            detail = exc.response.text
        logging.error(
            "GitHub App token request status error (%s): %s",
            exc.response.status_code,
            detail,
        )
        return None
    except httpx.HTTPError as exc:
        logging.error("GitHub App token request failed: %s", exc)
        return None

    return resp.json().get("token")


def _create_pr_with_test_file(*, from_email, to_email, subject, text_body):
    """
    Create a branch on sirodoht/fivehundredzero, add file 'test', and open a PR.
    """

    token = _get_github_token()
    if not token:
        logging.error("No GitHub token available; cannot open PR.")
        return

    repo = "sirodoht/fivehundredzero"
    base_branch = "main"
    branch_name = f"postmark-{uuid.uuid4().hex[:12]}"
    api_base = "https://api.github.com"

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "fivehundredzero-postmark",
    }

    body_content = (
        f"From: {from_email}\nTo: {to_email}\nSubject: {subject}\n\n{text_body or ''}\n"
    )
    encoded_content = base64.b64encode(body_content.encode()).decode()

    try:
        with httpx.Client(headers=headers, timeout=10) as client:
            ref_resp = client.get(
                f"{api_base}/repos/{repo}/git/ref/heads/{base_branch}"
            )
            ref_resp.raise_for_status()
            base_sha = ref_resp.json()["object"]["sha"]

            create_ref_resp = client.post(
                f"{api_base}/repos/{repo}/git/refs",
                json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
            )
            create_ref_resp.raise_for_status()

            create_file_resp = client.put(
                f"{api_base}/repos/{repo}/contents/test",
                json={
                    "message": f"Add test file from Postmark webhook {branch_name}",
                    "content": encoded_content,
                    "branch": branch_name,
                },
            )
            create_file_resp.raise_for_status()

            pr_title = f"Postmark email: {subject or 'No subject'}"
            pr_body = f"Auto-created from Postmark webhook.\n\nFrom: {from_email}\nTo: {to_email}\n\n{text_body or ''}"
            pr_resp = client.post(
                f"{api_base}/repos/{repo}/pulls",
                json={
                    "title": pr_title[:240],
                    "head": branch_name,
                    "base": base_branch,
                    "body": pr_body[:4000],
                },
            )
            pr_resp.raise_for_status()

            pr_url = pr_resp.json().get("html_url")
            logging.info("Created PR for Postmark email: %s", pr_url)
    except httpx.HTTPStatusError as exc:
        try:
            detail = exc.response.json()
        except ValueError:
            detail = exc.response.text
        logging.error(
            "GitHub API status error (%s): %s", exc.response.status_code, detail
        )
    except httpx.HTTPError as exc:
        logging.error("GitHub API request failed: %s", exc)
