import json
import logging

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

    return HttpResponse(status=200)


@csrf_exempt
@require_GET
def health(_request):
    return HttpResponse("ok", status=200)
