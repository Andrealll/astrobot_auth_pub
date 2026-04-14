import os
import resend

resend.api_key = os.getenv("RESEND_API_KEY")


def send_email(to: str, subject: str, html: str):
    params = {
        "from": os.getenv("EMAIL_FROM"),
        "to": [to],
        "subject": subject,
        "html": html,
    }
    return resend.Emails.send(params)