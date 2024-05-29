# utils.py
import random
from django.core.mail import send_mail
import mimetypes
from django.core.mail import EmailMessage
import threading
from django.template.loader import render_to_string
# Import necessary libraries
import base64
from django.utils.safestring import mark_safe


class EmailThread(threading.Thread):
    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()


class Util:
    @staticmethod
    def send_email(data, use_html_content=True):
        from_email = 'noblepay@nobleservefinance.com'

        # Create an EmailMessage
        email = EmailMessage(
            subject=data['email_subject'],
            to=[data['to_email']],
            from_email=from_email,
        )

        # Set the email body content
        email_body = mark_safe(data['email_body'])
        if use_html_content:
            # Set content_subtype to 'html' if HTML content is used
            email.content_subtype = 'html'
        email.body = email_body

        # Attach the file if provided
        if 'file_name' in data and 'file_content' in data:
            file_content = base64.b64decode(data['file_content'])
            content_type, encoding = mimetypes.guess_type(data['file_name'])
            content_type = content_type or 'application/octet-stream'
            email.attach(data['file_name'], file_content, content_type)

        # Create an instance of EmailThread with the email
        email_thread = EmailThread(email)

        # Start the email thread to send the email asynchronously
        email_thread.start()


def generate_verification_code():
    return str(random.randint(10000, 99999))
