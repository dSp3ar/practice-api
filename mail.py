import datetime
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import jwt
from flask import request

from config import Config

sender_email, sender_password = "pashadrovnin.camo@gmail.com", "crek dfrr yfda zcmk"
server = smtplib.SMTP("smtp.gmail.com", 587)
server.starttls()
message = MIMEMultipart()
message["From"] = sender_email


def create_approve_url(user_id):
    return request.root_url + 'auth/approval/' + jwt.encode(
        {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=10),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        },
        Config.SECRET_APPROVAL_KEY,
        algorithm='HS256'
    )


def send_email(recipient_email, subject, body):
    message.attach(MIMEText(body, "plain"))
    message["To"], message["Subject"] = recipient_email, subject
    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, recipient_email, message.as_string())
