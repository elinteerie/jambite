import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication


# Hardcoded SMTP server settings
SMTP_SERVER = 'digitalearthmining.com'
SMTP_PORT = 587  # Port for TLS
SENDER_EMAIL = 'jjo@digitalearthmining.com'
SENDER_PASSWORD = 'uy3K5zsMhkllo4Lf'

def send_custom_email(recipient_email, sender_username, subject, message, is_html=False):
    """
    Function to send an email using hardcoded SMTP server settings.
    
    :param recipient_email: Recipient's email address.
    :param sender_username: Sender's email address (username).
    :param subject: Subject of the email.
    :param message: Body of the email.
    :param is_html: Boolean indicating if the message is HTML.
    """
    
    # Create the email message
    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = recipient_email
    msg['Subject'] = subject
    
    # Attach the message body
    if is_html:
        msg.attach(MIMEText(message, 'html'))
    else:
        msg.attach(MIMEText(message, 'plain'))
    
    # Connect to the SMTP server and send the email
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Upgrade the connection to a secure encrypted SSL/TLS connection
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
            print("Email sent successfully")
    except Exception as e:
        print(f"Failed to send email: {e}")
