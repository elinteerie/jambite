import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication


# Hardcoded SMTP server settings
SMTP_SERVER='smtp.gmail.com'
SMTP_PORT=465  # Port for TLS
SENDER_EMAIL='itededucationalsoftwares@gmail.com'
SENDER_PASSWORD='mpttokatkeucieev'

def send_custom_email(recipient_email, user_name, otp):
    """
    Sends a welcome email with an HTML template.
    
    :param recipient_email: Recipient's email address.
    :param user_name: The name of the recipient.
    """
    
    # HTML Email Template
    html_template = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to Jambite</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                background-color: #f4f4f4;
                margin: 0;
                padding: 0;
            }}
            .container {{
                max-width: 600px;
                margin: 20px auto;
                background-color: #ffffff;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1);
                text-align: center;
            }}
            h1 {{
                color: #333;
            }}
            p {{
                color: #555;
                font-size: 16px;
                line-height: 1.6;
            }}
            .button {{
                display: inline-block;
                background-color: #007bff;
                color: white;
                padding: 10px 20px;
                text-decoration: none;
                border-radius: 5px;
                margin-top: 20px;
            }}
            .footer {{
                margin-top: 20px;
                font-size: 12px;
                color: #888;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome to ArtiflexGateway - Mobile NFT Marketplace</h1>
            <p>Hi <strong>{user_name}</strong>,</p>
            <p>We're excited to have you on board. Get ready to explore all the amazing features we have to offer.</p>
            <h1>{otp} here is your code</h1>
            <p class="footer">If you have any questions, feel free to contact our support team.</p>
            <p class="footer">&copy; 2025 Jambite. All rights reserved.</p>
        </div>
    </body>
    </html>
    """

    # Create the email message
    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = recipient_email
    msg['Subject'] = "Welcome to ArtiflexGateway!"

    # Attach the HTML content
    msg.attach(MIMEText(html_template, 'html'))

    # Connect to the SMTP server and send the email
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Secure the connection
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
            print("Welcome email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")