from scapy.all import *  # Scapy is a powerful Python-based network packet manipulation program & library
import logging  # Python's built-in logging module, for log file creation and management
import smtplib  # Simple Mail Transfer Protocol (SMTP) is used for sending emails
from email.message import EmailMessage  # To create and manage the email contents

# Initialize logging - We're creating a log file named 'intrusion_detection_log.txt', and setting logging level to INFO
logging.basicConfig(filename="intrusion_detection_log.txt", level=logging.INFO)

# Define a list of strings that we consider as potential intrusion indicators
patterns = [
    "bad_keyword1",
    "bad_keyword2",
    "bad_keyword3"
    # Add as many as you need, each representing a suspicious pattern to be checked in the packet payload
]

def send_email(alert_message):
    # This function is used to send email alerts when an intrusion is detected
    msg = EmailMessage()
    msg.set_content(alert_message)  # Setting the email content to the alert message

    # Setting the email parameters
    msg['Subject'] = 'IDS Alert'
    msg['From'] = "your_email@example.com"  # Replace this with the sender's email address
    msg['To'] = "destination_email@example.com"  # Replace this with the recipient's email address

    # Setting up the SMTP server through which the email will be sent
    server = smtplib.SMTP('smtp.gmail.com', 587)  # Gmail's SMTP server is used here, 587 is the port number
    server.starttls()  # Start TLS for security
    server.login("your_email@example.com", "your_password")  # Login to the sender's email account

    # Sending the email and closing the server connection
    server.send_message(msg)
    server.quit()

def packet_callback(packet):
    # This function is called for each packet sniffed
    if packet[TCP].payload:  # If the TCP packet has a payload
        tcp_payload = str(packet[TCP].payload)  # Convert the payload into a string

        # Check if the payload contains any of the suspicious patterns
        for pattern in patterns:
            if pattern in tcp_payload:
                alert_message = f"ALERT: Intrusion detected! Pattern: {pattern}"
                print(alert_message)  # Print the alert message to the console
                logging.info(alert_message)  # Log the alert message to the log file
                send_email(alert_message)  # Send an email alert

def start_intrusion_detection():
    # This function starts the intrusion detection by starting to sniff packets
    sniff(filter="tcp", prn=packet_callback, store=0)  # Sniff TCP packets, and for each packet, call the packet_callback function

if __name__ == "__main__":
    start_intrusion_detection()  # Start the intrusion detection
