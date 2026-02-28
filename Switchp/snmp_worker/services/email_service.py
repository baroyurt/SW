"""
Email notification service.
Sends alerts via email using SMTP.
"""

import logging
from typing import List, Optional
import asyncio
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


class EmailNotificationService:
    """Service for sending email notifications."""
    
    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        smtp_user: str,
        smtp_password: str,
        from_address: str,
        to_addresses: List[str],
        enabled: bool = True
    ):
        """
        Initialize email notification service.
        
        Args:
            smtp_host: SMTP server host
            smtp_port: SMTP server port
            smtp_user: SMTP username
            smtp_password: SMTP password
            from_address: From email address
            to_addresses: List of recipient email addresses
            enabled: Whether service is enabled
        """
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.from_address = from_address
        self.to_addresses = to_addresses
        self.enabled = enabled
        self.logger = logging.getLogger('snmp_worker.email')
        
        if self.enabled and self.to_addresses:
            self.logger.info(f"Email notification service initialized (sending to {len(to_addresses)} recipients)")
        else:
            self.logger.info("Email notification service disabled")
    
    async def send_email_async(
        self,
        subject: str,
        body: str,
        html_body: Optional[str] = None
    ) -> bool:
        """
        Send email (async).
        
        Args:
            subject: Email subject
            body: Email body (plain text)
            html_body: Optional HTML body
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.enabled or not self.to_addresses:
            self.logger.debug("Email disabled, skipping notification")
            return False
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.from_address
            msg['To'] = ', '.join(self.to_addresses)
            
            # Attach plain text
            msg.attach(MIMEText(body, 'plain'))
            
            # Attach HTML if provided
            if html_body:
                msg.attach(MIMEText(html_body, 'html'))
            
            # Send email
            await aiosmtplib.send(
                msg,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_user,
                password=self.smtp_password,
                start_tls=True
            )
            
            self.logger.info(f"Email sent successfully: {subject}")
            return True
        
        except Exception as e:
            self.logger.error(f"Failed to send email: {e}")
            return False
    
    def send_email(
        self,
        subject: str,
        body: str,
        html_body: Optional[str] = None
    ) -> bool:
        """
        Send email (sync wrapper).
        
        Args:
            subject: Email subject
            body: Email body (plain text)
            html_body: Optional HTML body
            
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(self.send_email_async(subject, body, html_body))
                return True
            else:
                return loop.run_until_complete(self.send_email_async(subject, body, html_body))
        except Exception as e:
            self.logger.error(f"Error in send_email: {e}")
            return False
    
    def send_alarm(
        self,
        device_name: str,
        device_ip: str,
        alarm_type: str,
        severity: str,
        message: str
    ) -> bool:
        """
        Send alarm notification.
        
        Args:
            device_name: Device name
            device_ip: Device IP
            alarm_type: Type of alarm
            severity: Alarm severity (UPPERCASE)
            message: Alarm message
            
        Returns:
            True if sent successfully, False otherwise
        """
        # ★★★ FIX: Severity zaten büyük harf, asla lower() kullanma! ★★★
        severity_upper = severity.upper() if severity else "MEDIUM"
        
        subject = f"[{severity_upper}] Network Alert - {device_name}"
        
        # Plain text body
        body = f"""
Network Alert

Device: {device_name}
IP: {device_ip}
Type: {alarm_type}
Severity: {severity_upper}

Message:
{message}

--
SNMP Worker - Network Monitoring System
"""
        
        # HTML body - severity_upper kullan
        severity_color = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#0dcaf0',
            'INFO': '#0d6efd'
        }
        color = severity_color.get(severity_upper, '#6c757d')
        
        html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
        .header {{ background-color: {color}; color: white; padding: 20px; }}
        .content {{ padding: 20px; }}
        .info {{ background-color: #f8f9fa; padding: 15px; border-left: 4px solid {color}; }}
        .footer {{ padding: 20px; font-size: 12px; color: #6c757d; }}
    </style>
</head>
<body>
    <div class="header">
        <h2>Network Alert</h2>
    </div>
    <div class="content">
        <div class="info">
            <p><strong>Device:</strong> {device_name}</p>
            <p><strong>IP Address:</strong> {device_ip}</p>
            <p><strong>Alert Type:</strong> {alarm_type}</p>
            <p><strong>Severity:</strong> {severity_upper}</p>
        </div>
        <h3>Details</h3>
        <p>{message}</p>
    </div>
    <div class="footer">
        <p>SNMP Worker - Network Monitoring System</p>
    </div>
</body>
</html>
"""
        
        return self.send_email(subject, body, html_body)
    
    def send_port_down(
        self,
        device_name: str,
        device_ip: str,
        port_number: int,
        port_name: str
    ) -> bool:
        """
        Send port down notification.
        
        Args:
            device_name: Device name
            device_ip: Device IP
            port_number: Port number
            port_name: Port name
            
        Returns:
            True if sent successfully, False otherwise
        """
        subject = f"[HIGH] Port Kapandı - {device_name} Port {port_number}"
        message = f"{device_name} cihazında Port {port_number} ({port_name}) bağlantısı kesildi."
        
        return self.send_alarm(device_name, device_ip, "Port Kapandı", "HIGH", message)
    
    def send_device_unreachable(
        self,
        device_name: str,
        device_ip: str
    ) -> bool:
        """
        Send device unreachable notification.
        
        Args:
            device_name: Device name
            device_ip: Device IP
            
        Returns:
            True if sent successfully, False otherwise
        """
        subject = f"[CRITICAL] Device Unreachable - {device_name}"
        message = f"Device {device_name} ({device_ip}) is not responding to SNMP requests."
        
        return self.send_alarm(device_name, device_ip, "Device Unreachable", "CRITICAL", message)