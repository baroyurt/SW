"""
Email notification service.
Sends alerts via email using SMTP.
"""

import logging
from datetime import datetime
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
        enabled: bool = True,
        smtp_ssl_verify: bool = False
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
            smtp_ssl_verify: Whether to validate the SMTP server's TLS certificate.
                             Set False (default) for on-premise servers that use
                             self-signed or private-CA certificates.
        """
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_password = smtp_password
        self.from_address = from_address
        self.to_addresses = to_addresses
        self.enabled = enabled
        self.smtp_ssl_verify = smtp_ssl_verify
        self.logger = logging.getLogger('snmp_worker.email')
        
        if self.enabled and self.to_addresses:
            self.logger.info(f"Email notification service initialized (sending to {len(to_addresses)} recipients)")
        else:
            self.logger.info("Email notification service disabled")
    
    async def send_email_async(
        self,
        subject: str,
        body: str,
        html_body: Optional[str] = None,
        recipients: Optional[List[str]] = None
    ) -> bool:
        """
        Send email (async).
        
        Args:
            subject: Email subject
            body: Email body (plain text)
            html_body: Optional HTML body
            recipients: Optional override for recipient list (uses self.to_addresses if None)
            
        Returns:
            True if sent successfully, False otherwise
        """
        to_list = recipients if recipients is not None else self.to_addresses
        if not self.enabled or not to_list:
            self.logger.debug("Email disabled or no recipients, skipping notification")
            return False
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.from_address
            msg['To'] = ', '.join(to_list)
            
            # Attach plain text
            msg.attach(MIMEText(body, 'plain'))
            
            # Attach HTML if provided
            if html_body:
                msg.attach(MIMEText(html_body, 'html'))
            
            # Send email.
            # Port 465 → implicit SSL/TLS (use_tls=True).
            # Port 587 → STARTTLS (start_tls=True).
            # Any other port defaults to STARTTLS for safety.
            # validate_certs is controlled by the smtp_ssl_verify config setting (default False)
            # for on-premise servers that use self-signed / private-CA certificates.
            validate = self.smtp_ssl_verify
            tls_kwargs = (
                {"use_tls": True, "validate_certs": validate} if self.smtp_port == 465
                else {"start_tls": True, "validate_certs": validate}
            )
            await aiosmtplib.send(
                msg,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_user,
                password=self.smtp_password,
                **tls_kwargs
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
        html_body: Optional[str] = None,
        recipients: Optional[List[str]] = None
    ) -> bool:
        """
        Send email (sync wrapper).
        
        Args:
            subject: Email subject
            body: Email body (plain text)
            html_body: Optional HTML body
            recipients: Optional override for recipient list (uses self.to_addresses if None)
            
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            # asyncio.run() creates a fresh event loop, runs the coroutine to
            # completion, then closes it.  This works correctly from any sync
            # context — including background threads — and does not depend on a
            # pre-existing event loop.  (asyncio.get_event_loop() raises
            # RuntimeError in Python 3.10+ when called from a non-main thread
            # that has no running event loop, which silently broke email in the
            # threaded worker.)
            return asyncio.run(self.send_email_async(subject, body, html_body, recipients))
        except RuntimeError as e:
            if "This event loop is already running" in str(e):
                # Called from inside a running async context — schedule as task.
                asyncio.ensure_future(self.send_email_async(subject, body, html_body, recipients))
                return True
            self.logger.error(f"Error in send_email: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error in send_email: {e}")
            return False
    
    def send_alarm(
        self,
        device_name: str,
        device_ip: str,
        alarm_type: str,
        severity: str,
        message: str,
        recipients: Optional[List[str]] = None
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
        
        now = datetime.now().strftime('%d.%m.%Y %H:%M:%S')
        
        subject = f"CHAMADA Network Alert"
        
        # Plain text body
        body = f"""
CHAMADA Network Alert

Device: {device_name}
IP: ***
Type: {alarm_type}
Severity: {severity_upper}
Time: {now}

Message:
{message}

--
CHAMADA Network Monitoring System
"""
        
        # HTML body — CHAMADA dark theme
        severity_color = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#0dcaf0',
            'INFO': '#0d6efd'
        }
        color = severity_color.get(severity_upper, '#6c757d')

        logo_svg = (
            f'<img src="data:image/png;base64,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" '
            'width="36" height="36" alt="CHAMADA" style="display:block;border:0;">'
        )

        html_body = f"""<!DOCTYPE html>
<html lang="tr">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>CHAMADA Network Alert</title></head>
<body style="margin:0;padding:0;background:#0a0f1c;font-family:Arial,Helvetica,sans-serif;color:#c8d5e8;">
<table width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#0a0f1c">
  <tr><td align="center" style="padding:30px 10px;">
    <table width="620" cellpadding="0" cellspacing="0" border="0"
           style="max-width:620px;width:100%;background:#111827;border-radius:10px;
                  border:1px solid #1e2d4d;overflow:hidden;">
      <!-- Header -->
      <tr><td style="background:linear-gradient(135deg,#0d1527 0%,#1a2540 100%);
                     padding:22px 28px;border-bottom:2px solid #d4a017;">
        <table cellpadding="0" cellspacing="0" border="0"><tr>
          <td style="vertical-align:middle;padding-right:14px;">{logo_svg}</td>
          <td style="vertical-align:middle;line-height:1.3;">
            <span style="display:block;font-size:20px;font-weight:900;color:#d4a017;letter-spacing:3px;">CHAMADA</span>
            <span style="display:block;font-size:12px;color:#8899bb;letter-spacing:1px;margin-top:2px;">Network Alert</span>
          </td>
        </tr></table>
      </td></tr>
      <!-- Content -->
      <tr><td style="padding:28px;color:#c8d5e8;">
        <p style="margin:0 0 16px;font-size:15px;font-weight:700;color:{color};">
          [{severity_upper}] {device_name}
        </p>
        <table cellpadding="0" cellspacing="0" border="0"
               style="border-left:3px solid {color};padding-left:14px;width:100%;">
          <tr><td style="padding:4px 0;color:#8899bb;width:130px;">Cihaz:</td>
              <td style="padding:4px 0;color:#c8d5e8;">{device_name}</td></tr>
          <tr><td style="padding:4px 0;color:#8899bb;">IP Adresi:</td>
              <td style="padding:4px 0;color:#c8d5e8;">***</td></tr>
          <tr><td style="padding:4px 0;color:#8899bb;">Alarm Türü:</td>
              <td style="padding:4px 0;color:#c8d5e8;">{alarm_type}</td></tr>
          <tr><td style="padding:4px 0;color:#8899bb;">Önem:</td>
              <td style="padding:4px 0;font-weight:700;color:{color};">{severity_upper}</td></tr>
          <tr><td style="padding:4px 0;color:#8899bb;">Saat:</td>
              <td style="padding:4px 0;color:#c8d5e8;">{now}</td></tr>
        </table>
        <p style="margin:18px 0 6px;font-weight:700;color:#8899bb;">Detaylar</p>
        <p style="margin:0;color:#c8d5e8;">{message}</p>
      </td></tr>
      <!-- Footer -->
      <tr><td style="background:#070d1a;padding:14px 28px;border-top:1px solid #1e2d4d;text-align:center;">
        <span style="font-size:11px;color:#4a5568;">CHAMADA Network Monitoring System</span>
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>"""
        
        return self.send_email(subject, body, html_body, recipients)
    
    def send_mac_moved(
        self,
        old_device_name: str,
        old_port: str,
        new_device_name: str,
        new_port: str,
        old_conn: str,
        new_conn: str,
        mac_address: str,
        message: str,
        vlan_id: Optional[int] = None,
        severity: str = "HIGH",
        recipients: Optional[List[str]] = None
    ) -> bool:
        """
        Send a MAC-moved notification with Device-A (red) / Device-B (green) HTML layout.

        Args:
            old_device_name: Source device name (Device-A)
            old_port: Source port string
            new_device_name: Destination device name (Device-B)
            new_port: Destination port string
            old_conn: Human-readable connection label for source port, e.g. "DRGT(172.18.1.1)"
            new_conn: Human-readable connection label for destination port, e.g. "Osman(172.18.1.2)"
            mac_address: The MAC address that moved
            message: Full plain-text alarm message (used for plain-text part of the email)
            vlan_id: VLAN ID if known
            severity: Alarm severity string (uppercase)

        Returns:
            True if sent successfully, False otherwise
        """
        severity_upper = severity.upper() if severity else "HIGH"
        now = datetime.now().strftime('%d.%m.%Y %H:%M:%S')

        subject = "CHAMADA Network Alert – MAC Hareketi"

        # Plain-text body
        body = f"""
CHAMADA Network Alert – MAC Hareketi

MAC: {mac_address}
VLAN: {vlan_id if vlan_id else '-'}
Saat: {now}

Kaynak  (Device-A): {old_device_name} port {old_port}  |  Mevcut Bağlantı: {old_conn}
Hedef   (Device-B): {new_device_name} port {new_port}  |  Mevcut Bağlantı: {new_conn}

Detaylar:
{message}

--
CHAMADA Network Monitoring System
"""

        logo_svg = (
            f'<img src="data:image/png;base64,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" '
            'width="36" height="36" alt="CHAMADA" style="display:block;border:0;">'
        )

        vlan_str = str(vlan_id) if vlan_id else "-"
        severity_color = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#0dcaf0',
            'INFO': '#0d6efd'
        }
        hdr_color = severity_color.get(severity_upper, '#fd7e14')

        html_body = f"""<!DOCTYPE html>
<html lang="tr">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>CHAMADA – MAC Hareketi</title></head>
<body style="margin:0;padding:0;background:#0a0f1c;font-family:Arial,Helvetica,sans-serif;color:#c8d5e8;">
<table width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#0a0f1c">
  <tr><td align="center" style="padding:30px 10px;">
    <table width="640" cellpadding="0" cellspacing="0" border="0"
           style="max-width:640px;width:100%;background:#111827;border-radius:10px;
                  border:1px solid #1e2d4d;overflow:hidden;">
      <!-- Header -->
      <tr><td style="background:linear-gradient(135deg,#0d1527 0%,#1a2540 100%);
                     padding:22px 28px;border-bottom:2px solid #d4a017;">
        <table cellpadding="0" cellspacing="0" border="0"><tr>
          <td style="vertical-align:middle;padding-right:14px;">{logo_svg}</td>
          <td style="vertical-align:middle;line-height:1.3;">
            <span style="display:block;font-size:20px;font-weight:900;color:#d4a017;letter-spacing:3px;">CHAMADA</span>
            <span style="display:block;font-size:12px;color:#8899bb;letter-spacing:1px;margin-top:2px;">MAC Hareketi Alarmı</span>
          </td>
        </tr></table>
      </td></tr>
      <!-- Summary bar -->
      <tr><td style="padding:14px 28px;background:#0d1527;border-bottom:1px solid #1e2d4d;">
        <p style="margin:0;font-size:14px;font-weight:700;color:{hdr_color};">
          [{severity_upper}] &nbsp; MAC: {mac_address} &nbsp;|&nbsp; VLAN: {vlan_str} &nbsp;|&nbsp; {now}
        </p>
      </td></tr>
      <!-- Device-A row (red) -->
      <tr><td style="padding:18px 28px 10px;">
        <table width="100%" cellpadding="0" cellspacing="0" border="0"
               style="border-left:4px solid #dc3545;padding-left:14px;background:#1a0d0d;
                      border-radius:0 6px 6px 0;">
          <tr>
            <td style="padding:10px 14px;">
              <span style="display:block;font-size:11px;font-weight:700;color:#dc3545;
                           text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">
                &#9650; Device-A &nbsp;(Kaynak – Eski Konum)
              </span>
              <span style="font-size:14px;font-weight:700;color:#f5c0c0;">
                {old_device_name} &nbsp; Port {old_port}
              </span><br>
              <span style="font-size:13px;color:#e08080;">
                Mevcut Bağlantı: {old_conn}
              </span>
            </td>
          </tr>
        </table>
      </td></tr>
      <!-- Arrow -->
      <tr><td style="text-align:center;padding:4px 0;font-size:20px;color:#8899bb;">&#9660;</td></tr>
      <!-- Device-B row (green) -->
      <tr><td style="padding:10px 28px 18px;">
        <table width="100%" cellpadding="0" cellspacing="0" border="0"
               style="border-left:4px solid #28a745;padding-left:14px;background:#0d1a0e;
                      border-radius:0 6px 6px 0;">
          <tr>
            <td style="padding:10px 14px;">
              <span style="display:block;font-size:11px;font-weight:700;color:#28a745;
                           text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">
                &#9654; Device-B &nbsp;(Hedef – Yeni Konum)
              </span>
              <span style="font-size:14px;font-weight:700;color:#b0f0b0;">
                {new_device_name} &nbsp; Port {new_port}
              </span><br>
              <span style="font-size:13px;color:#80c880;">
                Mevcut Bağlantı: {new_conn}
              </span>
            </td>
          </tr>
        </table>
      </td></tr>
      <!-- Footer -->
      <tr><td style="background:#070d1a;padding:14px 28px;border-top:1px solid #1e2d4d;text-align:center;">
        <span style="font-size:11px;color:#4a5568;">CHAMADA Network Monitoring System</span>
      </td></tr>
    </table>
  </td></tr>
</table>
</body></html>"""

        return self.send_email(subject, body, html_body, recipients)

    def send_port_down(
        self,
        device_name: str,
        device_ip: str,
        port_number: int,
        port_name: str,
        recipients: Optional[List[str]] = None
    ) -> bool:
        """
        Send port down notification.
        
        Args:
            device_name: Device name
            device_ip: Device IP
            port_number: Port number
            port_name: Port name
            recipients: Optional override for recipient list
            
        Returns:
            True if sent successfully, False otherwise
        """
        subject = f"[HIGH] Port Kapandı - {device_name} Port {port_number}"
        message = f"{device_name} cihazında Port {port_number} ({port_name}) bağlantısı kesildi."
        
        return self.send_alarm(device_name, device_ip, "Port Kapandı", "HIGH", message, recipients)
    
    def send_device_unreachable(
        self,
        device_name: str,
        device_ip: str,
        recipients: Optional[List[str]] = None
    ) -> bool:
        """
        Send device unreachable notification.
        
        Args:
            device_name: Device name
            device_ip: Device IP
            recipients: Optional override for recipient list
            
        Returns:
            True if sent successfully, False otherwise
        """
        subject = f"[CRITICAL] Device Unreachable - {device_name}"
        message = f"Device {device_name} is not responding to SNMP requests."
        
        return self.send_alarm(device_name, device_ip, "Device Unreachable", "CRITICAL", message, recipients)
