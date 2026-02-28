"""
Telegram notification service.
Sends alerts via Telegram bot.
"""

import logging
from typing import Optional
import asyncio
from telegram import Bot
from telegram.error import TelegramError


class TelegramNotificationService:
    """Service for sending Telegram notifications."""
    
    def __init__(
        self,
        bot_token: str,
        chat_id: str,
        enabled: bool = True
    ):
        """
        Initialize Telegram notification service.
        
        Args:
            bot_token: Telegram bot token
            chat_id: Telegram chat ID
            enabled: Whether service is enabled
        """
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.enabled = enabled
        self.logger = logging.getLogger('snmp_worker.telegram')
        
        if self.enabled and self.bot_token and self.chat_id:
            self.bot = Bot(token=self.bot_token)
            self.logger.info("Telegram notification service initialized")
        else:
            self.bot = None
            self.logger.info("Telegram notification service disabled")
    
    async def send_message_async(self, message: str) -> bool:
        """
        Send message via Telegram (async).
        
        Args:
            message: Message to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.enabled or not self.bot:
            self.logger.debug("Telegram disabled, skipping notification")
            return False
        
        try:
            await self.bot.send_message(
                chat_id=self.chat_id,
                text=message,
                parse_mode='HTML'
            )
            self.logger.info(f"Telegram message sent successfully")
            return True
        
        except TelegramError as e:
            self.logger.error(f"Failed to send Telegram message: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error sending Telegram message: {e}")
            return False
    
    def send_message(self, message: str) -> bool:
        """
        Send message via Telegram (sync wrapper).
        
        Args:
            message: Message to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.create_task(self.send_message_async(message))
                return True
            else:
                return loop.run_until_complete(self.send_message_async(message))
        except Exception as e:
            self.logger.error(f"Error in send_message: {e}")
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
        
        # Format severity emoji
        severity_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🔵',
            'INFO': 'ℹ️'
        }
        emoji = severity_emoji.get(severity_upper, '⚠️')
        
        # Format message
        formatted_message = (
            f"{emoji} <b>Network Alert</b>\n\n"
            f"<b>Device:</b> {device_name}\n"
            f"<b>IP:</b> {device_ip}\n"
            f"<b>Type:</b> {alarm_type}\n"
            f"<b>Severity:</b> {severity_upper}\n\n"
            f"<b>Message:</b>\n{message}"
        )
        
        return self.send_message(formatted_message)
    
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
        message = (
            f"🔴 <b>Port Kapandı</b>\n\n"
            f"<b>Cihaz:</b> {device_name}\n"
            f"<b>IP:</b> {device_ip}\n"
            f"<b>Port:</b> {port_number} ({port_name})\n\n"
            f"Port bağlantısı kesildi."
        )
        
        return self.send_message(message)
    
    def send_port_up(
        self,
        device_name: str,
        device_ip: str,
        port_number: int,
        port_name: str
    ) -> bool:
        """
        Send port up notification.
        
        Args:
            device_name: Device name
            device_ip: Device IP
            port_number: Port number
            port_name: Port name
            
        Returns:
            True if sent successfully, False otherwise
        """
        message = (
            f"🟢 <b>Port Up</b>\n\n"
            f"<b>Device:</b> {device_name}\n"
            f"<b>IP:</b> {device_ip}\n"
            f"<b>Port:</b> {port_number} ({port_name})\n\n"
            f"Port is now up."
        )
        
        return self.send_message(message)
    
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
        message = (
            f"🔴 <b>Device Unreachable</b>\n\n"
            f"<b>Device:</b> {device_name}\n"
            f"<b>IP:</b> {device_ip}\n\n"
            f"Device is not responding to SNMP requests."
        )
        
        return self.send_message(message)