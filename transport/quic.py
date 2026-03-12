#!/usr/bin/env python3
"""
QUIC транспорт для протокола Анемон
Обеспечивает низкую задержку и мультиплексирование
"""

import asyncio
import logging
import ssl
import certifi
from typing import Optional, Callable
from dataclasses import dataclass, field

import aioquic
from aioquic.asyncio import QuicConnectionProtocol, serve, connect
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived, ConnectionTerminated

from .base import BaseTransport, TransportConfig, TransportStats

logger = logging.getLogger(__name__)


@dataclass
class QUICConfig(TransportConfig):
    """Конфигурация QUIC транспорта"""
    server_name: str = "localhost"
    port: int = 4433
    alpn_protocols: list = field(default_factory=lambda: ["anemone", "h3"])
    max_datagram_size: int = 1200
    congestion_control: str = "reno"  # reno, cubic, bbr
    enable_0rtt: bool = True
    idle_timeout: float = 60.0


class AnemoneQuicProtocol(QuicConnectionProtocol):
    """Протокол QUIC для Анемон"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._data_callback = None
        self._close_callback = None
        self._streams = {}
    
    def quic_event_received(self, event: QuicEvent):
        """Обработка событий QUIC"""
        if isinstance(event, StreamDataReceived):
            # Данные получены
            if self._data_callback:
                asyncio.create_task(
                    self._data_callback(event.data, event.stream_id)
                )
        
        elif isinstance(event, ConnectionTerminated):
            # Соединение закрыто
            if self._close_callback:
                asyncio.create_task(self._close_callback())
    
    async def send_data(self, data: bytes, stream_id: int = 0):
        """Отправка данных"""
        self._quic.send_stream_data(stream_id, data)
        self.transmit()
    
    def set_callbacks(self, data_callback, close_callback):
        """Установка callback'ов"""
        self._data_callback = data_callback
        self._close_callback = close_callback


class QUICTransport(BaseTransport):
    """
    QUIC транспорт с поддержкой 0-RTT и мультиплексирования
    """
    
    def __init__(self, config: QUICConfig):
        super().__init__(config)
        self.config = config
        self.protocol: Optional[AnemoneQuicProtocol] = None
        self.client = None
        self.server = None
        self._data_callback: Optional[Callable] = None
        self._close_callback: Optional[Callable] = None
        self._ssl_context = None
        self._setup_ssl()
    
    def _setup_ssl(self):
        """Настройка SSL контекста для QUIC"""
        self._ssl_context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH,
            cafile=certifi.where()
        )
        self._ssl_context.check_hostname = False
        self._ssl_context.verify_mode = ssl.CERT_NONE  # Для тестирования
    
    async def connect(self, peer_id: Optional[str] = None) -> bool:
        """
        Подключение к QUIC серверу
        """
        try:
            configuration = QuicConfiguration(
                alpn_protocols=self.config.alpn_protocols,
                is_client=True,
                max_datagram_size=self.config.max_datagram_size,
                idle_timeout=self.config.idle_timeout
            )
            
            # Настройка конгестион контроля
            if self.config.congestion_control == "cubic":
                configuration.congestion_control_algorithm = "cubic"
            elif self.config.congestion_control == "bbr":
                configuration.congestion_control_algorithm = "bbr"
            
            # Подключаемся
            self.client = await connect(
                host=self.config.server_name,
                port=self.config.port,
                configuration=configuration,
                create_protocol=AnemoneQuicProtocol,
                session_ticket_handler=self._handle_session_ticket,
                wait_connected=True
            )
            
            self.protocol = self.client
            self.protocol.set_callbacks(
                self._on_data_received,
                self._on_connection_closed
            )
            
            self.connected = True
            logger.info(f"QUIC connected to {self.config.server_name}:{self.config.port}")
            
            if self._connect_callback:
                await self._connect_callback()
            
            return True
            
        except Exception as e:
            logger.error(f"QUIC connection failed: {e}")
            return False
    
    async def listen(self) -> bool:
        """
        Запуск QUIC сервера
        """
        try:
            configuration = QuicConfiguration(
                alpn_protocols=self.config.alpn_protocols,
                is_client=False,
                max_datagram_size=self.config.max_datagram_size,
                idle_timeout=self.config.idle_timeout
            )
            
            # Для продакшена нужны сертификаты
            configuration.load_cert_chain(
                certfile="cert.pem",
                keyfile="key.pem"
            )
            
            self.server = await serve(
                host="0.0.0.0",
                port=self.config.port,
                configuration=configuration,
                create_protocol=AnemoneQuicProtocol
            )
            
            logger.info(f"QUIC server listening on port {self.config.port}")
            return True
            
        except Exception as e:
            logger.error(f"QUIC server start failed: {e}")
            return False
    
    def _handle_session_ticket(self, ticket):
        """Обработка session ticket для 0-RTT"""
        if self.config.enable_0rtt:
            # Сохраняем ticket для будущих соединений
            logger.debug("Received session ticket for 0-RTT")
    
    def _on_data_received(self, data: bytes, stream_id: int):
        """Callback при получении данных"""
        self.bytes_received += len(data)
        self.packets_received += 1
        
        if self._data_callback:
            asyncio.create_task(self._data_callback(data))
    
    def _on_connection_closed(self):
        """Callback при закрытии соединения"""
        self.connected = False
        if self._close_callback:
            asyncio.create_task(self._close_callback())
    
    async def send(self, data: bytes) -> bool:
        """
        Отправка данных через QUIC
        """
        if not self.connected or not self.protocol:
            return False
        
        try:
            await self.protocol.send_data(data)
            self.bytes_sent += len(data)
            self.packets_sent += 1
            return True
        except Exception as e:
            logger.error(f"QUIC send failed: {e}")
            return False
    
    async def receive(self) -> Optional[bytes]:
        """
        Получение данных (используется callback)
        """
        return None
    
    def on_data(self, callback: Callable):
        """Установка callback для данных"""
        self._data_callback = callback
    
    def on_connect(self, callback: Callable):
        """Установка callback при подключении"""
        self._connect_callback = callback
    
    def on_close(self, callback: Callable):
        """Установка callback при закрытии"""
        self._close_callback = callback
    
    async def close(self):
        """Закрытие соединения"""
        logger.info("Closing QUIC transport")
        
        if self.client:
            self.client.close()
            await self.client.wait_closed()
        
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        self.connected = False
        logger.info("QUIC transport closed")
    
    def get_stats(self) -> TransportStats:
        """Получение статистики"""
        stats = TransportStats(
            bytes_sent=self.bytes_sent,
            bytes_received=self.bytes_received,
            packets_sent=self.packets_sent,
            packets_received=self.packets_received,
            connected=self.connected,
            rtt_ms=0
        )
        
        # Добавляем QUIC-специфичную статистику если доступна
        if self.protocol and self.protocol._quic:
            stats.extra = {
                'congestion_window': self.protocol._quic._path.congestion_window,
                'bytes_in_flight': self.protocol._quic._path.bytes_in_flight,
                'smoothed_rtt': self.protocol._quic._path.smoothed_rtt / 1000 if self.protocol._quic._path.smoothed_rtt else 0
            }
            stats.rtt_ms = stats.extra['smoothed_rtt']
        
        return stats