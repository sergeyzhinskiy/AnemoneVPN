#!/usr/bin/env python3
"""
Базовые классы для транспортов протокола Анемон
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional, Callable, Dict, Any
import logging

logger = logging.getLogger(__name__)


@dataclass
class TransportConfig:
    """Базовая конфигурация транспорта"""
    enabled: bool = True
    timeout: float = 30.0
    max_retries: int = 3


@dataclass
class TransportStats:
    """Статистика транспорта"""
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    connected: bool = False
    rtt_ms: float = 0.0
    extra: Dict[str, Any] = None


class BaseTransport(ABC):
    """
    Абстрактный базовый класс для всех транспортов
    """
    
    def __init__(self, config: TransportConfig):
        self.config = config
        self.connected = False
        self.bytes_sent = 0
        self.bytes_received = 0
        self.packets_sent = 0
        self.packets_received = 0
        self._connect_callback: Optional[Callable] = None
        self._data_callback: Optional[Callable] = None
        self._close_callback: Optional[Callable] = None
    
    @abstractmethod
    async def connect(self, peer_id: Optional[str] = None) -> bool:
        """Установка соединения"""
        pass
    
    @abstractmethod
    async def listen(self) -> bool:
        """Ожидание входящего соединения (для сервера)"""
        pass
    
    @abstractmethod
    async def send(self, data: bytes) -> bool:
        """Отправка данных"""
        pass
    
    @abstractmethod
    async def receive(self) -> Optional[bytes]:
        """Получение данных"""
        pass
    
    @abstractmethod
    async def close(self):
        """Закрытие соединения"""
        pass
    
    @abstractmethod
    def get_stats(self) -> TransportStats:
        """Получение статистики"""
        return TransportStats(
            bytes_sent=self.bytes_sent,
            bytes_received=self.bytes_received,
            packets_sent=self.packets_sent,
            packets_received=self.packets_received,
            connected=self.connected
        )
    
    def on_connect(self, callback: Callable):
        """Установка callback при подключении"""
        self._connect_callback = callback
    
    def on_data(self, callback: Callable):
        """Установка callback при получении данных"""
        self._data_callback = callback
    
    def on_close(self, callback: Callable):
        """Установка callback при закрытии"""
        self._close_callback = callback
