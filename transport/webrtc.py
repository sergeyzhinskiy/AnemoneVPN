#!/usr/bin/env python3
"""
WebRTC транспорт для протокола Анемон
Использует aiortc для P2P соединений с обходом NAT 
"""

import asyncio
import json
import logging
import random
import string
from typing import Optional, Callable, Dict, Any
from dataclasses import dataclass, field

from aiortc import RTCPeerConnection, RTCSessionDescription, RTCDataChannel
#from aiortc import SignalingState
from aiortc.contrib.signaling import TcpSocketSignaling
import websockets

from .base import BaseTransport, TransportConfig, TransportStats

logger = logging.getLogger(__name__)


@dataclass
class WebRTCConfig(TransportConfig):
    """Конфигурация WebRTC транспорта"""
    ice_servers: list = field(default_factory=lambda: [
        {'urls': 'stun:stun.l.google.com:19302'},
        {'urls': 'stun:stun1.l.google.com:19302'}
    ])
    signaling_server: str = "ws://localhost:8080"
    max_message_size: int = 65535
    data_channel_label: str = "anemone"
    ordered: bool = False  # Неупорядоченная доставка для скорости
    max_retransmits: Optional[int] = None  # Без ретрансмиссий для real-time


class WebRTCTransport(BaseTransport):
    """
    WebRTC транспорт с поддержкой P2P и обхода NAT 
    """
    
    def __init__(self, config: WebRTCConfig):
        super().__init__(config)
        self.config = config
        self.pc: Optional[RTCPeerConnection] = None
        self.channel: Optional[RTCDataChannel] = None
        self.signaling = None
        self.websocket = None
        self.connection_id = self._generate_id()
        self._data_callback: Optional[Callable] = None
        self._close_callback: Optional[Callable] = None
        
    def _generate_id(self) -> str:
        """Генерация уникального ID соединения"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
    async def connect(self, peer_id: Optional[str] = None) -> bool:
        """
        Установка WebRTC соединения
        Если peer_id указан - подключаемся как клиент, иначе ждем подключения 
        """
        try:
            self.pc = RTCPeerConnection()
            
            # Настройка ICE серверов
            self.pc._config.iceServers = self.config.ice_servers
            
            # Обработчики событий
            @self.pc.on("iceconnectionstatechange")
            async def on_ice_connection_state_change():
                logger.info(f"ICE connection state: {self.pc.iceConnectionState}")
                if self.pc.iceConnectionState == "failed":
                    await self.close()
            
            @self.pc.on("connectionstatechange")
            async def on_connection_state_change():
                logger.info(f"Connection state: {self.pc.connectionState}")
                if self.pc.connectionState == "failed":
                    await self.close()
            
            if peer_id:
                # Режим клиента (offerer) 
                return await self._connect_as_offerer(peer_id)
            else:
                # Режим сервера (answerer) 
                return await self._connect_as_answerer()
                
        except Exception as e:
            logger.error(f"WebRTC connection failed: {e}")
            return False
    
    async def _connect_as_offerer(self, peer_id: str) -> bool:
        """Подключение как инициатор"""
        logger.info(f"Connecting as offerer to peer {peer_id}")
        
        # Создаем data channel
        self.channel = self.pc.createDataChannel(
            self.config.data_channel_label,
            ordered=self.config.ordered,
            maxRetransmits=self.config.max_retransmits
        )
        self._setup_data_channel()
        
        # Создаем offer
        offer = await self.pc.createOffer()
        await self.pc.setLocalDescription(offer)
        
        # Отправляем offer через signaling
        await self._send_signaling({
            'type': 'offer',
            'sdp': self.pc.localDescription.sdp,
            'connection_id': self.connection_id,
            'peer_id': peer_id
        })
        
        # Ждем answer
        answer = await self._receive_signaling()
        if answer and answer['type'] == 'answer':
            await self.pc.setRemoteDescription(
                RTCSessionDescription(sdp=answer['sdp'], type='answer')
            )
            logger.info("WebRTC connection established as offerer")
            return True
        
        return False
    
    async def _connect_as_answerer(self) -> bool:
        """Ожидание подключения как отвечающая сторона"""
        logger.info("Waiting for connection as answerer")
        
        # Ждем offer
        offer_msg = await self._receive_signaling()
        if not offer_msg or offer_msg['type'] != 'offer':
            logger.error("No valid offer received")
            return False
        
        # Устанавливаем remote description
        await self.pc.setRemoteDescription(
            RTCSessionDescription(sdp=offer_msg['sdp'], type='offer')
        )
        
        # Создаем data channel для ответа
        self.channel = self.pc.createDataChannel(
            self.config.data_channel_label,
            ordered=self.config.ordered
        )
        self._setup_data_channel()
        
        # Создаем answer
        answer = await self.pc.createAnswer()
        await self.pc.setLocalDescription(answer)
        
        # Отправляем answer
        await self._send_signaling({
            'type': 'answer',
            'sdp': self.pc.localDescription.sdp,
            'connection_id': offer_msg['connection_id']
        })
        
        logger.info("WebRTC connection established as answerer")
        return True
    
    def _setup_data_channel(self):
        """Настройка data channel"""
        if not self.channel:
            return
            
        @self.channel.on("open")
        def on_open():
            logger.info("Data channel opened")
            self.connected = True
            if self._connect_callback:
                asyncio.create_task(self._connect_callback())
        
        @self.channel.on("close")
        def on_close():
            logger.info("Data channel closed")
            self.connected = False
            if self._close_callback:
                asyncio.create_task(self._close_callback())
        
        @self.channel.on("message")
        def on_message(message):
            if isinstance(message, str):
                # JSON сообщение
                try:
                    data = json.loads(message)
                    if self._data_callback:
                        asyncio.create_task(self._data_callback(data))
                except:
                    pass
            else:
                # Бинарные данные
                if self._data_callback:
                    asyncio.create_task(self._data_callback(message))
    
    async def listen(self) -> bool:
        """
        Режим сервера - ожидание входящих подключений.
        Для WebRTC это означает запуск signaling сервера.
        """
        logger.info("WebRTC server listening mode activated")
    
        try:
            # В режиме сервера мы просто ждем подключений
            # WebRTC использует signaling для установки соединения
            # Поэтому здесь мы только запускаем signaling сервер
            self.connected = True  # Сервер всегда "подключен" в режиме ожидания
        
            if self._connect_callback:
                await self._connect_callback()
            
            logger.info("WebRTC server ready to accept connections")
            return True
        
        except Exception as e:
            logger.error(f"WebRTC server listen failed: {e}")
            return False
    
    async def _send_signaling(self, data: dict):
        """
        Отправка signaling сообщения через WebSocket 
        """
        try:
            if not self.websocket:
                self.websocket = await websockets.connect(self.config.signaling_server)
            
            await self.websocket.send(json.dumps(data))
            logger.debug(f"Sent signaling: {data['type']}")
            
        except Exception as e:
            logger.error(f"Signaling send failed: {e}")
    
    async def _receive_signaling(self, timeout: float = 30.0) -> Optional[dict]:
        """
        Получение signaling сообщения
        """
        try:
            if not self.websocket:
                self.websocket = await websockets.connect(self.config.signaling_server)
            
            # Ждем сообщение с таймаутом
            message = await asyncio.wait_for(
                self.websocket.recv(),
                timeout=timeout
            )
            
            data = json.loads(message)
            logger.debug(f"Received signaling: {data.get('type')}")
            return data
            
        except asyncio.TimeoutError:
            logger.error(f"Signaling receive timeout after {timeout}s")
            return None
        except Exception as e:
            logger.error(f"Signaling receive failed: {e}")
            return None
    
    async def send(self, data: bytes) -> bool:
        """
        Отправка данных через WebRTC data channel
        """
        if not self.connected or not self.channel or self.channel.readyState != "open":
            logger.warning("Cannot send: channel not ready")
            return False
        
        try:
            # Фрагментируем большие сообщения 
            if len(data) > self.config.max_message_size:
                for i in range(0, len(data), self.config.max_message_size):
                    chunk = data[i:i + self.config.max_message_size]
                    self.channel.send(chunk)
                    self.bytes_sent += len(chunk)
                    self.packets_sent += 1
            else:
                self.channel.send(data)
                self.bytes_sent += len(data)
                self.packets_sent += 1
            
            return True
            
        except Exception as e:
            logger.error(f"Send failed: {e}")
            return False
    
    async def receive(self) -> Optional[bytes]:
        """
        Получение данных (используется callback вместо этого метода)
        """
        # В WebRTC используем callback, поэтому этот метод не используется
        return None
    
    def on_data(self, callback: Callable):
        """Установка callback для получения данных"""
        self._data_callback = callback
    
    def on_connect(self, callback: Callable):
        """Установка callback при подключении"""
        self._connect_callback = callback
    
    def on_close(self, callback: Callable):
        """Установка callback при закрытии"""
        self._close_callback = callback
    
    async def close(self):
        """Закрытие соединения"""
        logger.info("Closing WebRTC transport")
        
        if self.channel:
            self.channel.close()
        
        if self.pc:
            await self.pc.close()
        
        if self.websocket:
            await self.websocket.close()
        
        self.connected = False
        logger.info("WebRTC transport closed")
    
    def get_stats(self) -> TransportStats:
        """Получение статистики"""
        return TransportStats(
            bytes_sent=self.bytes_sent,
            bytes_received=self.bytes_received,
            packets_sent=self.packets_sent,
            packets_received=self.packets_received,
            connected=self.connected,
            rtt_ms=0  # WebRTC не дает прямого RTT
        )
