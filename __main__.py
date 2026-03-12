#!/usr/bin/env python3
"""
Обновленный главный модуль с адаптивным движком
"""

import asyncio
import argparse
import logging
import signal
import sys
from typing import Optional, Dict

from anemone.core.tun import TUNInterface
from anemone.core.crypto import CryptoEngine
from anemone.mimic.fragmenter import PacketFragmenter
from anemone.mimic.filler import ContentFiller, TrafficMixer
from anemone.adaptive.ml_detector import MLDetector
from anemone.adaptive.strategy import AdaptiveEngine, ProfileType
from anemone.transport.webrtc import WebRTCTransport, WebRTCConfig
from anemone.transport.quic import QUICTransport, QUICConfig
from anemone.transport.base import BaseTransport
from anemone.utils.logger import setup_logging
from anemone.utils.config import load_config

logger = logging.getLogger(__name__)


class AnemoneVPN:
    """
    Основной класс VPN клиента/сервера с адаптивностью
    """
    
    def __init__(self, mode: str = "client", config: dict = None):
        self.mode = mode
        self.config = config or {}
        self.running = False
        
        # Инициализация компонентов
        self.tun = TUNInterface(
            name=config.get('tun_name', 'anemone%d'),
            mtu=config.get('mtu', 1300)
        )
        
        self.crypto = CryptoEngine(
            rotation_interval=config.get('key_rotation', 3600)
        )
        
        self.fragmenter = PacketFragmenter(
            profile_name=config.get('profile', 'web')
        )
        
        self.filler = ContentFiller()
        self.mixer = TrafficMixer(
            self.filler,
            mix_ratio=config.get('mix_ratio', 0.3)
        )
        
        # ML и адаптивность
        self.ml_detector = MLDetector() if config.get('adaptive', True) else None
        self.adaptive_engine = AdaptiveEngine()
        
        # Транспорты
        self.transports: Dict[str, BaseTransport] = {}
        self.active_transport: Optional[BaseTransport] = None
        
        # Состояние
        self.peers = {}
        self.stats = {
            'bytes_sent': 0,
            'bytes_received': 0,
            'packets_sent': 0,
            'packets_received': 0,
            'fragments_created': 0,
            'fragments_lost': 0,
            'adaptations': 0
        }
    
    async def initialize_transports(self):
        """Инициализация всех транспортов"""
        
        # WebRTC транспорт [citation:2]
        if self.config.get('enable_webrtc', True):
            webrtc_config = WebRTCConfig(
                enabled=True,
                server_name=self.config.get('server', 'localhost'),
                port=self.config.get('webrtc_port', 8080),
                signaling_server=self.config.get('signaling_server', 'ws://localhost:8080')
            )
            webrtc = WebRTCTransport(webrtc_config)
            webrtc.on_data(self._on_transport_data)
            webrtc.on_connect(self._on_transport_connect)
            webrtc.on_close(self._on_transport_close)
            self.transports['webrtc'] = webrtc
        
        # QUIC транспорт
        if self.config.get('enable_quic', True):
            quic_config = QUICConfig(
                enabled=True,
                server_name=self.config.get('server', 'localhost'),
                port=self.config.get('quic_port', 4433)
            )
            quic = QUICTransport(quic_config)
            quic.on_data(self._on_transport_data)
            quic.on_connect(self._on_transport_connect)
            quic.on_close(self._on_transport_close)
            self.transports['quic'] = quic
        
        logger.info(f"Initialized {len(self.transports)} transports")
    
    async def _on_transport_data(self, data: bytes):
        """Обработка данных из транспорта"""
        # Расшифровываем
        try:
            # Определяем peer_id из контекста
            peer_id = "server" if self.mode == "client" else "client"
            
            # Разделяем на зашифрованные данные и тег
            if len(data) > 16:  # Минимальная длина
                encrypted = data[:-16]
                tag = data[-16:]
                plaintext = self.crypto.decrypt(encrypted, tag, peer_id)
                
                # Отправляем в TUN
                self.tun.write_packet(plaintext)
                self.stats['bytes_received'] += len(plaintext)
                self.stats['packets_received'] += 1
                
                # Записываем успех
                if self.adaptive_engine:
                    self.adaptive_engine.record_success()
        except Exception as e:
            logger.error(f"Failed to process transport data: {e}")
            if self.adaptive_engine:
                self.adaptive_engine.record_failure()
    
    async def _on_transport_connect(self):
        """Обработка подключения транспорта"""
        logger.info("Transport connected")
        
        # Отправляем приветственное сообщение
        await self.active_transport.send(b"ANEMONE_INIT")
    
    async def _on_transport_close(self):
        """Обработка отключения транспорта"""
        logger.warning("Transport disconnected")
        
        # Пробуем переключиться на другой транспорт
        await self._switch_transport()
    
    async def _switch_transport(self):
        """Переключение на другой транспорт"""
        for name, transport in self.transports.items():
            if transport != self.active_transport and not transport.connected:
                logger.info(f"Switching to {name} transport")
                success = await transport.connect(
                    self.config.get('server') if self.mode == "client" else None
                )
                if success:
                    self.active_transport = transport
                    self.stats['adaptations'] += 1
                    return
        
        logger.error("No alternative transports available")
    
    async def start(self):
        """Запуск VPN"""
        logger.info(f"Starting Anemone VPN in {self.mode} mode")
        
        # Инициализация транспортов
        await self.initialize_transports()
        
        # Создание TUN интерфейса
        if not self.tun.create():
            logger.error("Failed to create TUN interface")
            return False
        
        # Настройка IP
        if self.mode == "server":
            self.tun.configure_ip("10.8.0.1/24")
            
            # Запускаем серверные транспорты
            if 'webrtc' in self.transports:
                # Для WebRTC сервер просто ждет подключений
                pass
            if 'quic' in self.transports:
                await self.transports['quic'].listen()
        else:
            self.tun.configure_ip("10.8.0.2/24")
            
            # Подключаемся к серверу
            for name, transport in self.transports.items():
                logger.info(f"Connecting via {name}...")
                success = await transport.connect(self.config.get('server'))
                if success:
                    self.active_transport = transport
                    logger.info(f"Connected via {name}")
                    break
            
            if not self.active_transport:
                logger.error("Failed to connect via any transport")
                return False
        
        # Инициализация адаптивного движка
        if self.adaptive_engine:
            await self.adaptive_engine.initialize(
                ml_detector=self.ml_detector,
                fragmenter=self.fragmenter,
                filler=self.mixer,
                transports=self.transports
            )
        
        self.running = True
        
        # Запуск основных циклов
        await asyncio.gather(
            self._tun_reader_loop(),
            self._adaptive_loop(),
            self._stats_loop()
        )
        
        return True
    
    async def _tun_reader_loop(self):
        """Чтение пакетов из TUN интерфейса"""
        logger.info("Starting TUN reader loop")
        
        while self.running:
            packet = self.tun.read_packet()
            if packet and self.active_transport and self.active_transport.connected:
                await self._process_outgoing_packet(packet)
            
            await asyncio.sleep(0.01)
    
    async def _adaptive_loop(self):
        """Цикл адаптации к условиям сети"""
        while self.running:
            await asyncio.sleep(5)  # Проверка каждые 5 секунд
            
            if self.adaptive_engine and self.active_transport:
                # Собираем статистику для анализа
                flow_data = {
                    'duration_ms': 5000,
                    'mean_interval': 10,
                    'std_interval': 5,
                    'bytes_sent': self.stats['bytes_sent'],
                    'bytes_received': self.stats['bytes_received'],
                    'packets_sent': self.stats['packets_sent'],
                    'packets_received': self.stats['packets_received'],
                    'retransmissions': 0,
                    'out_of_order': 0
                }
                
                # Адаптируемся
                adaptation = await self.adaptive_engine.update(flow_data)
                
                if adaptation.get('current_strategy') != getattr(self, '_last_strategy', None):
                    logger.info(f"Adaptation: {adaptation}")
                    self._last_strategy = adaptation.get('current_strategy')
    
    async def _stats_loop(self):
        """Периодический вывод статистики"""
        while self.running:
            await asyncio.sleep(60)
            
            transport_stats = {}
            if self.active_transport:
                stats = self.active_transport.get_stats()
                transport_stats = {
                    'transport_bytes_sent': stats.bytes_sent,
                    'transport_bytes_recv': stats.bytes_received,
                    'transport_rtt_ms': stats.rtt_ms
                }
            
            logger.info(f"Stats: {self.stats} {transport_stats}")
    
    async def _process_outgoing_packet(self, packet: bytes):
        """Обработка исходящего пакета с адаптацией"""
        
        # Получаем текущие параметры от адаптивного движка
        adaptive_config = {}
        if self.adaptive_engine and self.adaptive_engine.strategy_manager.current_strategy:
            adaptive_config = self.adaptive_engine.strategy_manager.get_current_config()
        
        # Фрагментация с адаптивными параметрами
        if adaptive_config.get('fragmentation_level', 0.5) > 0.3:
            fragments = self.fragmenter.fragment_packet(packet)
            self.stats['fragments_created'] += len(fragments)
        else:
            # Минимальная фрагментация
            fragments = [self.fragmenter._create_fragment(packet, 0, 1)]
        
        for fragment in fragments:
            # Шифрование
            encrypted, tag = self.crypto.encrypt(
                fragment.data,
                peer_id="server" if self.mode == "client" else "client",
                aad=str(fragment.sequence).encode()
            )
            
            # Подмешивание контента с адаптивным соотношением
            if adaptive_config.get('filler_ratio', 0.3) > 0:
                # Временно устанавливаем соотношение для этого пакета
                original_ratio = self.mixer.mix_ratio
                self.mixer.mix_ratio = adaptive_config.get('filler_ratio', 0.3)
                mixed = await self.mixer.mix_with_tunnel_data(encrypted + tag)
                self.mixer.mix_ratio = original_ratio
            else:
                mixed = encrypted + tag
            
            # Искусственная задержка если нужно
            if adaptive_config.get('packet_delay_ms', 0) > 0:
                await asyncio.sleep(adaptive_config['packet_delay_ms'] / 1000)
            
            # Отправка через активный транспорт
            if self.active_transport and self.active_transport.connected:
                success = await self.active_transport.send(mixed)
                
                if success:
                    self.stats['bytes_sent'] += len(mixed)
                    self.stats['packets_sent'] += 1
                    if self.adaptive_engine:
                        self.adaptive_engine.record_success()
                else:
                    if self.adaptive_engine:
                        self.adaptive_engine.record_failure()
    
    async def stop(self):
        """Остановка VPN"""
        logger.info("Stopping Anemone VPN")
        self.running = False
        
        for transport in self.transports.values():
            await transport.close()
        
        self.tun.close()
        await self.filler.close()
        logger.info("Anemone VPN stopped")


async def main():
    """Главная функция"""
    parser = argparse.ArgumentParser(description="Anemone Adaptive VPN Protocol")
    parser.add_argument("--mode", choices=["client", "server"], default="client")
    parser.add_argument("--server", help="Server address")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--profile", choices=["web", "youtube", "zoom", "telegram", "gaming", "adaptive"], default="adaptive")
    parser.add_argument("--config", help="Config file path")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--transport", choices=["webrtc", "quic", "auto"], default="auto")
    
    args = parser.parse_args()
    
    # Настройка логирования
    setup_logging(level=logging.DEBUG if args.debug else logging.INFO)
    
    # Загрузка конфигурации
    config = {}
    if args.config:
        config = load_config(args.config)
    
    # Обновление из аргументов командной строки
    config.update({
        'mode': args.mode,
        'profile': args.profile,
        'server': args.server,
        'port': args.port,
        'adaptive': args.profile == "adaptive"
    })
    
    # Настройка транспортов
    if args.transport != "auto":
        config['enable_webrtc'] = args.transport == "webrtc"
        config['enable_quic'] = args.transport == "quic"
    
    # Создание и запуск VPN
    vpn = AnemoneVPN(mode=args.mode, config=config)
    
    # Обработка сигналов
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(vpn.stop()))
    
    try:
        await vpn.start()
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    finally:
        await vpn.stop()


if __name__ == "__main__":
    asyncio.run(main())