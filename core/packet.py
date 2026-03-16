#!/usr/bin/env python3
"""
Модуль для работы с сетевыми пакетами.
Обеспечивает парсинг, модификацию и инкапсуляцию пакетов для протокола Анемон.
"""

import struct
import socket
import logging
import random
import time
from typing import Optional, Tuple, Dict, Any, List
from enum import IntEnum
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class IPProtocol(IntEnum):
    """Протоколы IP (из IANA)"""
    ICMP = 1
    TCP = 6
    UDP = 17
    GRE = 47
    ESP = 50
    AH = 51
    ICMPV6 = 58
    OSPF = 89
    SCTP = 132


class IPVersion(IntEnum):
    """Версии IP"""
    IPV4 = 4
    IPV6 = 6


@dataclass
class PacketInfo:
    """Информация о пакете после парсинга"""
    # Общая информация
    raw_data: bytes
    timestamp: float = field(default_factory=time.time)
    length: int = 0
    
    # IP заголовок
    ip_version: Optional[int] = None
    ip_header_length: Optional[int] = None
    ip_total_length: Optional[int] = None
    ip_ttl: Optional[int] = None
    ip_protocol: Optional[int] = None
    ip_checksum: Optional[int] = None
    ip_src: Optional[str] = None
    ip_dst: Optional[str] = None
    
    # TCP заголовок (если есть)
    tcp_src_port: Optional[int] = None
    tcp_dst_port: Optional[int] = None
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_flags: Optional[Dict[str, bool]] = None
    tcp_window: Optional[int] = None
    tcp_checksum: Optional[int] = None
    tcp_urgent_ptr: Optional[int] = None
    tcp_options: Optional[bytes] = None
    
    # UDP заголовок (если есть)
    udp_src_port: Optional[int] = None
    udp_dst_port: Optional[int] = None
    udp_length: Optional[int] = None
    udp_checksum: Optional[int] = None
    
    # Данные
    payload: bytes = b''
    
    # Дополнительные метрики для ML
    packet_size: int = 0
    inter_arrival_time: float = 0.0
    
    @property
    def is_tcp(self) -> bool:
        return self.ip_protocol == IPProtocol.TCP
    
    @property
    def is_udp(self) -> bool:
        return self.ip_protocol == IPProtocol.UDP
    
    @property
    def is_icmp(self) -> bool:
        return self.ip_protocol == IPProtocol.ICMP
    
    @property
    def is_syn(self) -> bool:
        return self.tcp_flags and self.tcp_flags.get('syn', False)
    
    @property
    def is_ack(self) -> bool:
        return self.tcp_flags and self.tcp_flags.get('ack', False)
    
    @property
    def is_fin(self) -> bool:
        return self.tcp_flags and self.tcp_flags.get('fin', False)
    
    @property
    def is_rst(self) -> bool:
        return self.tcp_flags and self.tcp_flags.get('rst', False)
    
    @property
    def is_psh(self) -> bool:
        return self.tcp_flags and self.tcp_flags.get('psh', False)
    
    @property
    def is_urg(self) -> bool:
        return self.tcp_flags and self.tcp_flags.get('urg', False)


class PacketParser:
    """
    Парсер сетевых пакетов.
    Извлекает заголовки IP, TCP, UDP и мета-информацию.
    """
    
    @staticmethod
    def parse_ipv4(packet: bytes) -> Optional[PacketInfo]:
        """
        Парсинг IPv4 пакета.
        Формат заголовка IPv4:
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |Version|  IHL  |Type of Service|          Total Length         |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |         Identification        |Flags|      Fragment Offset    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Time to Live |    Protocol   |         Header Checksum       |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       Source Address                          |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Destination Address                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Options                    |    Padding    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        if len(packet) < 20:
            logger.debug("Packet too short for IPv4 header")
            return None
        
        info = PacketInfo(raw_data=packet)
        
        # Version (4 bits) and IHL (4 bits)
        version_ihl = packet[0]
        info.ip_version = version_ihl >> 4
        info.ip_header_length = (version_ihl & 0x0F) * 4
        
        if info.ip_version != 4:
            return None
        
        # Total Length (16 bits)
        info.ip_total_length = struct.unpack('!H', packet[2:4])[0]
        
        # TTL (8 bits)
        info.ip_ttl = packet[8]
        
        # Protocol (8 bits)
        info.ip_protocol = packet[9]
        
        # Header Checksum (16 bits)
        info.ip_checksum = struct.unpack('!H', packet[10:12])[0]
        
        # Source and Destination IPs
        info.ip_src = socket.inet_ntoa(packet[12:16])
        info.ip_dst = socket.inet_ntoa(packet[16:20])
        
        # Общая длина пакета
        info.length = len(packet)
        info.packet_size = len(packet)
        
        # Payload начинается после IP заголовка
        payload_start = info.ip_header_length
        info.payload = packet[payload_start:info.ip_total_length]
        
        # Парсим следующий уровень в зависимости от протокола
        if info.ip_protocol == IPProtocol.TCP and len(info.payload) >= 20:
            PacketParser._parse_tcp(info, info.payload)
        elif info.ip_protocol == IPProtocol.UDP and len(info.payload) >= 8:
            PacketParser._parse_udp(info, info.payload)
        
        return info
    
    @staticmethod
    def _parse_tcp(info: PacketInfo, data: bytes):
        """
        Парсинг TCP заголовка.
        Формат TCP заголовка:
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |          Source Port          |       Destination Port        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                        Sequence Number                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Acknowledgment Number                      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Data |       |C|E|U|A|P|R|S|F|                               |
        | Offset| Res.  |W|C|R|C|S|S|Y|I|            Window             |
        |       |       |R|E|G|K|H|T|N|N|                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |           Checksum            |         Urgent Pointer        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Options                    |    Padding    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        if len(data) < 20:
            return
        
        # Source and Destination Ports
        info.tcp_src_port = struct.unpack('!H', data[0:2])[0]
        info.tcp_dst_port = struct.unpack('!H', data[2:4])[0]
        
        # Sequence Number
        info.tcp_seq = struct.unpack('!I', data[4:8])[0]
        
        # Acknowledgment Number
        info.tcp_ack = struct.unpack('!I', data[8:12])[0]
        
        # Data Offset (4 bits) and Flags (12 bits)
        data_offset_flags = struct.unpack('!H', data[12:14])[0]
        info.tcp_header_length = (data_offset_flags >> 12) * 4
        
        # Parse flags
        flags = data_offset_flags & 0x1FF  # Lower 9 bits
        info.tcp_flags = {
            'fin': bool(flags & 0x001),
            'syn': bool(flags & 0x002),
            'rst': bool(flags & 0x004),
            'psh': bool(flags & 0x008),
            'ack': bool(flags & 0x010),
            'urg': bool(flags & 0x020),
            'ece': bool(flags & 0x040),
            'cwr': bool(flags & 0x080),
            'ns': bool(flags & 0x100)
        }
        
        # Window
        info.tcp_window = struct.unpack('!H', data[14:16])[0]
        
        # Checksum
        info.tcp_checksum = struct.unpack('!H', data[16:18])[0]
        
        # Urgent Pointer
        info.tcp_urgent_ptr = struct.unpack('!H', data[18:20])[0]
        
        # Options (if any)
        if info.tcp_header_length > 20:
            options_len = info.tcp_header_length - 20
            info.tcp_options = data[20:20 + options_len]
    
    @staticmethod
    def _parse_udp(info: PacketInfo, data: bytes):
        """
        Парсинг UDP заголовка.
        Формат UDP заголовка:
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |          Source Port          |       Destination Port        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |            Length             |           Checksum            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        if len(data) < 8:
            return
        
        info.udp_src_port = struct.unpack('!H', data[0:2])[0]
        info.udp_dst_port = struct.unpack('!H', data[2:4])[0]
        info.udp_length = struct.unpack('!H', data[4:6])[0]
        info.udp_checksum = struct.unpack('!H', data[6:8])[0]
    
    @staticmethod
    def parse(packet: bytes) -> Optional[PacketInfo]:
        """
        Универсальный метод парсинга пакета.
        Автоматически определяет версию IP.
        """
        if len(packet) < 1:
            return None
        
        # Проверяем версию IP по первому полубайту
        version = packet[0] >> 4
        
        if version == 4:
            return PacketParser.parse_ipv4(packet)
        elif version == 6:
            # TODO: Добавить поддержку IPv6
            logger.debug("IPv6 parsing not yet implemented")
            return None
        else:
            logger.debug(f"Unknown IP version: {version}")
            return None


class PacketBuilder:
    """
    Сборщик и модификатор пакетов.
    Позволяет изменять поля пакетов и создавать новые.
    """
    
    @staticmethod
    def modify_ttl(packet: bytes, new_ttl: int) -> Optional[bytes]:
        """
        Изменение TTL в IPv4 пакете и пересчет контрольной суммы.
        Важно для TTL-маскировки.
        """
        info = PacketParser.parse(packet)
        if not info or info.ip_version != 4:
            return None
        
        # TTL находится в 9-м байте (индекс 8)
        packet_bytes = bytearray(packet)
        
        # Запоминаем старый TTL для пересчета контрольной суммы
        old_ttl = packet_bytes[8]
        
        # Устанавливаем новый TTL
        packet_bytes[8] = new_ttl & 0xFF
        
        # Пересчитываем контрольную сумму IP заголовка
        # Обнуляем старую контрольную сумму
        packet_bytes[10:12] = b'\x00\x00'
        
        # Вычисляем новую контрольную сумму
        ip_header = packet_bytes[:info.ip_header_length]
        new_checksum = PacketBuilder._calculate_checksum(ip_header)
        packet_bytes[10:12] = struct.pack('!H', new_checksum)
        
        # Если это TCP, нужно пересчитать TCP контрольную сумму
        if info.is_tcp and info.tcp_checksum is not None:
            PacketBuilder._update_tcp_checksum(packet_bytes, info)
        
        return bytes(packet_bytes)
    
    @staticmethod
    def _update_tcp_checksum(packet: bytearray, info: PacketInfo):
        """
        Пересчет TCP контрольной суммы после изменения IP заголовка.
        """
        # Обнуляем TCP контрольную сумму
        tcp_start = info.ip_header_length
        packet[tcp_start + 16:tcp_start + 18] = b'\x00\x00'
        
        # Создаем псевдозаголовок для расчета TCP контрольной суммы
        pseudo_header = PacketBuilder._create_tcp_pseudo_header(
            info.ip_src, info.ip_dst, info.ip_protocol,
            len(info.payload)
        )
        
        # Вычисляем новую контрольную сумму
        tcp_segment = packet[tcp_start:tcp_start + len(info.payload)]
        new_checksum = PacketBuilder._calculate_checksum(
            pseudo_header + tcp_segment
        )
        
        packet[tcp_start + 16:tcp_start + 18] = struct.pack('!H', new_checksum)
    
    @staticmethod
    def _create_tcp_pseudo_header(src_ip: str, dst_ip: str, 
                                  protocol: int, tcp_length: int) -> bytes:
        """
        Создание псевдозаголовка для TCP контрольной суммы.
        """
        src = socket.inet_aton(src_ip)
        dst = socket.inet_aton(dst_ip)
        
        return struct.pack(
            '!4s4sBBH',
            src, dst,
            0, protocol, tcp_length
        )
    
    @staticmethod
    def _calculate_checksum(data: bytes) -> int:
        """
        Расчет Internet checksum (RFC 1071).
        """
        checksum = 0
        words = len(data) // 2
        
        for i in range(words):
            word = struct.unpack('!H', data[i*2:i*2 + 2])[0]
            checksum += word
        
        if len(data) % 2:
            checksum += data[-1] << 8
        
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        return ~checksum & 0xFFFF
    
    @staticmethod
    def create_fake_packet(profile: str = "web") -> bytes:
        """
        Создание фейкового пакета для маскировки.
        Используется для заполнения туннеля при отсутствии данных.
        """
        # Выбираем случайные порты в зависимости от профиля
        if profile == "web":
            dst_port = 80
            src_port = random.randint(1024, 65535)
        elif profile == "https":
            dst_port = 443
            src_port = random.randint(1024, 65535)
        elif profile == "dns":
            dst_port = 53
            src_port = random.randint(1024, 65535)
        elif profile == "ssh":
            dst_port = 22
            src_port = random.randint(1024, 65535)
        else:
            dst_port = random.choice([80, 443, 53, 22])
            src_port = random.randint(1024, 65535)
        
        # Создаем минимальный TCP SYN пакет
        ip_header = struct.pack(
            '!BBHHHBBH4s4s',
            0x45,  # Version 4, IHL 5
            0,     # Type of Service
            40,    # Total Length (20 IP + 20 TCP)
            random.randint(0, 65535),  # Identification
            0x4000,  # Flags: Don't Fragment
            64,     # TTL
            IPProtocol.TCP,  # Protocol
            0,      # Checksum (будет вычислен позже)
            socket.inet_aton('10.0.0.1'),  # Source IP
            socket.inet_aton('10.0.0.2')   # Destination IP
        )
        
        tcp_header = struct.pack(
            '!HHIIBBHHH',
            src_port,
            dst_port,
            random.randint(0, 2**32-1),  # Sequence number
            0,                            # Acknowledgment number
            0x50,                         # Data offset 5, flags SYN
            0x02,                          # SYN flag
            8192,                          # Window size
            0,                             # Checksum
            0                              # Urgent pointer
        )
        
        # Собираем пакет
        packet = ip_header + tcp_header
        
        # Вычисляем IP checksum
        ip_header_bytes = bytearray(ip_header)
        ip_header_bytes[10:12] = b'\x00\x00'
        ip_checksum = PacketBuilder._calculate_checksum(bytes(ip_header_bytes))
        
        # Вставляем checksum в заголовок
        packet = packet[:10] + struct.pack('!H', ip_checksum) + packet[12:]
        
        return packet


class PacketQueue:
    """
    Очередь пакетов с метками времени для анализа.
    Используется ML-детектором для сбора статистики.
    """
    
    def __init__(self, max_size: int = 1000):
        self.packets: List[Tuple[float, PacketInfo]] = []
        self.max_size = max_size
        self.last_arrival = time.time()
    
    def add_packet(self, packet_info: PacketInfo):
        """Добавление пакета в очередь с временной меткой"""
        now = time.time()
        
        # Вычисляем интервал между прибытиями
        packet_info.inter_arrival_time = now - self.last_arrival
        self.last_arrival = now
        
        self.packets.append((now, packet_info))
        
        # Ограничиваем размер очереди
        if len(self.packets) > self.max_size:
            self.packets.pop(0)
    
    def get_statistics(self, window_seconds: float = 5.0) -> Dict[str, Any]:
        """
        Получение статистики по пакетам за последние N секунд.
        Используется для ML-детектора.
        """
        now = time.time()
        recent = [(t, p) for t, p in self.packets 
                  if now - t <= window_seconds]
        
        if not recent:
            return {}
        
        packet_sizes = [p.packet_size for _, p in recent]
        inter_arrivals = [p.inter_arrival_time for _, p in recent 
                         if p.inter_arrival_time > 0]
        
        # Считаем протоколы
        protocols = {}
        for _, p in recent:
            proto = 'unknown'
            if p.is_tcp:
                proto = 'tcp'
            elif p.is_udp:
                proto = 'udp'
            elif p.is_icmp:
                proto = 'icmp'
            protocols[proto] = protocols.get(proto, 0) + 1
        
        # TCP флаги
        tcp_flags = {}
        for _, p in recent:
            if p.is_tcp and p.tcp_flags:
                for flag, value in p.tcp_flags.items():
                    if value:
                        tcp_flags[flag] = tcp_flags.get(flag, 0) + 1
        
        return {
            'packet_count': len(recent),
            'bytes_total': sum(packet_sizes),
            'packet_size': {
                'mean': sum(packet_sizes) / len(packet_sizes),
                'min': min(packet_sizes),
                'max': max(packet_sizes),
                'std': (sum((x - (sum(packet_sizes) / len(packet_sizes)))**2 
                           for x in packet_sizes) / len(packet_sizes))**0.5
            },
            'inter_arrival': {
                'mean': sum(inter_arrivals) / len(inter_arrivals) if inter_arrivals else 0,
                'min': min(inter_arrivals) if inter_arrivals else 0,
                'max': max(inter_arrivals) if inter_arrivals else 0
            },
            'protocols': protocols,
            'tcp_flags': tcp_flags,
            'rate_packets_per_sec': len(recent) / window_seconds,
            'rate_bytes_per_sec': sum(packet_sizes) / window_seconds
        }
    
    def clear(self):
        """Очистка очереди"""
        self.packets.clear()
        self.last_arrival = time.time()


class PacketModifier:
    """
    Класс для модификации пакетов в соответствии со стратегией.
    Интегрируется с AdaptiveEngine.
    """
    
    def __init__(self, strategy_manager=None):
        self.strategy_manager = strategy_manager
        self.stats = {
            'packets_modified': 0,
            'ttl_changes': 0,
            'fragments_created': 0
        }
    
    def apply_strategy(self, packet: bytes) -> Optional[bytes]:
        """
        Применение текущей стратегии к пакету.
        Может изменять TTL, добавлять фрагментацию и т.д.
        """
        if not self.strategy_manager or not self.strategy_manager.current_strategy:
            return packet
        
        config = self.strategy_manager.get_current_config()
        modified_packet = packet
        
        # Применяем TTL-маскировку если нужно
        ttl_level = config.get('ttl_mask_level', 0)
        if ttl_level > 0 and random.random() < ttl_level:
            # Уменьшаем TTL для некоторых пакетов
            info = PacketParser.parse(packet)
            if info and info.ip_ttl and info.ip_ttl > 10:
                new_ttl = max(1, info.ip_ttl - random.randint(5, 15))
                new_packet = PacketBuilder.modify_ttl(packet, new_ttl)
                if new_packet:
                    modified_packet = new_packet
                    self.stats['ttl_changes'] += 1
                    self.stats['packets_modified'] += 1
        
        return modified_packet


# Для совместимости с существующим кодом
def create_fragmenter():
    """Фабричный метод для создания фрагментатора"""
    from ..mimic.fragmenter import PacketFragmenter
    return PacketFragmenter()
