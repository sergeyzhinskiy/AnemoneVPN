#!/usr/bin/env python3
"""
Модуль для работы с TUN/TAP интерфейсами.
Основан на реализации из [citation:5][citation:9]
"""

import os
import fcntl
import struct
import socket
import logging
from typing import Optional

# Константы Linux для TUN/TAP
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca

logger = logging.getLogger(__name__)

class TUNInterface:
    """
    Кросс-платформенный класс для работы с TUN интерфейсом
    Поддерживает Linux, планируется поддержка Windows/macOS [citation:9]
    """
    
    def __init__(self, name: str = "anemone%d", mtu: int = 1300):
        self.name = name
        self.mtu = mtu
        self.fd = None
        self.ip_address = None
        self.is_running = False
        
    def create(self) -> bool:
        """
        Создание TUN интерфейса
        Возвращает True при успехе
        """
        try:
            # Открытие устройства TUN
            self.fd = os.open("/dev/net/tun", os.O_RDWR)
            if self.fd < 0:
                logger.error("Cannot open /dev/net/tun")
                return False
                
            # Настройка интерфейса
            ifs = fcntl.ioctl(
                self.fd,
                TUNSETIFF,
                struct.pack("16sH", self.name.encode('utf-8'), IFF_TUN | IFF_NO_PI)
            )
            
            # Получаем имя созданного интерфейса
            self.name = ifs[:16].decode('utf-8').strip('\x00')
            logger.info(f"Created TUN interface: {self.name}")
            
            # Настройка MTU
            self._set_mtu()
            
            self.is_running = True
            return True
            
        except Exception as e:
            logger.error(f"Failed to create TUN interface: {e}")
            return False
    
    def _set_mtu(self):
        """Установка MTU для интерфейса"""
        try:
            # Используем системную команду для установки MTU
            os.system(f"ip link set dev {self.name} mtu {self.mtu}")
            logger.debug(f"Set MTU to {self.mtu} on {self.name}")
        except Exception as e:
            logger.warning(f"Failed to set MTU: {e}")
    
    def configure_ip(self, ip_address: str, netmask: str = "255.255.255.0"):
        """
        Назначение IP адреса интерфейсу
        """
        try:
            # Поднимаем интерфейс и назначаем IP
            os.system(f"ip addr add {ip_address}/{self._netmask_to_cidr(netmask)} dev {self.name}")
            os.system(f"ip link set dev {self.name} up")
            self.ip_address = ip_address
            logger.info(f"Configured {self.name} with IP {ip_address}")
        except Exception as e:
            logger.error(f"Failed to configure IP: {e}")
    
    def _netmask_to_cidr(self, netmask: str) -> int:
        """Преобразование маски в CIDR нотацию"""
        return sum(bin(int(x)).count('1') for x in netmask.split('.'))
    
    def read_packet(self) -> Optional[bytes]:
        """
        Чтение пакета из TUN интерфейса
        Возвращает сырые байты пакета
        """
        if not self.is_running:
            return None
            
        try:
            packet = os.read(self.fd, 2048)  # Читаем до 2048 байт
            return packet
        except Exception as e:
            logger.error(f"Error reading packet: {e}")
            return None
    
    def write_packet(self, packet: bytes) -> bool:
        """
        Запись пакета в TUN интерфейс
        """
        if not self.is_running:
            return False
            
        try:
            os.write(self.fd, packet)
            return True
        except Exception as e:
            logger.error(f"Error writing packet: {e}")
            return False
    
    def close(self):
        """Закрытие интерфейса"""
        if self.fd:
            os.close(self.fd)
            self.is_running = False
            logger.info(f"Closed TUN interface {self.name}")


class TAPInterface(TUNInterface):
    """
    TAP интерфейс (Ethernet level) - для расширенной совместимости
    """
    
    def create(self) -> bool:
        try:
            self.fd = os.open("/dev/net/tun", os.O_RDWR)
            ifs = fcntl.ioctl(
                self.fd,
                TUNSETIFF,
                struct.pack("16sH", self.name.encode('utf-8'), IFF_TAP | IFF_NO_PI)
            )
            self.name = ifs[:16].decode('utf-8').strip('\x00')
            self._set_mtu()
            self.is_running = True
            logger.info(f"Created TAP interface: {self.name}")
            return True
        except Exception as e:
            logger.error(f"Failed to create TAP interface: {e}")
            return False