#!/usr/bin/env python3
"""
Модуль фрагментации пакетов для обхода DPI
Реализует методы из DPYProxy [citation:10] с улучшениями
"""

import random
import struct
import time
import logging
from typing import List, Tuple, Optional
from dataclasses import dataclass
import numpy as np

logger = logging.getLogger(__name__)

@dataclass
class Fragment:
    """Фрагмент пакета"""
    id: int
    sequence: int
    total: int
    data: bytes
    ttl: int
    timestamp: float


class PacketFragmenter:
    """
    Фрагментация пакетов с переменным размером и TTL-маскировкой
    На основе исследований USENIX NSDI 2026 [citation:10]
    """
    
    def __init__(self, profile_name: str = "web"):
        self.profile_name = profile_name
        self.fragment_id = random.randint(1, 1000000)
        self.fragment_buffer = {}
        
        # Статистические модели размеров фрагментов для разных профилей
        self.profiles = {
            "youtube": {
                "min": 100,
                "max": 1400,
                "mean": 1200,
                "std": 200,
                "distribution": "normal",
                "ttl_range": (32, 64)
            },
            "zoom": {
                "min": 50,
                "max": 1200,
                "mean": 800,
                "std": 300,
                "distribution": "normal",
                "ttl_range": (16, 32)
            },
            "web": {
                "min": 40,
                "max": 1500,
                "mean": 600,
                "std": 400,
                "distribution": "pareto",
                "ttl_range": (48, 128)
            },
            "telegram": {
                "min": 20,
                "max": 500,
                "mean": 200,
                "std": 100,
                "distribution": "exponential",
                "ttl_range": (128, 255)
            }
        }
        
        self.current_profile = self.profiles.get(profile_name, self.profiles["web"])
        
    def set_profile(self, profile_name: str):
        """Смена профиля фрагментации"""
        if profile_name in self.profiles:
            self.current_profile = self.profiles[profile_name]
            logger.info(f"Switched fragmentation profile to {profile_name}")
    
    def _generate_fragment_size(self) -> int:
        """
        Генерация размера фрагмента согласно статистической модели
        """
        prof = self.current_profile
        size = prof["mean"]
        
        if prof["distribution"] == "normal":
            # Нормальное распределение (как у видео)
            size = int(np.random.normal(prof["mean"], prof["std"]))
        elif prof["distribution"] == "pareto":
            # Распределение Парето (веб-трафик)
            size = int(np.random.pareto(1.5) * 300 + 40)
        elif prof["distribution"] == "exponential":
            # Экспоненциальное распределение (мессенджеры)
            size = int(np.random.exponential(100) + 20)
        
        # Ограничиваем размеры
        size = max(prof["min"], min(prof["max"], size))
        return size
    
    def _generate_ttl(self) -> int:
        """Генерация TTL для маскировки [citation:10]"""
        ttl_range = self.current_profile["ttl_range"]
        return random.randint(ttl_range[0], ttl_range[1])
    
    def fragment_packet(self, packet: bytes) -> List[Fragment]:
        """
        Фрагментация пакета с переменным размером фрагментов
        """
        fragments = []
        remaining = packet
        offset = 0
        total_fragments = 0
        
        # Предварительный подсчет количества фрагментов
        temp_remaining = packet
        while temp_remaining:
            frag_size = self._generate_fragment_size()
            if len(temp_remaining) <= frag_size:
                frag_size = len(temp_remaining)
            temp_remaining = temp_remaining[frag_size:]
            total_fragments += 1
        
        # Реальная фрагментация
        fragment_id = self.fragment_id
        self.fragment_id += 1
        
        sequence = 0
        while remaining:
            # Размер этого фрагмента
            if total_fragments - sequence == 1:
                # Последний фрагмент - остаток
                frag_size = len(remaining)
            else:
                frag_size = self._generate_fragment_size()
                if frag_size > len(remaining):
                    frag_size = len(remaining)
            
            # Создаем фрагмент
            frag_data = remaining[:frag_size]
            
            # Решаем, будет ли это "умирающий" пакет (примерно 20% фрагментов)
            if random.random() < 0.2:  # 20% шанс
                ttl = 1  # Умрет в сети
                logger.debug(f"Creating dying fragment with TTL=1")
            else:
                ttl = self._generate_ttl()
            
            fragment = Fragment(
                id=fragment_id,
                sequence=sequence,
                total=total_fragments,
                data=frag_data,
                ttl=ttl,
                timestamp=time.time()
            )
            
            fragments.append(fragment)
            remaining = remaining[frag_size:]
            sequence += 1
            
            # Добавляем случайную паузу между фрагментами для большей реалистичности
            if random.random() < 0.3:  # 30% шанс микро-паузы
                time.sleep(random.uniform(0.001, 0.005))  # 1-5ms
        
        logger.debug(f"Fragmented packet into {len(fragments)} fragments")
        return fragments
    
    def reassemble_fragments(self, fragments: List[Fragment]) -> Optional[bytes]:
        """
        Сборка пакета из фрагментов
        Учитывает только фрагменты с TTL > 0 (которые дошли)
        """
        if not fragments:
            return None
            
        # Группируем по ID фрагментации
        fragments_by_id = {}
        for frag in fragments:
            if frag.ttl <= 0:  # Пропускаем "умершие" пакеты
                continue
            if frag.id not in fragments_by_id:
                fragments_by_id[frag.id] = []
            fragments_by_id[frag.id].append(frag)
        
        # Для каждого ID пробуем собрать
        for frag_id, frag_list in fragments_by_id.items():
            # Сортируем по sequence
            frag_list.sort(key=lambda x: x.sequence)
            
            # Проверяем, все ли фрагменты на месте
            expected_total = frag_list[0].total if frag_list else 0
            if len(frag_list) != expected_total:
                # Не все фрагменты дошли, возможно, нужно запросить повторно
                logger.warning(f"Missing fragments for packet {frag_id}: have {len(frag_list)}, need {expected_total}")
                continue
            
            # Собираем данные
            reassembled = b''.join(f.data for f in frag_list)
            logger.debug(f"Reassembled packet {frag_id} ({len(reassembled)} bytes)")
            return reassembled
        
        return None
    
    def tls_record_fragmentation(self, tls_record: bytes, fragment_size: int = 20) -> List[bytes]:
        """
        Специализированная фрагментация TLS записей [citation:10]
        """
        fragments = []
        for i in range(0, len(tls_record), fragment_size):
            fragment = tls_record[i:i + fragment_size]
            fragments.append(fragment)
        return fragments


class TCPPacketFragmenter(PacketFragmenter):
    """
    Фрагментация на уровне TCP сегментов
    """
    
    def create_tcp_segments(self, data: bytes, mss: int = 1460) -> List[bytes]:
        """
        Создание TCP сегментов с переменным размером
        """
        segments = []
        
        # MSS может варьироваться для маскировки
        current_mss = mss
        
        while data:
            # Случайно изменяем MSS в пределах разумного
            if random.random() < 0.3:
                current_mss = random.randint(500, mss)
            
            segment = data[:current_mss]
            segments.append(segment)
            data = data[current_mss:]
            
            # Добавляем случайные TCP опции
            if random.random() < 0.1:
                # Имитация TCP options
                options = self._generate_tcp_options()
                segments[-1] = segments[-1] + options
        
        return segments
    
    def _generate_tcp_options(self) -> bytes:
        """Генерация случайных TCP опций"""
        options = {
            0: b'\x00',  # EOL
            1: b'\x01',  # NOP
            2: struct.pack('!BBH', 2, 4, 1460),  # MSS
            3: struct.pack('!BBB', 3, 3, 10),  # Window scale
            4: struct.pack('!BB', 4, 2),  # SACK permitted
        }
        
        # Выбираем случайную опцию
        opt_type = random.choice(list(options.keys()))
        return options[opt_type]