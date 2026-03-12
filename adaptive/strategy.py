#!/usr/bin/env python3
"""
Модуль адаптивного переключения стратегий обхода DPI
"""

import asyncio
import logging
from enum import Enum
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class StrategyType(Enum):
    """Типы стратегий обхода"""
    STEALTH = "stealth"          # Максимальная скрытность
    BALANCED = "balanced"         # Баланс скорости и скрытности
    PERFORMANCE = "performance"    # Максимальная производительность
    AGGRESSIVE = "aggressive"      # Агрессивный обход


class ProfileType(Enum):
    """Профили маскировки трафика"""
    WEB = "web"                    # Обычный веб-серфинг
    YOUTUBE = "youtube"            # Видео-трафик
    ZOOM = "zoom"                  # Видеоконференция
    TELEGRAM = "telegram"          # Мессенджер
    GAMING = "gaming"              # Игровой трафик


@dataclass
class StrategyConfig:
    """Конфигурация стратегии"""
    name: str
    profile: ProfileType
    fragmentation_level: float  # 0-1, где 1 - максимальная фрагментация
    filler_ratio: float         # 0-1, доля подмешиваемого контента
    ttl_mask_level: float       # 0-1, интенсивность TTL-маскировки
    packet_delay_ms: float      # Искусственная задержка
    timeout_sec: float          # Таймаут соединения
    retry_count: int            # Количество попыток


class StrategyManager:
    """
    Менеджер стратегий - адаптивно переключает режимы работы
    на основе обнаруженных угроз
    """
    
    def __init__(self):
        self.current_strategy: Optional[StrategyConfig] = None
        self.current_profile: ProfileType = ProfileType.WEB
        self.strategy_history: List[Tuple[datetime, StrategyConfig]] = []
        
        # Доступные стратегии
        self.strategies = self._init_strategies()
        
        # Счетчики успехов/неудач
        self.success_count = 0
        self.failure_count = 0
        self.last_switch_time = datetime.now()
        
        # Пороги для переключения
        self.switch_cooldown = timedelta(seconds=30)
        self.failure_threshold = 3
        self.anomaly_threshold = 0.7
        
    def _init_strategies(self) -> Dict[StrategyType, Dict[ProfileType, StrategyConfig]]:
        """Инициализация всех стратегий"""
        strategies = {}
        
        # STEALTH стратегии - максимальная скрытность
        stealth = {}
        stealth[ProfileType.WEB] = StrategyConfig(
            name="Stealth Web",
            profile=ProfileType.WEB,
            fragmentation_level=0.9,
            filler_ratio=0.5,
            ttl_mask_level=0.8,
            packet_delay_ms=50,
            timeout_sec=10.0,
            retry_count=3
        )
        stealth[ProfileType.YOUTUBE] = StrategyConfig(
            name="Stealth YouTube",
            profile=ProfileType.YOUTUBE,
            fragmentation_level=0.8,
            filler_ratio=0.4,
            ttl_mask_level=0.7,
            packet_delay_ms=30,
            timeout_sec=8.0,
            retry_count=3
        )
        strategies[StrategyType.STEALTH] = stealth
        
        # BALANCED стратегии
        balanced = {}
        balanced[ProfileType.WEB] = StrategyConfig(
            name="Balanced Web",
            profile=ProfileType.WEB,
            fragmentation_level=0.6,
            filler_ratio=0.3,
            ttl_mask_level=0.5,
            packet_delay_ms=20,
            timeout_sec=7.0,
            retry_count=2
        )
        balanced[ProfileType.ZOOM] = StrategyConfig(
            name="Balanced Zoom",
            profile=ProfileType.ZOOM,
            fragmentation_level=0.5,
            filler_ratio=0.2,
            ttl_mask_level=0.4,
            packet_delay_ms=10,
            timeout_sec=5.0,
            retry_count=2
        )
        strategies[StrategyType.BALANCED] = balanced
        
        # PERFORMANCE стратегии
        performance = {}
        performance[ProfileType.WEB] = StrategyConfig(
            name="Performance Web",
            profile=ProfileType.WEB,
            fragmentation_level=0.3,
            filler_ratio=0.1,
            ttl_mask_level=0.2,
            packet_delay_ms=5,
            timeout_sec=5.0,
            retry_count=1
        )
        performance[ProfileType.GAMING] = StrategyConfig(
            name="Performance Gaming",
            profile=ProfileType.GAMING,
            fragmentation_level=0.2,
            filler_ratio=0.05,
            ttl_mask_level=0.1,
            packet_delay_ms=2,
            timeout_sec=3.0,
            retry_count=1
        )
        strategies[StrategyType.PERFORMANCE] = performance
        
        return strategies
    
    async def adapt_to_conditions(self, 
                                  anomaly_score: float,
                                  connection_stats: Dict) -> Optional[StrategyConfig]:
        """
        Адаптация стратегии к текущим условиям
        """
        current_time = datetime.now()
        
        # Проверяем, не слишком ли часто переключаемся
        if current_time - self.last_switch_time < self.switch_cooldown:
            return None
        
        new_strategy = None
        
        # 1. Аномалии в трафике - переходим в stealth
        if anomaly_score > self.anomaly_threshold:
            logger.warning(f"High anomaly score ({anomaly_score:.2f}), switching to STEALTH")
            new_strategy = self.strategies[StrategyType.STEALTH][self.current_profile]
        
        # 2. Много неудач - повышаем скрытность
        elif self.failure_count >= self.failure_threshold:
            logger.warning(f"Too many failures ({self.failure_count}), increasing stealth")
            if self.current_strategy and self.current_strategy.name.startswith("Performance"):
                new_strategy = self.strategies[StrategyType.BALANCED][self.current_profile]
            elif self.current_strategy and self.current_strategy.name.startswith("Balanced"):
                new_strategy = self.strategies[StrategyType.STEALTH][self.current_profile]
        
        # 3. Все хорошо - можно попробовать повысить производительность
        elif self.success_count > self.failure_count * 3 and self.failure_count == 0:
            logger.info("All good, trying better performance")
            if self.current_strategy and self.current_strategy.name.startswith("Stealth"):
                new_strategy = self.strategies[StrategyType.BALANCED][self.current_profile]
            elif self.current_strategy and self.current_strategy.name.startswith("Balanced"):
                new_strategy = self.strategies[StrategyType.PERFORMANCE][self.current_profile]
        
        if new_strategy and new_strategy != self.current_strategy:
            await self.switch_strategy(new_strategy)
            return new_strategy
        
        return None
    
    async def switch_strategy(self, new_strategy: StrategyConfig):
        """
        Переключение на новую стратегию
        """
        logger.info(f"Switching strategy: {self.current_strategy.name if self.current_strategy else 'None'} -> {new_strategy.name}")
        
        # Сохраняем историю
        self.strategy_history.append((datetime.now(), new_strategy))
        self.current_strategy = new_strategy
        self.last_switch_time = datetime.now()
        
        # Сбрасываем счетчики
        self.success_count = 0
        self.failure_count = 0
    
    def set_profile(self, profile: ProfileType):
        """
        Смена профиля маскировки
        """
        self.current_profile = profile
        logger.info(f"Profile set to {profile.value}")
    
    def record_success(self):
        """Запись успешной передачи"""
        self.success_count += 1
    
    def record_failure(self):
        """Запись неудачной передачи"""
        self.failure_count += 1
    
    def get_current_config(self) -> Dict:
        """
        Получение текущей конфигурации для других модулей
        """
        if not self.current_strategy:
            return {}
        
        return {
            'profile': self.current_strategy.profile.value,
            'fragmentation_level': self.current_strategy.fragmentation_level,
            'filler_ratio': self.current_strategy.filler_ratio,
            'ttl_mask_level': self.current_strategy.ttl_mask_level,
            'packet_delay_ms': self.current_strategy.packet_delay_ms,
            'timeout_sec': self.current_strategy.timeout_sec,
            'retry_count': self.current_strategy.retry_count
        }


class AdaptiveEngine:
    """
    Адаптивный движок - координация всех модулей
    """
    
    def __init__(self):
        self.strategy_manager = StrategyManager()
        self.ml_detector = None
        self.transports = {}
        self.fragmenter = None
        self.filler = None
        
        # Текущее состояние
        self.current_anomaly = 0.0
        self.connection_quality = 1.0
        self.last_update = datetime.now()
    
    async def initialize(self, 
                        ml_detector,
                        fragmenter,
                        filler,
                        transports: Dict):
        """
        Инициализация с компонентами
        """
        self.ml_detector = ml_detector
        self.fragmenter = fragmenter
        self.filler = filler
        self.transports = transports
        
        # Начинаем с balanced стратегии
        await self.strategy_manager.switch_strategy(
            self.strategy_manager.strategies[StrategyType.BALANCED][ProfileType.WEB]
        )
    
    async def update(self, flow_data: Dict) -> Dict:
        """
        Обновление состояния и адаптация
        """
        current_time = datetime.now()
        
        # Анализируем поток через ML детектор
        if self.ml_detector:
            analysis = await self.ml_detector.analyze_flow(flow_data)
            self.current_anomaly = analysis['anomaly_score']
            
            # Адаптируем стратегию
            new_strategy = await self.strategy_manager.adapt_to_conditions(
                self.current_anomaly,
                flow_data
            )
            
            if new_strategy:
                # Применяем новую стратегию к компонентам
                await self._apply_strategy(new_strategy)
        
        # Оцениваем качество соединения
        self._update_connection_quality(flow_data)
        
        return {
            'anomaly_score': self.current_anomaly,
            'connection_quality': self.connection_quality,
            'current_strategy': self.strategy_manager.current_strategy.name if self.strategy_manager.current_strategy else 'unknown',
            'current_profile': self.strategy_manager.current_profile.value
        }
    
    async def _apply_strategy(self, strategy: StrategyConfig):
        """
        Применение стратегии к компонентам
        """
        # 1. Настройка фрагментатора
        if self.fragmenter:
            self.fragmenter.set_profile(strategy.profile.value)
            # Дополнительные параметры фрагментации
            self.fragmenter.fragmentation_intensity = strategy.fragmentation_level
        
        # 2. Настройка подмешивания контента
        if self.filler and hasattr(self.filler, 'mixer'):
            self.filler.mixer.mix_ratio = strategy.filler_ratio
        
        # 3. Выбор оптимального транспорта
        await self._select_best_transport(strategy)
    
    async def _select_best_transport(self, strategy: StrategyConfig):
        """
        Выбор лучшего транспорта для текущей стратегии
        """
        if not self.transports:
            return
        
        # Для разных профилей - разные приоритеты
        transport_priorities = {
            ProfileType.GAMING: ['quic', 'webrtc', 'websocket'],
            ProfileType.ZOOM: ['webrtc', 'quic', 'websocket'],
            ProfileType.YOUTUBE: ['quic', 'websocket', 'webrtc'],
            ProfileType.WEB: ['websocket', 'quic', 'webrtc'],
            ProfileType.TELEGRAM: ['websocket', 'quic', 'webrtc']
        }
        
        priorities = transport_priorities.get(strategy.profile, ['quic', 'webrtc', 'websocket'])
        
        # Пробуем транспорты в порядке приоритета
        for transport_name in priorities:
            if transport_name in self.transports:
                transport = self.transports[transport_name]
                if transport and transport.connected:
                    logger.info(f"Selected transport {transport_name} for profile {strategy.profile.value}")
                    return transport_name
        
        logger.warning("No suitable transport found")
        return None
    
    def _update_connection_quality(self, flow_data: Dict):
        """
        Оценка качества соединения на основе статистики
        """
        # Простая метрика: соотношение успешных передач к неудачным
        total = self.strategy_manager.success_count + self.strategy_manager.failure_count
        if total > 0:
            self.connection_quality = self.strategy_manager.success_count / total
        else:
            self.connection_quality = 1.0
    
    def record_success(self):
        """Запись успеха"""
        self.strategy_manager.record_success()
    
    def record_failure(self):
        """Запись неудачи"""
        self.strategy_manager.record_failure()