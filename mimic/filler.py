#!/usr/bin/env python3
"""
Модуль подмешивания реального легитимного контента
"""

import aiohttp
import asyncio
import random
import json
import logging
from typing import Optional, Dict, List
from datetime import datetime
import hashlib
import os

logger = logging.getLogger(__name__)

class ContentFiller:
    """
    Генератор и подмешиватель реального контента
    Использует публичные API для получения настоящих данных
    """
    
    def __init__(self, cache_dir: str = "/tmp/anemone_cache"):
        self.cache_dir = cache_dir
        self.cache = {}
        self.session = None
        self._ensure_cache_dir()
        
        # Источники контента
        self.sources = {
            'news': [
                'http://feeds.bbci.co.uk/news/rss.xml',
                'https://rss.nytimes.com/services/xml/rss/nyt/HomePage.xml',
                'https://news.google.com/rss'
            ],
            'images': [
                'https://picsum.photos/200/300',  # Random image
                'https://source.unsplash.com/random'
            ],
            'videos': [
                'https://www.youtube.com/feeds/videos.xml?channel_id=UCXuqSBlHAE6Xw-yeJA0Tunw'
            ]
        }
        
    def _ensure_cache_dir(self):
        """Создание директории для кэша"""
        os.makedirs(self.cache_dir, exist_ok=True)
    
    async def get_session(self):
        """Получение aiohttp сессии"""
        if not self.session:
            self.session = aiohttp.ClientSession()
        return self.session
    
    async def fetch_random_news(self) -> Optional[bytes]:
        """
        Получение случайной новости для подмешивания
        """
        try:
            session = await self.get_session()
            source = random.choice(self.sources['news'])
            
            # Проверяем кэш
            cache_key = hashlib.md5(source.encode()).hexdigest()
            cache_file = os.path.join(self.cache_dir, cache_key)
            
            if os.path.exists(cache_file) and (datetime.now().timestamp() - os.path.getmtime(cache_file)) < 300:
                # Кэш валиден (5 минут)
                with open(cache_file, 'rb') as f:
                    return f.read()
            
            # Загружаем свежие данные
            async with session.get(source, timeout=5) as response:
                if response.status == 200:
                    content = await response.read()
                    # Сохраняем в кэш
                    with open(cache_file, 'wb') as f:
                        f.write(content)
                    return content
        except Exception as e:
            logger.warning(f"Failed to fetch news: {e}")
        
        return None
    
    async def fetch_random_image(self) -> Optional[bytes]:
        """Получение случайного изображения"""
        try:
            session = await self.get_session()
            source = random.choice(self.sources['images'])
            
            async with session.get(source, timeout=3) as response:
                if response.status == 200:
                    return await response.read()
        except Exception as e:
            logger.warning(f"Failed to fetch image: {e}")
        
        return None
    
    async def get_filler_content(self, size_hint: int = 500) -> bytes:
        """
        Получение контента для заполнения туннеля
        """
        # 70% - новости, 20% - изображения, 10% - видео метаданные
        content_type = random.choices(
            ['news', 'image', 'video'],
            weights=[0.7, 0.2, 0.1]
        )[0]
        
        content = None
        if content_type == 'news':
            content = await self.fetch_random_news()
        elif content_type == 'image':
            content = await self.fetch_random_image()
        else:
            # Видео метаданные
            content = await self._fetch_video_metadata()
        
        if content and len(content) > size_hint:
            # Обрезаем до нужного размера
            content = content[:size_hint]
        
        return content or self._generate_dummy_content(size_hint)
    
    async def _fetch_video_metadata(self) -> Optional[bytes]:
        """Получение метаданных видео с YouTube"""
        try:
            session = await self.get_session()
            source = random.choice(self.sources['videos'])
            
            async with session.get(source, timeout=5) as response:
                if response.status == 200:
                    return await response.read()
        except Exception as e:
            logger.warning(f"Failed to fetch video metadata: {e}")
        return None
    
    def _generate_dummy_content(self, size: int) -> bytes:
        """Генерация заглушки если реальный контент недоступен"""
        # Генерируем реалистичный JSON
        dummy = {
            "timestamp": datetime.now().isoformat(),
            "random_id": random.randint(1000, 9999),
            "data": os.urandom(size - 100).hex() if size > 100 else "dummy"
        }
        return json.dumps(dummy).encode()
    
    async def close(self):
        """Закрытие сессии"""
        if self.session:
            await self.session.close()


class TrafficMixer:
    """
    Смешивание реального трафика с VPN данными
    """
    
    def __init__(self, filler: ContentFiller, mix_ratio: float = 0.3):
        self.filler = filler
        self.mix_ratio = mix_ratio  # Доля подмешиваемого контента
    
    async def mix_with_tunnel_data(self, tunnel_data: bytes) -> bytes:
        """
        Подмешивание легитимного контента к данным туннеля
        """
        if random.random() < self.mix_ratio:
            # Получаем контент для подмешивания
            filler_content = await self.filler.get_filler_content(
                size_hint=len(tunnel_data) // 2
            )
            
            if filler_content:
                # Смешиваем данные
                mixed = self._interleave_data(tunnel_data, filler_content)
                logger.debug(f"Mixed tunnel data with {len(filler_content)} bytes of filler content")
                return mixed
        
        return tunnel_data
    
    def _interleave_data(self, data1: bytes, data2: bytes) -> bytes:
        """
        Перемешивание двух потоков данных
        """
        result = bytearray()
        i, j = 0, 0
        
        while i < len(data1) and j < len(data2):
            # Берем кусок из первого потока
            chunk1_size = random.randint(10, 50)
            chunk1 = data1[i:min(i + chunk1_size, len(data1))]
            result.extend(chunk1)
            i += len(chunk1)
            
            # Добавляем кусок из второго потока
            if j < len(data2):
                chunk2_size = random.randint(5, 30)
                chunk2 = data2[j:min(j + chunk2_size, len(data2))]
                result.extend(chunk2)
                j += len(chunk2)
        
        # Добавляем остатки
        if i < len(data1):
            result.extend(data1[i:])
        if j < len(data2):
            result.extend(data2[j:])
        
        return bytes(result)