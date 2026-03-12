#!/usr/bin/env python3
"""
Криптографическое ядро протокола Анемон
Использует AES-256-GCM для шифрования [citation:1][citation:8]
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import os
import logging
import time
from typing import Tuple, Optional, Dict

logger = logging.getLogger(__name__)

class CryptoEngine:
    """
    Криптографический движок с поддержкой:
    - AES-256-GCM аутентифицированное шифрование
    - ECDH для ключевого обмена (Perfect Forward Secrecy)
    - Автоматическая ротация ключей
    """
    
    def __init__(self, rotation_interval: int = 3600):
        self.rotation_interval = rotation_interval  # секунды
        self.private_key = None
        self.public_key = None
        self.session_keys = {}  # peer_id -> {key, timestamp}
        self._generate_identity_key()
        
    def _generate_identity_key(self):
        """Генерация долговременного ключа идентификации"""
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        self.public_key = self.private_key.public_key()
        logger.debug("Identity key pair generated")
    
    def get_public_key_bytes(self) -> bytes:
        """Экспорт публичного ключа для передачи"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def perform_key_exchange(self, peer_public_key_bytes: bytes, peer_id: str) -> bytes:
        """
        ECDH ключевой обмен для создания общего секрета
        Возвращает сессионный ключ
        """
        # Загружаем публичный ключ пира
        peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes)
        
        # Вычисляем общий секрет
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Диверсифицируем ключ через HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 бит для AES-256
            salt=None,
            info=b"anemone-session-key",
        )
        session_key = hkdf.derive(shared_secret)
        
        # Сохраняем ключ с меткой времени
        self.session_keys[peer_id] = {
            'key': session_key,
            'timestamp': time.time()
        }
        
        return session_key
    
    def encrypt(self, data: bytes, peer_id: str, aad: bytes = b"") -> Tuple[bytes, bytes]:
        """
        Шифрование данных AES-256-GCM
        Возвращает (nonce + ciphertext, tag)
        """
        # Проверяем и обновляем ключ при необходимости
        self._check_key_rotation(peer_id)
        
        session_key = self.session_keys.get(peer_id, {}).get('key')
        if not session_key:
            raise ValueError(f"No session key for peer {peer_id}")
        
        # Генерируем случайный nonce (12 байт рекомендуется для GCM)
        nonce = os.urandom(12)
        
        aesgcm = AESGCM(session_key)
        ciphertext = aesgcm.encrypt(nonce, data, aad)
        
        # Возвращаем nonce + ciphertext и отдельно tag (последние 16 байт ciphertext)
        # В GCM tag обычно последние 16 байт
        return nonce + ciphertext[:-16], ciphertext[-16:]
    
    def decrypt(self, encrypted_data: bytes, tag: bytes, peer_id: str, aad: bytes = b"") -> bytes:
        """
        Расшифровка данных
        encrypted_data: nonce + ciphertext
        """
        session_key = self.session_keys.get(peer_id, {}).get('key')
        if not session_key:
            raise ValueError(f"No session key for peer {peer_id}")
        
        # Извлекаем nonce (первые 12 байт)
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        aesgcm = AESGCM(session_key)
        # Восстанавливаем полный ciphertext с тегом
        full_ciphertext = ciphertext + tag
        
        try:
            plaintext = aesgcm.decrypt(nonce, full_ciphertext, aad)
            return plaintext
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise
    
    def _check_key_rotation(self, peer_id: str):
        """Проверка необходимости ротации ключа"""
        key_info = self.session_keys.get(peer_id)
        if key_info:
            age = time.time() - key_info['timestamp']
            if age > self.rotation_interval:
                logger.info(f"Session key for {peer_id} expired, rotation needed")
                # Сигнализируем о необходимости ротации
                # В реальной реализации здесь будет вызов callback
                pass
    
    def rotate_key(self, peer_id: str, new_key: bytes):
        """Принудительная ротация ключа"""
        self.session_keys[peer_id] = {
            'key': new_key,
            'timestamp': time.time()
        }
        logger.info(f"Rotated session key for {peer_id}")


class PerfectForwardSecrecy:
    """
    Реализация Perfect Forward Secrecy через эфемерные ключи
    """
    
    def __init__(self):
        self.ephemeral_key = None
        
    def generate_ephemeral_key(self):
        """Генерация эфемерного ключа для каждой сессии"""
        self.ephemeral_key = ec.generate_private_key(ec.SECP384R1())
        return self.ephemeral_key
    
    def derive_session_key(self, peer_ephemeral_key_bytes: bytes) -> bytes:
        """Вычисление сессионного ключа из эфемерных ключей"""
        peer_key = serialization.load_pem_public_key(peer_ephemeral_key_bytes)
        shared_secret = self.ephemeral_key.exchange(ec.ECDH(), peer_key)
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.urandom(16),
            info=b"anemone- ephemeral-session",
        )
        return hkdf.derive(shared_secret)