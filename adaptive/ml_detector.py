#!/usr/bin/env python3
"""
Модуль машинного обучения для обнаружения попыток DPI и блокировок
Использует nfstream для сбора статистик и scikit-learn для классификации [citation:1]
"""

import asyncio
import numpy as np
import pickle
import os
from typing import Dict, List, Optional, Tuple
from collections import deque
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, field

try:
    from nfstream import NFStreamer, NFPlugin
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    import joblib
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logging.warning("scikit-learn or nfstream not available, ML detector disabled")

logger = logging.getLogger(__name__)


@dataclass
class FlowFeatures:
    """Статистические характеристики потока для ML-анализа [citation:1][citation:10]"""
    # Временные характеристики
    duration_ms: float
    mean_packet_interval_ms: float
    std_packet_interval_ms: float
    min_packet_interval_ms: float
    max_packet_interval_ms: float
    
    # Размеры пакетов
    mean_packet_size: float
    std_packet_size: float
    min_packet_size: int
    max_packet_size: int
    
    # Направленность трафика
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    ratio_bytes_sent_received: float
    
    # TCP флаги (если применимо)
    syn_packets: int
    fin_packets: int
    rst_packets: int
    ack_packets: int
    
    # Дополнительные метрики
    window_size_variance: float
    out_of_order_packets: int
    retransmissions: int


class AnomalyScore:
    """Оценка аномальности текущего соединения"""
    
    def __init__(self, window_size: int = 100):
        self.scores = deque(maxlen=window_size)
        self.baseline_mean = 0.0
        self.baseline_std = 1.0
        self.threshold = 2.0  # Количество стандартных отклонений
        
    def add_score(self, score: float):
        """Добавление новой оценки"""
        self.scores.append(score)
        self._update_baseline()
        
    def _update_baseline(self):
        """Обновление базовой статистики"""
        if len(self.scores) > 10:
            self.baseline_mean = np.mean(self.scores)
            self.baseline_std = max(np.std(self.scores), 0.001)
    
    def is_anomaly(self, score: float) -> bool:
        """Проверка, является ли оценка аномальной"""
        if len(self.scores) < 10:
            return False
        z_score = abs(score - self.baseline_mean) / self.baseline_std
        return z_score > self.threshold


class CustomNFPlugin(NFPlugin):
    """Плагин для nfstream для сбора кастомных метрик [citation:1]"""
    
    def __init__(self):
        self.features = {}
    
    def on_init(self, flow, obs):
        """Вызывается при создании потока"""
        flow.anemone_custom_metric = 0
    
    def on_update(self, flow, obs):
        """Вызывается при обновлении потока"""
        # Собираем нестандартные метрики
        if obs.raw_size > 1000:
            flow.anemone_custom_metric += 1


class MLDetector:
    """
    ML-детектор для обнаружения попыток анализа трафика
    Обучается на характеристиках нормального и заблокированного трафика [citation:10]
    """
    
    def __init__(self, model_path: str = "models/dpi_detector.pkl"):
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.anomaly_score = AnomalyScore()
        self.is_trained = False
        self.feature_history = deque(maxlen=1000)
        
        # Пороги для принятия решений
        self.thresholds = {
            'retransmission_ratio': 0.05,  # 5% ретрансмиссий - подозрительно
            'out_of_order_ratio': 0.03,     # 3% пакетов не по порядку
            'packet_size_consistency': 0.7,  # Консистентность размеров пакетов
            'timing_regularity': 0.6         # Регулярность интервалов
        }
        
        self._init_model()
    
    def _init_model(self):
        """Инициализация или загрузка модели"""
        if not ML_AVAILABLE:
            logger.warning("ML libraries not available, using rule-based detection only")
            return
            
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.model_path.replace('.pkl', '_scaler.pkl'))
                self.is_trained = True
                logger.info(f"Loaded ML model from {self.model_path}")
            except Exception as e:
                logger.error(f"Failed to load model: {e}")
        
        if not self.is_trained:
            # Создаем простую модель для начала
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
            logger.info("Created new RandomForest model")
    
    async def analyze_flow(self, flow_data: Dict) -> Dict:
        """
        Анализ характеристик потока на предмет DPI [citation:10]
        """
        features = self._extract_features(flow_data)
        
        # Сохраняем в историю
        self.feature_history.append(features)
        
        # Правила на основе эвристик
        rule_based_verdict = self._rule_based_analysis(features)
        
        # ML-based анализ если доступен
        ml_verdict = {}
        if ML_AVAILABLE and self.is_trained and len(self.feature_history) > 10:
            ml_verdict = self._ml_analysis(features)
        
        # Комбинируем вердикты
        combined_verdict = self._combine_verdicts(rule_based_verdict, ml_verdict)
        
        # Обновляем аномалию
        self.anomaly_score.add_score(combined_verdict['anomaly_score'])
        
        return combined_verdict
    
    def _extract_features(self, flow_data: Dict) -> FlowFeatures:
        """
        Извлечение признаков из данных потока [citation:1]
        """
        # В реальной реализации здесь будет анализ pcap или flow данных
        return FlowFeatures(
            duration_ms=flow_data.get('duration_ms', 0),
            mean_packet_interval_ms=flow_data.get('mean_interval', 0),
            std_packet_interval_ms=flow_data.get('std_interval', 0),
            min_packet_interval_ms=flow_data.get('min_interval', 0),
            max_packet_interval_ms=flow_data.get('max_interval', 0),
            mean_packet_size=flow_data.get('mean_size', 0),
            std_packet_size=flow_data.get('std_size', 0),
            min_packet_size=flow_data.get('min_size', 0),
            max_packet_size=flow_data.get('max_size', 0),
            bytes_sent=flow_data.get('bytes_sent', 0),
            bytes_received=flow_data.get('bytes_received', 0),
            packets_sent=flow_data.get('packets_sent', 0),
            packets_received=flow_data.get('packets_received', 0),
            ratio_bytes_sent_received=flow_data.get('ratio', 1.0),
            syn_packets=flow_data.get('syn', 0),
            fin_packets=flow_data.get('fin', 0),
            rst_packets=flow_data.get('rst', 0),
            ack_packets=flow_data.get('ack', 0),
            window_size_variance=flow_data.get('window_variance', 0),
            out_of_order_packets=flow_data.get('out_of_order', 0),
            retransmissions=flow_data.get('retransmissions', 0)
        )
    
    def _rule_based_analysis(self, features: FlowFeatures) -> Dict:
        """
        Анализ на основе эвристических правил
        """
        score = 0.0
        reasons = []
        
        # 1. Аномально высокая доля ретрансмиссий
        total_packets = features.packets_sent + features.packets_received
        if total_packets > 0:
            retrans_ratio = features.retransmissions / total_packets
            if retrans_ratio > self.thresholds['retransmission_ratio']:
                score += 0.3
                reasons.append(f"High retransmission ratio: {retrans_ratio:.2%}")
        
        # 2. Много пакетов не по порядку (признак активного анализа)
        if total_packets > 0:
            ooo_ratio = features.out_of_order_packets / total_packets
            if ooo_ratio > self.thresholds['out_of_order_ratio']:
                score += 0.25
                reasons.append(f"High out-of-order ratio: {ooo_ratio:.2%}")
        
        # 3. Слишком регулярные интервалы (признак синтетического трафика)
        if features.std_packet_interval_ms > 0 and features.mean_packet_interval_ms > 0:
            cv = features.std_packet_interval_ms / features.mean_packet_interval_ms
            if cv < 0.2:  # Очень низкая вариативность
                score += 0.2
                reasons.append(f"Too regular timing: CV={cv:.2f}")
        
        # 4. Слишком консистентные размеры пакетов
        if features.mean_packet_size > 0:
            size_cv = features.std_packet_size / features.mean_packet_size
            if size_cv < 0.1:  # Почти все пакеты одинакового размера
                score += 0.15
                reasons.append(f"Too consistent packet sizes: CV={size_cv:.2f}")
        
        # 5. Асимметрия трафика (много входящих, мало исходящих - как при анализе)
        if features.bytes_sent > 0 and features.bytes_received > 0:
            ratio = features.bytes_received / features.bytes_sent
            if ratio > 10:  # Получаем в 10 раз больше, чем отправляем
                score += 0.1
                reasons.append(f"Traffic asymmetry: received {ratio:.1f}x more than sent")
        
        return {
            'anomaly_score': min(score, 1.0),
            'is_suspicious': score > 0.5,
            'reasons': reasons,
            'method': 'rule_based'
        }
    
    def _ml_analysis(self, features: FlowFeatures) -> Dict:
        """
        ML-based анализ (требует обученной модели) [citation:10]
        """
        try:
            # Преобразуем признаки в вектор
            feature_vector = np.array([[
                features.duration_ms,
                features.mean_packet_interval_ms,
                features.std_packet_interval_ms,
                features.mean_packet_size,
                features.std_packet_size,
                features.bytes_sent,
                features.bytes_received,
                features.packets_sent,
                features.packets_received,
                features.ratio_bytes_sent_received,
                features.retransmissions,
                features.out_of_order_packets
            ]])
            
            # Масштабируем
            feature_vector_scaled = self.scaler.transform(feature_vector)
            
            # Предсказание
            prediction = self.model.predict(feature_vector_scaled)[0]
            probability = self.model.predict_proba(feature_vector_scaled)[0]
            
            # prediction: 0 - нормальный, 1 - подозрительный
            anomaly_score = probability[1] if len(probability) > 1 else 0.5
            
            return {
                'anomaly_score': float(anomaly_score),
                'is_suspicious': prediction == 1,
                'confidence': float(max(probability)),
                'method': 'ml_based'
            }
        except Exception as e:
            logger.error(f"ML analysis failed: {e}")
            return {'anomaly_score': 0.5, 'is_suspicious': False, 'method': 'ml_failed'}
    
    def _combine_verdicts(self, rule_verdict: Dict, ml_verdict: Dict) -> Dict:
        """
        Комбинирование вердиктов от разных методов
        """
        # Веса для разных методов
        weights = {
            'rule_based': 0.4,
            'ml_based': 0.6
        }
        
        combined_score = 0.0
        total_weight = 0.0
        
        # Добавляем rule-based
        if rule_verdict:
            combined_score += rule_verdict['anomaly_score'] * weights['rule_based']
            total_weight += weights['rule_based']
        
        # Добавляем ML-based если доступен
        if ml_verdict and ml_verdict.get('method') != 'ml_failed':
            combined_score += ml_verdict['anomaly_score'] * weights['ml_based']
            total_weight += weights['ml_based']
        
        if total_weight > 0:
            combined_score /= total_weight
        
        # Собираем все причины
        all_reasons = rule_verdict.get('reasons', [])
        
        return {
            'anomaly_score': combined_score,
            'is_suspicious': combined_score > 0.5,
            'reasons': all_reasons,
            'ml_available': 'ml_based' in ml_verdict.get('method', ''),
            'timestamp': datetime.now().isoformat()
        }
    
    async def collect_training_data(self, interface: str = "any", duration: int = 60):
        """
        Сбор данных для обучения модели с помощью nfstream [citation:1]
        """
        if not ML_AVAILABLE:
            logger.error("Cannot collect data: nfstream not available")
            return
        
        logger.info(f"Collecting training data from {interface} for {duration} seconds")
        
        # Создаем streamer с включенной статистикой
        streamer = NFStreamer(
            source=interface,
            snaplen=65535,
            idle_timeout=10,
            active_timeout=300,
            statistics=True,  # Включаем сбор статистики [citation:1]
            plugins=[CustomNFPlugin()]
        )
        
        flows = []
        start_time = datetime.now()
        
        # Собираем потоки в течение указанного времени
        for flow in streamer:
            if (datetime.now() - start_time).seconds > duration:
                break
            
            # Извлекаем признаки
            features = {
                'duration_ms': flow.bidirectional_duration_ms,
                'mean_interval': flow.bidirectional_mean_piat_ms,
                'std_interval': flow.bidirectional_stdev_piat_ms,
                'mean_size': flow.bidirectional_mean_ip_ps,
                'std_size': flow.bidirectional_stdev_ip_ps,
                'bytes_sent': flow.src2dst_ip_bytes,
                'bytes_received': flow.dst2src_ip_bytes,
                'packets_sent': flow.src2dst_packets,
                'packets_received': flow.dst2src_packets,
                'application': flow.application_name,
                'is_vpn': 'VPN' in flow.application_name or 'Tor' in flow.application_name
            }
            flows.append(features)
            
            if len(flows) % 100 == 0:
                logger.info(f"Collected {len(flows)} flows")
        
        logger.info(f"Collected {len(flows)} flows for training")
        return flows
    
    def train_model(self, training_data: List[Dict]):
        """
        Обучение модели на собранных данных [citation:10]
        """
        if not ML_AVAILABLE or not training_data:
            return
        
        # Подготавливаем признаки и метки
        X = []
        y = []
        
        for item in training_data:
            if 'is_vpn' in item:  # Только если есть метка
                X.append([
                    item.get('duration_ms', 0),
                    item.get('mean_interval', 0),
                    item.get('std_interval', 0),
                    item.get('mean_size', 0),
                    item.get('std_size', 0),
                    item.get('bytes_sent', 0),
                    item.get('bytes_received', 0),
                    item.get('packets_sent', 0),
                    item.get('packets_received', 0)
                ])
                y.append(1 if item.get('is_vpn') else 0)
        
        if len(X) < 10:
            logger.warning("Not enough training data")
            return
        
        # Масштабируем признаки
        X_scaled = self.scaler.fit_transform(X)
        
        # Обучаем модель
        self.model.fit(X_scaled, y)
        self.is_trained = True
        
        # Сохраняем модель
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.scaler, self.model_path.replace('.pkl', '_scaler.pkl'))
        
        logger.info(f"Model trained on {len(X)} samples and saved to {self.model_path}")
        
        # Оценка качества
        train_score = self.model.score(X_scaled, y)
        logger.info(f"Training accuracy: {train_score:.2f}")