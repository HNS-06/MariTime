#!/usr/bin/env python3
"""
MODBUS SECURITY RULE ENGINE - Anomaly Detection System

Core intellectual component of the MariTime security monitoring system.
Analyzes Modbus traffic to detect sophisticated cyber attacks against OT/ICS systems.

Detection Rules:
1. Function Code Anomaly - Unauthorized or rare function codes
2. Value Anomaly - Register values outside normal operational ranges  
3. Source IP Anomaly - Traffic from unknown/authorized sources
4. Timing Anomaly - Operations outside normal maintenance windows
5. Pattern Anomaly - Deviation from baseline traffic patterns
6. Safety Critical - Access to safety-critical registers without authorization
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from enum import Enum
from collections import defaultdict, deque
import statistics
import math

from os_fingerprint import OSFingerprinter
from dpi_validator import DPIValidator
from protocol_parsers import DNP3Parser, S7commParser
from siem_forwarder import SIEMForwarder
from containment_soar import ContainmentSOAR

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('rule_engine.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('rule_engine')

import os
import time
import asyncio

# Try to load YAML config
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

# MITRE ATT&CK for ICS mapping
_MITRE_MAP_PATH = os.path.join(os.path.dirname(__file__), '..', 'config', 'mitre_ics_map.json')
_RULES_YAML_PATH = os.path.join(os.path.dirname(__file__), '..', 'config', 'rules.yaml')

def _load_mitre_map() -> dict:
    try:
        if os.path.exists(_MITRE_MAP_PATH):
            with open(_MITRE_MAP_PATH, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def _load_rules_yaml() -> dict:
    if not YAML_AVAILABLE:
        return {}
    try:
        if os.path.exists(_RULES_YAML_PATH):
            with open(_RULES_YAML_PATH, 'r') as f:
                return yaml.safe_load(f) or {}
    except Exception:
        pass
    return {}

MITRE_MAP = _load_mitre_map()
RULES_CONFIG = _load_rules_yaml()

class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"
class AlertType(Enum):
    """Types of security alerts."""
    FUNCTION_CODE_ANOMALY = "function_code_anomaly"
    VALUE_ANOMALY = "value_anomaly"
    SOURCE_IP_ANOMALY = "source_ip_anomaly"
    TIMING_ANOMALY = "timing_anomaly"
    PATTERN_ANOMALY = "pattern_anomaly"
    SAFETY_CRITICAL_VIOLATION = "safety_critical_violation"
    REGISTER_WRITE_ANOMALY = "register_write_anomaly"
    FLOODING_ATTACK = "flooding_attack"
    CONFIDENCE_ANOMALY = "confidence_anomaly"
    OS_FINGERPRINT_ANOMALY = "os_fingerprint_anomaly"
    DPI_PROTOCOL_VIOLATION = "dpi_protocol_violation"
    UNAUTHORIZED_S7_CONTROL = "unauthorized_s7_control"
    UNAUTHORIZED_DNP3_CONTROL = "unauthorized_dnp3_control"
class ModbusBaselineModel:
    """Baseline model for normal Modbus traffic patterns."""
    
    def __init__(self):
        # Normal operation windows
        self.normal_hours = list(range(8, 18))  # 8 AM - 6 PM
        self.shift_change_hours = [5, 6, 17, 18]  # Around shift changes
        
        # Normal register access patterns
        self.normal_read_registers = [40001, 40003, 40004]  # pump_speed, temperature, pressure
        self.normal_write_registers = [40002, 40005]        # valve_position, flow_rate
        self.safety_critical_registers = [40006]           # alarm_status
        
        # Normal function codes
        self.normal_function_codes = [0x03]  # Read Holding Registers
        self.shift_write_function_codes = [0x06]  # Write Single Register
        
        # Normal value ranges for each register
        self.register_ranges = {
            40001: (0, 100),    # pump_speed: 0-100%
            40002: (0, 100),    # valve_position: 0-100%
            40003: (0, 150),    # temperature: 0-150°C (in 10s scale)
            40004: (0, 10),     # pressure: 0-10 bar (in 10s scale)
            40005: (0, 100),    # flow_rate: 0-100%
            40006: (0, 10)      # alarm_status: 0-10 alarms
        }
        
        # Traffic statistics for baseline
        self.traffic_patterns = {
            'hourly_counts': defaultdict(int),
            'daily_counts': defaultdict(int),
            'function_code_counts': defaultdict(int),
            'register_access_counts': defaultdict(int),
            'value_history': defaultdict(list)
        }
        
        # Whitelist and blacklist
        self.whitelisted_ips = {'10.0.1.1', '10.0.1.2', '10.0.2.1'}
        self.blacklisted_ips = set()
        
        # Rate limiting per source IP
        self.ip_request_counts = defaultdict(int)
        self.ip_request_timestamps = defaultdict(list)
        
        # Anomaly detection thresholds
        self.anomaly_thresholds = {
            'value_anomaly_std_dev': 2.0,
            'flooding_threshold': 50,  # packets per minute
            'rare_function_code_threshold': 0.05,  # 5% of total requests
            'timing_anomaly_threshold': 3,  # hours outside normal range
            'pattern_anomaly_threshold': 0.8  # correlation coefficient
        }
        
        # Load history from baseline files
        self._load_baseline_history()
    
    def _load_baseline_history(self):
        """Load historical baseline data from log files."""
        try:
            # Load HMI client logs for baseline
            if os.path.exists('hmi_traffic.log'):
                self._extract_baseline_from_hmi_log()
            
            # Load any existing baseline data files
            if os.path.exists('baseline_data.json'):
                with open('baseline_data.json', 'r') as f:
                    baseline_data = json.load(f)
                    self._update_baseline_from_data(baseline_data)
                    
        except Exception as e:
            logger.warning(f"Could not load baseline history: {e}")
    
    def _extract_baseline_from_hmi_log(self):
        """Extract baseline patterns from HMI client logs."""
        try:
            with open('hmi_traffic.log', 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line.strip())
                        hour = datetime.fromisoformat(entry['timestamp']).hour
                        function_code = entry.get('function_code', '0')
                        register = entry.get('register')
                        
                        # Track traffic by hour
                        self.traffic_patterns['hourly_counts'][hour] += 1
                        self.traffic_patterns['daily_counts'][hour] += 1
                        
                        # Track function code usage
                        if function_code:
                            self.traffic_patterns['function_code_counts'][function_code] += 1
                        
                        # Track register access patterns
                        if register:
                            self.traffic_patterns['register_access_counts'][register] += 1
                        
                        # Track value history
                        if 'value' in entry:
                            self.traffic_patterns['value_history'][register].append(entry['value'])
                            
                    except json.JSONDecodeError:
                        continue
                        
        except FileNotFoundError:
            pass
    
    def _update_baseline_from_data(self, baseline_data: Dict):
        """Update baseline from loaded data."""
        for key, value in baseline_data.items():
            if key in self.traffic_patterns:
                self.traffic_patterns[key].update(value)
    
    def record_traffic_entry(self, packet: Dict):
        """Record a traffic entry for baseline modeling."""
        try:
            timestamp = datetime.fromisoformat(packet['timestamp'])
            hour = timestamp.hour
            
            # Update traffic patterns
            self.traffic_patterns['hourly_counts'][hour] += 1
            self.traffic_patterns['daily_counts'][hour] += 1
            
            function_code = packet.get('function_code')
            if function_code:
                self.traffic_patterns['function_code_counts'][function_code] += 1
            
            register = packet.get('register')
            if register:
                self.traffic_patterns['register_access_counts'][register] += 1
            
            value = packet.get('value')
            if value is not None and register:
                self.traffic_patterns['value_history'][register].append(value)
                
                # Keep only recent history (last 24 hours worth)
                if len(self.traffic_patterns['value_history'][register]) > 1000:
                    self.traffic_patterns['value_history'][register] = self.traffic_patterns['value_history'][register][-1000:]
                    
        except Exception as e:
            logger.error(f"Error recording traffic entry: {e}")
    
    def is_normal_hour(self, hour: int) -> bool:
        """Check if current hour is within normal operation window."""
        return hour in self.normal_hours
    
    def is_shift_change_window(self, hour: int) -> bool:
        """Check if current hour is during scheduled shift changes."""
        return hour in self.shift_change_hours
    
    def is_safe_value(self, register: int, value: int) -> bool:
        """Check if value is within normal operational range."""
        if register in self.register_ranges:
            min_val, max_val = self.register_ranges[register]
            return min_val <= value <= max_val
        return True
    
    def is_safe_function_code(self, function_code: str, hour: int) -> bool:
        """Check if function code is safe for current time."""
        if function_code not in self.normal_function_codes:
            if self.is_shift_change_window(hour):
                return function_code in self.shift_write_function_codes
            return False
        return True
    
    def is_safe_register(self, register: int, is_write: bool) -> bool:
        """Check if register access is safe."""
        if is_write:
            return register in self.normal_write_registers
        else:
            return register in self.normal_read_registers
    
    def is_authorized_ip(self, source_ip: str) -> bool:
        """Check if source IP is authorized."""
        return source_ip in self.whitelisted_ips
    
    def record_request(self, source_ip: str):
        """Record request from source IP for rate limiting."""
        now = time.time()
        
        # Clean old timestamps
        if source_ip in self.ip_request_timestamps:
            self.ip_request_timestamps[source_ip] = [
                ts for ts in self.ip_request_timestamps[source_ip]
                if now - ts < 300  # Last 5 minutes
            ]
        
        self.ip_request_timestamps[source_ip].append(now)
        self.ip_request_counts[source_ip] = len(self.ip_request_timestamps[source_ip])
    
    def is_rate_limited(self, source_ip: str) -> bool:
        """Check if source IP is rate limited."""
        thresholds = self.anomaly_thresholds
        
        if source_ip in self.blacklisted_ips:
            return True
        
        current_count = self.ip_request_counts.get(source_ip, 0)
        return current_count >= thresholds['flooding_threshold']
class ModbusRuleEngine:
    """Core rule engine for detecting Modbus security anomalies."""
    
    def __init__(self):
        self.baseline = ModbusBaselineModel()
        self.alerts = []
        
        # Rule configuration
        self.rules = {
            'function_code_anomaly': True,
            'value_anomaly': True,
            'source_ip_anomaly': True,
            'timing_anomaly': True,
            'pattern_anomaly': True,
            'safety_critical_violation': True,
            'register_write_anomaly': True,
            'flooding_attack': True,
            'unauthorized_write': True,
            'os_fingerprint_anomaly': True,
            'dpi_protocol_violation': True,
            'unauthorized_s7_control': True,
            'unauthorized_dnp3_control': True
        }

        # Load rules from YAML config if available
        self._apply_yaml_config()

        self.os_fingerprinter = OSFingerprinter()
        self.dpi_validator = DPIValidator()
        self.dnp3_parser = DNP3Parser()
        self.s7_parser = S7commParser()
        
        siem_settings = RULES_CONFIG.get('settings', {}).get('siem', {})
        self.siem_forwarder = SIEMForwarder(
            host=siem_settings.get('host', '127.0.0.1'),
            port=siem_settings.get('port', 514),
            protocol=siem_settings.get('protocol', 'UDP'),
            fmt=siem_settings.get('format', 'CEF')
        )
        self.soar = ContainmentSOAR()

        # Hot-reload timestamp
        self._config_mtime = 0.0
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'alerts_generated': 0,
            'rules_triggered': defaultdict(int)
        }
    
    def process_packet(self, packet: Dict) -> List[Dict]:
        """Process a Modbus packet through all detection rules."""
        self.stats['packets_processed'] += 1
        
        alerts = []
        packet_time = datetime.fromisoformat(packet['timestamp'])
        hour = packet_time.hour
        
        # Record in baseline model
        self.baseline.record_traffic_entry(packet)
        
        # Apply detection rules
        dest_port = packet.get("dest_port") or packet.get("destination_port")
        src_port = packet.get("source_port")
        
        if dest_port == 102 or src_port == 102:
            alerts.extend(self._check_s7comm_anomaly(packet, hour))
            
        if dest_port == 20000 or src_port == 20000:
            alerts.extend(self._check_dnp3_anomaly(packet, hour))
            
        if dest_port not in (102, 20000) and src_port not in (102, 20000):
            alerts.extend(self._check_dpi_violation(packet, hour))

        alerts.extend(self._check_os_fingerprint(packet, hour))

        if self.rules['function_code_anomaly']:
            alerts.extend(self._check_function_code_anomaly(packet, hour))
        
        if self.rules['value_anomaly']:
            alerts.extend(self._check_value_anomaly(packet, hour))
        
        if self.rules['source_ip_anomaly']:
            alerts.extend(self._check_source_ip_anomaly(packet, hour))
        
        if self.rules['timing_anomaly']:
            alerts.extend(self._check_timing_anomaly(packet, hour))
        
        if self.rules['pattern_anomaly']:
            alerts.extend(self._check_pattern_anomaly(packet, hour))
        
        if self.rules['safety_critical_violation']:
            alerts.extend(self._check_safety_critical_violation(packet, hour))
        
        if self.rules['register_write_anomaly']:
            alerts.extend(self._check_register_write_anomaly(packet, hour))
        
        if self.rules['flooding_attack']:
            alerts.extend(self._check_flooding_attack(packet, hour))

        if self.rules.get('unauthorized_write', True):
            alerts.extend(self._check_unauthorized_write(packet, hour))

        # Record request for rate limiting
        source_ip = packet.get('source_ip', 'unknown')
        self.baseline.record_request(source_ip)
        
        # Check if critical alert fired and SOAR is enabled
        soar_settings = RULES_CONFIG.get('settings', {}).get('soar', {})
        if soar_settings.get('enabled', True):
            has_critical = any(a.get('severity') == 'critical' for a in alerts)
            if has_critical:
                for a in alerts:
                    if a.get('severity') == 'critical':
                        attacker_ip = a.get('packet_details', {}).get('source_ip') or a.get('analysis_details', {}).get('source_ip')
                        if attacker_ip and attacker_ip != 'unknown':
                            self.soar.block_ip(attacker_ip)

        # Forward alerts to SIEM if enabled
        siem_settings = RULES_CONFIG.get('settings', {}).get('siem', {})
        if siem_settings.get('enabled', True):
            for alert in alerts:
                self.siem_forwarder.send_alert(alert)

        # Add alerts to internal list
        self.alerts.extend(alerts)
        self.stats['alerts_generated'] += len(alerts)
        
        for alert in alerts:
            self.stats['rules_triggered'][alert['alert_type']] += 1
        
        return alerts

    def _check_s7comm_anomaly(self, packet: Dict, hour: int) -> List[Dict]:
        alerts = []
        if self.rules.get('unauthorized_s7_control', True):
            res = self.s7_parser.parse_packet(packet)
            if res and res.get('unauthorized'):
                alerts.append(self._create_alert(
                    AlertType.UNAUTHORIZED_S7_CONTROL,
                    AlertSeverity.CRITICAL,
                    f"Unauthorized S7comm operation: {res.get('description')}",
                    packet,
                    res
                ))
        return alerts

    def _check_dnp3_anomaly(self, packet: Dict, hour: int) -> List[Dict]:
        alerts = []
        if self.rules.get('unauthorized_dnp3_control', True):
            res = self.dnp3_parser.parse_packet(packet)
            if res and res.get('unauthorized'):
                alerts.append(self._create_alert(
                    AlertType.UNAUTHORIZED_DNP3_CONTROL,
                    AlertSeverity.CRITICAL,
                    f"Unauthorized DNP3 operation: {res.get('description')}",
                    packet,
                    res
                ))
        return alerts

    def _check_dpi_violation(self, packet: Dict, hour: int) -> List[Dict]:
        alerts = []
        if self.rules.get('dpi_protocol_violation', True):
            res = self.dpi_validator.validate_modbus_packet(packet)
            if res:
                alerts.append(self._create_alert(
                    AlertType.DPI_PROTOCOL_VIOLATION,
                    AlertSeverity.CRITICAL,
                    f"Modbus DPI protocol violation: {res.get('message')}",
                    packet,
                    res
                ))
        return alerts

    def _check_os_fingerprint(self, packet: Dict, hour: int) -> List[Dict]:
        alerts = []
        if self.rules.get('os_fingerprint_anomaly', True):
            source_ip = packet.get('source_ip', 'unknown')
            detected_os = self.os_fingerprinter.fingerprint_packet(packet)
            res = self.os_fingerprinter.check_anomaly(source_ip, detected_os)
            if res:
                alerts.append(self._create_alert(
                    AlertType.OS_FINGERPRINT_ANOMALY,
                    AlertSeverity.HIGH,
                    res.get('message'),
                    packet,
                    res
                ))
        return alerts
    
    def _check_function_code_anomaly(self, packet: Dict, hour: int) -> List[Dict]:
        """Rule 1: Detect unauthorized or rare function codes."""
        alerts = []
        
        function_code = packet.get('function_code', '')
        is_write = packet.get('operation') == 'write' or packet.get('function_code') in ['0x06', '0x10', '0x17']
        
        # Check for function codes not in baseline
        if function_code not in self.baseline.normal_function_codes:
            if self.is_shift_change_window(hour):
                if function_code not in self.baseline.shift_write_function_codes:
                    alerts.append(self._create_alert(
                        AlertType.FUNCTION_CODE_ANOMALY,
                        AlertSeverity.HIGH,
                        f"Unauthorized function code {function_code} during shift change",
                        packet,
                        {'function_code': function_code, 'hour': hour}
                    ))
            else:
                alerts.append(self._create_alert(
                    AlertType.FUNCTION_CODE_ANOMALY,
                    AlertSeverity.CRITICAL,
                    f"Unauthorized function code {function_code} during normal operation",
                    packet,
                    {'function_code': function_code, 'hour': hour}
                ))
        
        return alerts
    
    def _check_value_anomaly(self, packet: Dict, hour: int) -> List[Dict]:
        """Rule 2: Detect values outside normal operational ranges."""
        alerts = []
        
        register = packet.get('register')
        value = packet.get('value')
        
        if register is None or value is None:
            return alerts
        
        # Check against hard limits
        if not self.baseline.is_safe_value(register, value):
            severity = AlertSeverity.CRITICAL if register in self.baseline.safety_critical_registers else AlertSeverity.HIGH
            alerts.append(self._create_alert(
                AlertType.VALUE_ANOMALY,
                severity,
                f"Value {value} for register {register} outside safe operating range",
                packet,
                {'register': register, 'value': value, 'range': self.baseline.register_ranges.get(register, (0, 0))}
            ))
        
        # Check against statistical anomaly (using baseline)
        if register in self.baseline.traffic_patterns['value_history']:
            values = self.baseline.traffic_patterns['value_history'][register]
            if len(values) >= 10:
                mean = statistics.mean(values[-10:])
                std_dev = statistics.stdev(values[-10:]) if len(values) > 1 else 0
                
                if std_dev > 0:
                    z_score = abs(value - mean) / std_dev
                    if z_score > self.baseline.anomaly_thresholds['value_anomaly_std_dev']:
                        alerts.append(self._create_alert(
                            AlertType.VALUE_ANOMALY,
                            AlertSeverity.HIGH,
                            f"Statistical anomaly: value {value} deviates {z_score:.2f} standard deviations from normal",
                            packet,
                            {
                                'register': register, 
                                'value': value, 
                                'mean': mean, 
                                'std_dev': std_dev,
                                'z_score': z_score
                            }
                        ))
        
        return alerts
    
    def _check_source_ip_anomaly(self, packet: Dict, hour: int) -> List[Dict]:
        """Rule 3: Detect traffic from unauthorized source IPs."""
        alerts = []
        
        source_ip = packet.get('source_ip', 'unknown')
        
        if source_ip == 'unknown':
            return alerts
        
        # Check if IP is in whitelist
        if not self.baseline.is_authorized_ip(source_ip):
            alerts.append(self._create_alert(
                AlertType.SOURCE_IP_ANOMALY,
                AlertSeverity.HIGH,
                f"Traffic from unauthorized source IP: {source_ip}",
                packet,
                {'source_ip': source_ip, 'authorized_ips': list(self.baseline.whitelisted_ips)}
            ))
        
        return alerts
    
    def _check_timing_anomaly(self, packet: Dict, hour: int) -> List[Dict]:
        """Rule 4: Detect operations outside normal maintenance windows."""
        alerts = []
        
        # Check for activities outside normal hours
        if not self.baseline.is_normal_hour(hour):
            # Only flag critical activities outside normal hours
            function_code = packet.get('function_code', '')
            register = packet.get('register')
            
            if (function_code in ['0x06', '0x10', '0x17'] or  # Write operations
                (register and register in self.baseline.safety_critical_registers)):
                
                alerts.append(self._create_alert(
                    AlertType.TIMING_ANOMALY,
                    AlertSeverity.HIGH,
                    f"Critical operation outside normal hours (current: {hour:02d}:00)",
                    packet,
                    {'hour': hour, 'function_code': function_code, 'register': register}
                ))
        
        return alerts
    
    def _check_pattern_anomaly(self, packet: Dict, hour: int) -> List[Dict]:
        """Rule 5: Detect deviations from baseline traffic patterns."""
        alerts = []
        
        function_code = packet.get('function_code', '')
        register = packet.get('register')
        
        # Check function code frequency anomaly
        if function_code in self.baseline.traffic_patterns['function_code_counts']:
            total_counts = sum(self.baseline.traffic_patterns['function_code_counts'].values())
            func_counts = self.baseline.traffic_patterns['function_code_counts'][function_code]
            frequency = func_counts / total_counts if total_counts > 0 else 0
            
            if frequency < self.baseline.anomaly_thresholds['rare_function_code_threshold']:
                alerts.append(self._create_alert(
                    AlertType.PATTERN_ANOMALY,
                    AlertSeverity.WARNING,
                    f"Rare function code pattern: {function_code} appears {frequency:.1%} of time",
                    packet,
                    {
                        'function_code': function_code,
                        'frequency': frequency,
                        'threshold': self.baseline.anomaly_thresholds['rare_function_code_threshold']
                    }
                ))
        
        # Check register access anomaly
        if register in self.baseline.traffic_patterns['register_access_counts']:
            total_accesses = sum(self.baseline.traffic_patterns['register_access_counts'].values())
            reg_accesses = self.baseline.traffic_patterns['register_access_counts'][register]
            access_rate = reg_accesses / total_accesses if total_accesses > 0 else 0
            
            if access_rate > 0.5:  # Register accessed >50% of the time
                alerts.append(self._create_alert(
                    AlertType.PATTERN_ANOMALY,
                    AlertSeverity.INFO,
                    f"Unusual register access pattern: {register} accessed {access_rate:.1%} of time",
                    packet,
                    {
                        'register': register,
                        'access_rate': access_rate
                    }
                ))
        
        return alerts
    
    def _check_safety_critical_violation(self, packet: Dict, hour: int) -> List[Dict]:
        """Rule 6: Detect unauthorized access to safety-critical registers."""
        alerts = []
        
        register = packet.get('register')
        is_write = packet.get('operation') == 'write' or packet.get('function_code', '').startswith('0x06')
        
        if register in self.baseline.safety_critical_registers and is_write:
            alerts.append(self._create_alert(
                AlertType.SAFETY_CRITICAL_VIOLATION,
                AlertSeverity.CRITICAL,
                f"Unauthorized write to safety-critical register {register} (alarm system)",
                packet,
                {'register': register, 'function_code': packet.get('function_code')}
            ))
        
        return alerts
    
    def _check_register_write_anomaly(self, packet: Dict, hour: int) -> List[Dict]:
        """Rule 7: Detect anomalous register write patterns."""
        alerts = []
        
        register = packet.get('register')
        is_write = packet.get('operation') == 'write' or packet.get('function_code', '').startswith('0x06')
        
        if is_write and register:
            # Check if register is normally safe for writes
            if not self.baseline.is_safe_register(register, is_write=True):
                alerts.append(self._create_alert(
                    AlertType.REGISTER_WRITE_ANOMALY,
                    AlertSeverity.HIGH,
                    f"Unsafe register {register} written to (normally reserved for control)",
                    packet,
                    {'register': register, 'function_code': packet.get('function_code')}
                ))
        
        return alerts
    
    def _check_flooding_attack(self, packet: Dict, hour: int) -> List[Dict]:
        """Rule 8: Detect potential flooding attacks."""
        alerts = []
        
        source_ip = packet.get('source_ip', 'unknown')
        
        if source_ip == 'unknown':
            return alerts
        
        if self.baseline.is_rate_limited(source_ip):
            alerts.append(self._create_alert(
                AlertType.FLOODING_ATTACK,
                AlertSeverity.CRITICAL,
                f"Potential flooding attack from source IP: {source_ip}",
                packet,
                {'source_ip': source_ip, 'request_count': self.baseline.ip_request_counts.get(source_ip, 0)}
            ))
        
        return alerts
    
    def _apply_yaml_config(self):
        """Apply settings from rules.yaml if available."""
        global RULES_CONFIG
        RULES_CONFIG = _load_rules_yaml()
        if not RULES_CONFIG:
            return
        rules_list = RULES_CONFIG.get('rules', [])
        for rule in rules_list:
            rule_id = rule.get('id')
            if rule_id and rule_id in self.rules:
                self.rules[rule_id] = rule.get('enabled', True)
        # Apply settings
        settings = RULES_CONFIG.get('settings', {})
        if 'flooding_threshold' in settings:
            self.baseline.anomaly_thresholds['flooding_threshold'] = settings.get('flooding_threshold', 50)
        logger.info(f'Loaded {len(rules_list)} rules from rules.yaml')

    def reload_config(self) -> Dict:
        """Hot-reload configuration from rules.yaml. Call this on Ctrl+R."""
        global MITRE_MAP, RULES_CONFIG
        MITRE_MAP = _load_mitre_map()
        RULES_CONFIG = _load_rules_yaml()
        self._apply_yaml_config()
        siem_settings = RULES_CONFIG.get('settings', {}).get('siem', {})
        self.siem_forwarder.host = siem_settings.get('host', '127.0.0.1')
        self.siem_forwarder.port = siem_settings.get('port', 514)
        self.siem_forwarder.protocol = siem_settings.get('protocol', 'UDP').upper()
        self.siem_forwarder.format = siem_settings.get('format', 'CEF').upper()
        logger.info('Configuration hot-reloaded')
        return {'rules_loaded': len(RULES_CONFIG.get('rules', [])), 'mitre_techniques': len(MITRE_MAP)}

    def _check_unauthorized_write(self, packet: Dict, hour: int) -> List[Dict]:
        """Rule: Detect writes without HMAC authorization token."""
        alerts = []
        is_write = packet.get('operation') == 'write' or packet.get('function_code', '').startswith('0x06')

        # Only check if HMAC rule is enabled in config
        yaml_rules = {r['id']: r for r in RULES_CONFIG.get('rules', [])}
        hmac_rule = yaml_rules.get('unauthorized_write', {})
        if not hmac_rule.get('enabled', True) or not hmac_rule.get('parameters', {}).get('require_hmac', False):
            return alerts

        if is_write:
            source_ip = packet.get('source_ip', 'unknown')
            # Flag unauthorized IPs attempting writes
            if not self.baseline.is_authorized_ip(source_ip):
                alerts.append(self._create_alert(
                    AlertType.FUNCTION_CODE_ANOMALY,
                    AlertSeverity.CRITICAL,
                    f'Unauthorized write (no HMAC token) from {source_ip} to register {packet.get("register", "unknown")}',
                    packet,
                    {'source_ip': source_ip, 'register': packet.get('register'), 'hmac_required': True}
                ))
        return alerts

    def _create_alert(self, alert_type: AlertType, severity: AlertSeverity,
                     message: str, packet: Dict, details: Dict) -> Dict:
        """Create a standardized alert with MITRE ATT&CK ICS enrichment."""
        timestamp = datetime.now().isoformat()

        alert = {
            'timestamp': timestamp,
            'alert_id': f"{int(datetime.now().timestamp())}_{len(self.alerts)}",
            'alert_type': alert_type.value,
            'severity': severity.value,
            'message': message,
            'packet_details': packet,
            'analysis_details': details,
            'is_read': False,
            'mitre_id': MITRE_MAP.get(alert_type.value, {}).get('id', 'T0000'),
            'mitre_name': MITRE_MAP.get(alert_type.value, {}).get('name', 'Unknown Technique'),
            'mitre_tactic': MITRE_MAP.get(alert_type.value, {}).get('tactic', 'Unknown'),
            'protocol': 'MODBUS',
            'lifecycle_state': 'new',  # new | acknowledged | muted | escalated | closed
        }

        logger.warning(f"\U0001f6a8 ALERT [{severity.value.upper()}]: {message}")
        return alert
    
    def export_alerts(self, filepath: str = None) -> List[Dict]:
        """Export all alerts to file or return as list."""
        if filepath:
            with open(filepath, 'w') as f:
                json.dump(self.alerts, f, indent=2)
            logger.info(f"Alerts exported to {filepath}")
        else:
            return self.alerts.copy()
    
    def get_alerts(self, severity_filter: Optional[AlertSeverity] = None, 
                  alert_type_filter: Optional[AlertType] = None) -> List[Dict]:
        """Get alerts with optional filtering."""
        filtered_alerts = self.alerts.copy()
        
        if severity_filter:
            filtered_alerts = [a for a in filtered_alerts if a['severity'] == severity_filter.value]
        
        if alert_type_filter:
            filtered_alerts = [a for a in filtered_alerts if a['alert_type'] == alert_type_filter.value]
        
        return filtered_alerts
    
    def mark_alert_as_read(self, alert_id: str):
        """Mark an alert as read."""
        for alert in self.alerts:
            if alert['alert_id'] == alert_id:
                alert['is_read'] = True
                return True
        return False
    
    def get_stats(self) -> Dict:
        """Get rule engine statistics."""
        return {
            'packets_processed': self.stats['packets_processed'],
            'alerts_generated': self.stats['alerts_generated'],
            'rules_triggered': dict(self.stats['rules_triggered'])
        }
    
    def get_baseline_stats(self) -> Dict:
        """Get baseline model statistics."""
        return {
            'current_hour': datetime.now().hour,
            'hourly_traffic': dict(self.baseline.traffic_patterns['hourly_counts']),
            'authorized_ips': list(self.baseline.whitelisted_ips),
            'blacklisted_ips': list(self.baseline.blacklisted_ips)
        }
async def process_modbus_logs(rule_engine: ModbusRuleEngine, log_file: str = 'captured_packets.jsonl'):
    """Process Modbus logs through the rule engine."""
    try:
        if not os.path.exists(log_file):
            logger.warning(f"Log file {log_file} not found")
            return
        
        logger.info(f"Processing Modbus logs from {log_file}")
        
        with open(log_file, 'r') as f:
            for line_num, line in enumerate(f, 1):
                try:
                    packet_data = json.loads(line.strip())
                    
                    # Normalize packet data
                    normalized_packet = {
                        'timestamp': packet_data.get('timestamp', datetime.now().isoformat()),
                        'source_ip': packet_data.get('source_ip', 'unknown'),
                        'dest_ip': packet_data.get('dest_ip', 'unknown'),
                        'operation': packet_data.get('operation', 'read'),
                        'function_code': packet_data.get('function_code', ''),
                        'register': packet_data.get('register'),
                        'value': packet_data.get('value'),
                        'direction': packet_data.get('direction', 'unknown')
                    }
                    
                    # Process packet through rule engine
                    alerts = rule_engine.process_packet(normalized_packet)
                    
                    if alerts:
                        logger.info(f"Line {line_num}: Generated {len(alerts)} alerts")
                    
                    # Log processing every 1000 packets
                    if line_num % 1000 == 0:
                        stats = rule_engine.get_stats()
                        logger.info(f"Processed {stats['packets_processed']} packets, "
                                  f"Generated {stats['alerts_generated']} alerts")
                
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    logger.error(f"Error processing line {line_num}: {e}")
                    continue
        
        logger.info(f"Completed processing {line_num} packets")
        stats = rule_engine.get_stats()
        logger.info(f"Final stats: {stats}")
        
    except FileNotFoundError:
        logger.error(f"Log file {log_file} not found")
    except Exception as e:
        logger.error(f"Error processing logs: {e}")
async def main():
    """Main entry point for the Modbus rule engine."""
    
    logger.info("Starting Modbus Security Rule Engine")
    
    # Create rule engine
    rule_engine = ModbusRuleEngine()
    
    # Configure rule options
    rule_engine.rules = {
        'function_code_anomaly': True,
        'value_anomaly': True,
        'source_ip_anomaly': True,
        'timing_anomaly': True,
        'pattern_anomaly': True,
        'safety_critical_violation': True,
        'register_write_anomaly': True,
        'flooding_attack': True
    }
    
    # Process logs
    await process_modbus_logs(rule_engine, 'captured_packets.jsonl')
    
    # Export alerts
    rule_engine.export_alerts('security_alerts.json')
    
    # Print summary
    stats = rule_engine.get_stats()
    print(f"\n{'='*50}")
    print("SECURITY RULE ENGINE SUMMARY")
    print(f"{'='*50}")
    print(f"Packets processed: {stats['packets_processed']}")
    print(f"Alerts generated: {stats['alerts_generated']}")
    print(f"\nAlerts by type:")
    for alert_type, count in stats['rules_triggered'].items():
        print(f"  {alert_type}: {count}")
    
    print(f"\n{'='*50}")
if __name__ == '__main__':
    # Run the rule engine
    asyncio.run(main())
