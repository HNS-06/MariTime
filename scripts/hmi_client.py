#!/usr/bin/env python3
"""
LEGITIMATE HMI CLIENT - Modbus Traffic Generator

This script simulates a Human-Machine Interface (HMI) client that communicates
with the PLC using normal Modbus/TCP operations. This represents legitimate
industrial traffic for baseline modeling.

HMI Behavior Pattern:
- Read holding registers every 2 seconds (monitoring)
- Write to control registers only during scheduled shift changes (hourly)
- Use only function codes 0x03 (Read Holding Registers) for normal operation
- Never write to safety-critical registers during regular operation

Register Access Strategy:
- MONITORING (READ only): 40001 (pump speed), 40003 (temperature), 40004 (pressure)
- CONTROL (WRITE only during shifts): 40002 (valve position), 40005 (flow rate)
- SAFETY (WRITE NEVER): 40006 (alarm status)
"""

import asyncio
import pymodbus
from pymodbus.client import AsyncModbusTcpClient
from pymodbus.exceptions import ModbusIOException
import logging
import random
import json
from datetime import datetime
from typing import Dict, List
import signal
import os
import sys
sys.path.insert(0, os.path.dirname(__file__))
try:
    from hmac_auth import HMACAuthManager
    _HMAC_MANAGER = HMACAuthManager()
except ImportError:
    _HMAC_MANAGER = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('hmi_client.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('hmi_client')

# Register map for HMI operations
HMI_REGISTERS = {
    "monitor": {
        "registers": [40001, 40003, 40004],  # pump_speed, temperature, pressure
        "function_code": 0x03,
        "description": "Monitoring sensors - READ only"
    },
    "control": {
        "registers": [40002, 40005],        # valve_position, flow_rate
        "function_code": 0x06,             # Write Single Register
        "description": "Control parameters - WRITE during shifts"
    },
    "safety": {
        "registers": [40006],               # alarm_status
        "function_code": 0x06,
        "description": "Safety registers - NEVER write"
    }
}

class HMIClient:
    """Human-Machine Interface client simulating legitimate industrial traffic."""
    
    def __init__(self, host: str = '127.0.0.1', port: int = 502, station_id: int = 1):
        self.host = host
        self.port = port
        self.station_id = station_id
        self.client = None
        self.running = True
        self.log_file = open('hmi_traffic.log', 'a')
        
        # Register operation counters (for baseline modeling)
        self.operation_counts = {
            "read": 0,
            "write": 0,
            "success": 0,
            "failed": 0
        }
        
        # Track last shift change time (24-hour cycle)
        self.shift_change_time = 6  # 6 AM
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.running = False
    
    def log_transaction(self, operation_type: str, function_code: int, 
                       register: int, value: int = None, success: bool = True, error: str = ""):
        """Log HMI client transactions for baseline modeling."""
        timestamp = datetime.now().isoformat()
        transaction = {
            "timestamp": timestamp,
            "operation": operation_type,
            "client_id": self.station_id,
            "function_code": f"0x{function_code:02x}",
            "register": register,
            "value": value,
            "success": success,
            "error": error
        }
        
        log_entry = json.dumps(transaction) + "\n"
        self.log_file.write(log_entry)
        self.log_file.flush()
        
        # Update operation counters
        if success:
            self.operation_counts["success"] += 1
        else:
            self.operation_counts["failed"] += 1
            
        if operation_type.lower() == "read":
            self.operation_counts["read"] += 1
            logger.info(f"✓ Read Reg {register} (Function 0x{function_code:02x}) = {value}")
        elif operation_type.lower() == "write":
            self.operation_counts["write"] += 1
            logger.info(f"✓ Write Reg {register} (Function 0x{function_code:02x}) = {value}")
    
    def is_shift_change_hour(self, current_hour: int) -> bool:
        """Check if current time is within shift change window (0.5 hour window)."""
        time_diff = abs(current_hour - self.shift_change_time)
        return time_diff <= 1  # Allow 1 hour before and after 6AM
    
    def get_normal_value(self, register: int) -> int:
        """Get normal/simulated values for registers."""
        if register == 40001:  # pump_speed
            return random.randint(45, 55)
        elif register == 40002:  # valve_position
            return random.randint(30, 70)
        elif register == 40003:  # temperature
            return random.randint(70, 80)  # In 10s scale: 70-80 = 70-80°C
        elif register == 40004:  # pressure
            return random.randint(3, 4)  # In 10s scale: 3-4 = 3.0-4.0 bar
        elif register == 40005:  # flow_rate
            return random.randint(50, 60)
        elif register == 40006:  # alarm_status
            return 0  # Normal: no alarms
        return 0
    
    async def connect(self) -> bool:
        """Connect to Modbus server."""
        try:
            self.client = AsyncModbusTcpClient(
                host=self.host,
                port=self.port,
                framer=pymodbus.framer.SOCKET,
                timeout=5
            )
            await self.client.connect()
            logger.info(f"Connected to Modbus server at {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Modbus server: {e}")
            return False
    
    async def read_monitoring_registers(self):
        """Read monitoring registers (sensors) - normal operation."""
        registers_to_read = [r for category in HMI_REGISTERS.values() 
                           for r in category["registers"] 
                           if category["description"].startswith("Monitoring")]
        
        if not registers_to_read:
            return
            
        for register in registers_to_read:
            try:
                # Read single register
                response = await self.client.read_holding_registers(
                    address=register,
                    count=1,
                    slave=self.station_id
                )
                
                if response.isError():
                    self.log_transaction("READ", 0x03, register, success=False, 
                                       error=f"Modbus error: {response}")
                    continue
                
                value = response.registers[0]
                self.log_transaction("READ", 0x03, register, value=value, success=True)
                
            except ModbusIOException as e:
                self.log_transaction("READ", 0x03, register, success=False, error=str(e))
            except Exception as e:
                self.log_transaction("READ", 0x03, register, success=False, error=str(e))
    
    async def write_control_registers(self):
        """Write to control registers - only during shift changes."""
        registers_to_write = [r for category in HMI_REGISTERS.values() 
                            for r in category["registers"] 
                            if category["description"].startswith("Control")]
        
        if not registers_to_write:
            return
            
        for register in registers_to_write:
            try:
                # Generate normal control values
                value = self.get_normal_value(register)

                # Pre-authorize write with HMAC token
                if _HMAC_MANAGER:
                    token_data = _HMAC_MANAGER.generate_token(register, value, str(self.station_id))
                    logger.debug(f'HMAC token generated for reg {register}: expires {token_data["expires_at"]}')

                # Write single register
                response = await self.client.write_register(
                    address=register,
                    value=value,
                    slave=self.station_id
                )
                
                if response.isError():
                    self.log_transaction("WRITE", 0x06, register, value=value, 
                                       success=False, error=f"Modbus error: {response}")
                    continue
                
                self.log_transaction("WRITE", 0x06, register, value=value, success=True)
                
            except ModbusIOException as e:
                self.log_transaction("WRITE", 0x06, register, success=False, error=str(e))
            except Exception as e:
                self.log_transaction("WRITE", 0x06, register, success=False, error=str(e))
    
    async def run(self):
        """Main HMI client loop."""
        logger.info("Starting HMI client (Legitimate Traffic Generator)")
        logger.info(f"Baseline pattern: Read every 2s, Write only during shift changes (hour {self.shift_change_time})")
        
        if not await self.connect():
            return
        
        cycle_count = 0
        while self.running:
            current_hour = datetime.now().hour
            is_shift_change = self.is_shift_change_hour(current_hour)
            
            # Always read monitoring registers
            await self.read_monitoring_registers()
            
            # Write control registers only during shift changes
            if is_shift_change:
                logger.info(f"Shift change detected (current hour: {current_hour}), updating control registers")
                await self.write_control_registers()
            else:
                logger.debug(f"Normal operation (current hour: {current_hour}), no writes")
            
            # Log baseline statistics every 10 cycles
            cycle_count += 1
            if cycle_count % 10 == 0:
                logger.info(f"Baseline stats: "
                           f"Reads={self.operation_counts['read']}, "
                           f"Writes={self.operation_counts['write']}, "
                           f"Success={self.operation_counts['success']}, "
                           f"Failed={self.operation_counts['failed']}")
            
            await asyncio.sleep(2)  # 2-second polling cycle
        
        await self.disconnect()
    
    async def disconnect(self):
        """Disconnect from Modbus server."""
        if self.client:
            await self.client.close()
            logger.info("Disconnected from Modbus server")
        
        if hasattr(self, 'log_file') and not self.log_file.closed:
            self.log_file.write(f"\n=== HMI CLIENT SUMMARY ===\n")
            self.log_file.write(f"Total successful transactions: {self.operation_counts['success']}\n")
            self.log_file.write(f"Total failed transactions: {self.operation_counts['failed']}\n")
            self.log_file.write(f"READ operations: {self.operation_counts['read']}\n")
            self.log_file.write(f"WRITE operations: {self.operation_counts['write']}\n")
            self.log_file.close()
            
        logger.info("HMI client shutdown complete")
async def main():
    """Main entry point for HMI client."""
    
    # Create and run HMI client
    hmi_client = HMIClient(host='127.0.0.1', port=502)
    
    try:
        await hmi_client.run()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received, shutting down...")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
    finally:
        if hasattr(hmi_client, 'client') and hmi_client.client:
            await hmi_client.disconnect()
if __name__ == '__main__':
    # Run the HMI client
    asyncio.run(main())
