#!/usr/bin/env python3
"""
SIMULATED PLC SERVER - Modbus/TCP Server

This script simulates an industrial PLC (Programmable Logic Controller) using pymodbus.
It provides a fake OT environment with realistic register maps that can be read/written by HMI clients.

Register Map:
- 40001: Pump speed (0-100)
- 40002: Valve position (0-100)  
- 40003: Temperature sensor (0-150°C)
- 40004: Pressure sensor (0-10 bar)
- 40005: Flow rate (0-100%)
- 40006: Alarm status (0-999)

Function Code Support:
- 0x03: Read Holding Registers
- 0x06: Write Single Register (requires authentication in real systems)
- 0x10: Write Multiple Registers
"""

import logging
import random
import time
from datetime import datetime
from pymodbus.server.async_io import StartAsyncServer
from pymodbus.factory import ClientDecoder
from pymodbus.exceptions import ModbusIOException
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
from pymodbus.datastore import DefaultModbusContext
from pymodbus.pdu import ExceptionResponse
import json
from typing import Dict, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('plc_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('plc_server')
class PLCRegisterSimulator:
    """Simulates a PLC with realistic register values and drift."""
    
    def __init__(self):
        self.registers = {
            40001: {"value": 50, "name": "pump_speed", "min": 0, "max": 100, "unit": "%", "description": "Pump speed percentage"},
            40002: {"value": 0, "name": "valve_position", "min": 0, "max": 100, "unit": "%", "description": "Valve opening percentage"},
            40003: {"value": 75.0, "name": "temperature", "min": 0, "max": 150, "unit": "°C", "description": "Temperature sensor reading"},
            40004: {"value": 3.5, "name": "pressure", "min": 0, "max": 10, "unit": "bar", "description": "Pressure sensor reading"},
            40005: {"value": 60, "name": "flow_rate", "min": 0, "max": 100, "unit": "%", "description": "Flow rate percentage"},
            40006: {"value": 0, "name": "alarm_status", "min": 0, "max": 999, "unit": "count", "description": "Number of active alarms"},
        }
        self.log_file = open('plc_traffic.log', 'a')
        self._sensor_drift_simulation()
    
    def _sensor_drift_simulation(self):
        """Simulate natural sensor drift and variations."""
        # Simulate occasional sensor fluctuations
        import random
        
        for reg_id, reg_info in self.registers.items():
            if reg_info["name"] in ["temperature", "pressure", "flow_rate"]:
                # Add small noise to sensor readings
                noise = random.uniform(-0.5, 0.5)
                reg_info["value"] = round(min(max(reg_info["value"] + noise, reg_info["min"]), reg_info["max"]), 1)
    
    def log_transaction(self, client_ip: str, function_code: int, start_reg: int, 
                       values: list, write: bool = False, success: bool = True, error_msg: str = ""):
        """Log all Modbus transactions for audit trail."""
        timestamp = datetime.now().isoformat()
        transaction = {
            "timestamp": timestamp,
            "client_ip": client_ip,
            "function_code": f"0x{function_code:02x}",
            "start_register": start_reg,
            "values": values,
            "write": write,
            "success": success,
            "error_message": error_msg
        }
        
        log_entry = json.dumps(transaction) + "\n"
        self.log_file.write(log_entry)
        self.log_file.flush()
        
        if write:
            action = "WRITE"
        else:
            action = "READ"
            
        status = "✓" if success else "✗"
        logger.info(f"{status} {action} from {client_ip}: Function 0x{function_code:02x}, "
                   f"Start Reg {start_reg}, Values: {values}")
    
    def read_holding_registers(self, start: int, count: int) -> list:
        """Read holding registers with simulated values."""
        values = []
        for i in range(start, start + count):
            if i in self.registers:
                values.append(int(self.registers[i]["value"]))
            else:
                values.append(0)
        return values
    
    def write_single_register(self, address: int, value: int) -> bool:
        """Write to a single register with validation."""
        if address not in self.registers:
            return False
            
        reg_info = self.registers[address]
        if not (reg_info["min"] <= value <= reg_info["max"]):
            logger.warning(f"Value {value} for {reg_info['name']} outside range "
                         f"[{reg_info['min']}, {reg_info['max']}]")
            return False
            
        reg_info["value"] = value
        logger.info(f"Successfully wrote {value} to {reg_info['name']} ({address})")
        return True

    def close(self):
        """Clean up resources."""
        if hasattr(self, 'log_file') and not self.log_file.closed:
            self.log_file.close()
class CustomModbusRequestHandler:
    """Custom Modbus handler to log all transactions."""
    
    def __init__(self, plc_simulator: PLCRegisterSimulator):
        self.plc_simulator = plc_simulator
    
    async def handle_request(self, request, client_address, server):
        """Process Modbus requests with logging."""
        try:
            decoder = ClientDecoder()
            method = decoder.lookupPduClass(request)
            
            if not method:
                logger.warning(f"Unknown request from {client_address}: {request}")
                return False
            
            if method.__name__ == 'ReadHoldingRegistersRequest':
                return await self._handle_read_holding_registers(request, client_address)
            elif method.__name__ == 'WriteSingleRegisterRequest':
                return await self._handle_write_single_register(request, client_address)
            elif method.__name__ == 'WriteMultipleRegistersRequest':
                return await self._handle_write_multiple_registers(request, client_address)
            else:
                logger.info(f"Unsupported method {method.__name__} from {client_address}")
                return False
                
        except Exception as e:
            logger.error(f"Error handling request from {client_address}: {e}")
            return False
    
    async def _handle_read_holding_registers(self, request, client_address):
        """Handle register read requests."""
        start_addr = request.startingAddress
        count = request.quantityOfRegisters
        
        values = self.plc_simulator.read_holding_registers(start_addr, count)
        self.plc_simulator.log_transaction(
            str(client_address), 0x03, start_addr, values, write=False, success=True
        )
        return values
    
    async def _handle_write_single_register(self, request, client_address):
        """Handle single register write requests."""
        address = request.address
        value = request.value
        
        success = self.plc_simulator.write_single_register(address, value)
        self.plc_simulator.log_transaction(
            str(client_address), 0x06, address, [value], write=True, success=success
        )
        return success
    
    async def _handle_write_multiple_registers(self, request, client_address):
        """Handle multiple register write requests."""
        start_addr = request.startingAddress
        values = request.values
        
        success_count = 0
        for i, value in enumerate(values):
            addr = start_addr + i
            if self.plc_simulator.write_single_register(addr, value):
                success_count += 1
        
        all_success = success_count == len(values)
        self.plc_simulator.log_transaction(
            str(client_address), 0x10, start_addr, values, write=True, success=all_success
        )
        return all_success
async def start_plc_server():
    """Start the Modbus TCP server."""
    
    logger.info("Initializing PLC Simulator for Modbus/TCP")
    logger.info("Register Map:")
    plc_simulator = PLCRegisterSimulator()
    
    for reg_id, reg_info in plc_simulator.registers.items():
        logger.info(f"  {reg_id}: {reg_info['name']} "
                   f"(Range: {reg_info['min']}-{reg_info['max']} {reg_info['unit']}) "
                   f"Initial: {reg_info['value']}")
    
    logger.info("Modbus server will listen on port 502")
    
    # Setup Modbus store
    store = DefaultModbusContext(
        di=ModbusSlaveContext(ModbusSequentialDataBlock(0, [0] * 65536)),
        co=ModbusSlaveContext(ModbusSequentialDataBlock(0, [0] * 65536)),
        hr=ModbusSlaveContext(ModbusSequentialDataBlock.from_ranges(
            [(addr, 1) for addr in plc_simulator.registers.keys()]
        )),
        ur=ModbusSlaveContext(ModbusSequentialDataBlock(0, [0] * 65536))
    )
    
    # Setup request handler
    handler = CustomModbusRequestHandler(plc_simulator)
    
    # Start server
    async with StartAsyncServer(
        store,
        port=502,
        address='0.0.0.0',
        custom_functions=[CustomModbusRequestHandler],
        protocol=ClientDecoder()
    ) as server:
        logger.info("Modbus PLC server started successfully")
        logger.info("Press Ctrl+C to stop the server")
        
        try:
            await server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Server shutting down...")
        finally:
            plc_simulator.close()
if __name__ == '__main__':
    import asyncio
    asyncio.run(start_plc_server())
