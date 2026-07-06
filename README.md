<<<<<<< HEAD
# MariTime
=======
MariTime Modbus Security Monitor

A complete OT/ICS security monitoring system with:
- Simulated PLC using pymodbus
- Legitimate traffic generation (HMI client)
- Attack traffic generation
- Packet capture and analysis
- Rule-based anomaly detection
- Real-time alert dashboard

## Architecture

┌─────────────────┐      Modbus/TCP       ┌──────────────────┐
│  Simulated PLC   │◄─────(port 502)──────►│  Clients (Attacker + Legit)  │
└────────┬─────────┘                       └──────────────────┘
         │ mirrored traffic
         ▼
┌──────────────────┐
│  Packet Capture   │  (tshark/pyshark, or Zeek)
└────────┬──────────┘
         ▼
┌──────────────────┐
│  Rules Engine      │  (Python) — parses Modbus function codes,
│  + Baseline model  │   register writes, timing, source IP
└────────┬──────────┘
         ▼
┌──────────────────┐
│  Alert Dashboard   │  (React/Express)
└──────────────────┘

## Getting Started

1. Clone the repository
2. Install dependencies in backend/
3. Start the Modbus server in another terminal
4. Run traffic generators
5. Access the dashboard at http://localhost:3000

## Quick Start

```bash
# In backend directory
cd backend
npm install
npm run dev

# In another terminal
python3 -m scripts.plc_server

# In another terminal
python3 scripts/hmi_client.py
```

## Development

- Modbus server runs on port 502
- Packet capture runs on port 8080
- Express API runs on port 3000
- React dashboard runs on port 5173

## Technical Details

The system simulates a real industrial plant with:
- Register 40001: Pump speed (normal range: 0-100)
- Register 40002: Valve position (normal range: 0-100)
- Register 40003: Temperature sensor (normal range: 0-150°C)
- Function codes: 0x03 (read holding registers), 0x06 (write single register)

The rule engine detects anomalies like:
- Unauthorized register writes
- Values outside expected ranges
- Timing anomalies
- Source IP-based whitelist/blacklist

## License

MIT
>>>>>>> 778619d (Intial Commit)
