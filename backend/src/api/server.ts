import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createServer } from 'http';
import { Server } from 'socket.io';
import fetch from 'node-fetch';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;

// Setup HTTP Server and Socket.io
export const httpServer = createServer(app);
export const io = new Server(httpServer, {
  cors: { origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE'] },
});

app.use(cors());
app.use(express.json({ limit: '50mb' }));

// ── Alert API Routes ──
app.get('/api/alerts', (req, res) => {
  try {
    const { severity, type, hours } = req.query;
    
    // Import and run rule engine
    import('./ruleEngine.js');
    
    // For now, return mock data
    const alerts = generateMockAlerts();
    
    // Apply filters
    let filtered = alerts;
    if (severity) filtered = filtered.filter(a => a.severity === severity);
    if (type) filtered = filtered.filter(a => a.type === type);
    
    res.json({
      success: true,
      count: filtered.length,
      alerts: filtered
    });
  } catch (error) {
    console.error('Error fetching alerts:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch alerts'
    });
  }
});

app.get('/api/alerts/:id', (req, res) => {
  res.json({
    success: true,
    alert: { id: req.params.id, message: `Alert ${req.params.id}`, type: 'test' }
  });
});

app.post('/api/alerts/:id/read', (req, res) => {
  res.json({
    success: true,
    message: `Alert ${req.params.id} marked as read`
  });
});

app.get('/api/stats', (req, res) => {
  res.json({
    success: true,
    stats: {
      total_alerts: 1250,
      critical_alerts: 45,
      high_alerts: 125,
      recent_alerts: 15,
      active_attacks: 3,
      capture_status: 'running'
    }
  });
});

// Active assets database (in-memory simulation)
let simulationAssets = [
  { ip: '10.0.1.1', type: 'hmi', status: 'ok', first_seen: new Date(Date.now() - 3600000).toISOString(), last_seen: new Date().toISOString(), function_codes: ['0x03', '0x06'], total_packets: 1240, os_profile: 'VxWorks', vendor: 'Schneider Electric', model: 'Modicon M221', firmware_version: 'v1.4' },
  { ip: '10.0.1.2', type: 'hmi', status: 'ok', first_seen: new Date(Date.now() - 7200000).toISOString(), last_seen: new Date().toISOString(), function_codes: ['0x03'], total_packets: 890, os_profile: 'Linux', vendor: 'Siemens', model: 'SIMATIC HMI', firmware_version: 'v2.1' },
  { ip: '10.0.1.10', type: 'plc', status: 'ok', first_seen: new Date(Date.now() - 7200000).toISOString(), last_seen: new Date().toISOString(), function_codes: [], total_packets: 2130, os_profile: 'VxWorks', vendor: 'Siemens', model: 'S7-1200', firmware_version: 'v4.2' },
  { ip: '192.168.1.100', type: 'attacker', status: 'attacking', first_seen: new Date(Date.now() - 900000).toISOString(), last_seen: new Date().toISOString(), function_codes: ['0x03', '0x06', '0x17', '0x08'], total_packets: 450, os_profile: 'Linux', vendor: 'Unknown', model: 'Penetration Toolkit', firmware_version: 'v9.9' }
];

let blockedIps = new Set<string>();

// ── Asset Inventory ──
app.get('/api/assets', (req, res) => {
  res.json({
    success: true,
    assets: simulationAssets
  });
});

app.post('/api/assets/scan', (req, res) => {
  const newAsset = {
    ip: '10.0.1.20',
    type: 'plc',
    status: 'ok',
    first_seen: new Date().toISOString(),
    last_seen: new Date().toISOString(),
    function_codes: ['0x03'],
    total_packets: 15,
    os_profile: 'VxWorks',
    vendor: 'Rockwell Automation',
    model: 'ControlLogix 5580',
    firmware_version: 'v32.011'
  };
  
  if (!simulationAssets.some(a => a.ip === '10.0.1.20')) {
    simulationAssets.push(newAsset);
  }
  
  simulationAssets = simulationAssets.map(asset => {
    if (asset.ip === '10.0.1.10') {
      return { ...asset, firmware_version: 'v4.5' };
    }
    return asset;
  });

  res.json({
    success: true,
    message: 'Active scan completed successfully',
    scanned_count: simulationAssets.length,
    assets: simulationAssets
  });
});

app.post('/api/soar/release', (req, res) => {
  const { ip } = req.body;
  if (!ip) {
    return res.status(400).json({ success: false, error: 'IP address is required' });
  }
  
  blockedIps.delete(ip);
  
  simulationAssets = simulationAssets.map(asset => {
    if (asset.ip === ip) {
      return { ...asset, status: 'ok', type: 'unknown' };
    }
    return asset;
  });
  
  res.json({
    success: true,
    message: `Released IP ${ip} from containment`,
    ip
  });
});

// ── Network Topology ──
app.get('/api/topology', (req, res) => {
  res.json({
    success: true,
    nodes: [
      { id: 'plc', ip: '10.0.1.10', type: 'plc', status: 'ok', label: 'PLC Server' },
      { id: 'hmi1', ip: '10.0.1.1', type: 'hmi', status: 'ok', label: 'HMI Client 1' },
      { id: 'hmi2', ip: '10.0.1.2', type: 'hmi', status: 'ok', label: 'HMI Client 2' },
      { id: 'atk', ip: '192.168.1.100', type: 'attacker', status: 'attacking', label: 'ATTACKER' }
    ],
    edges: [
      { source: 'hmi1', target: 'plc', protocol: 'Modbus/TCP', port: 502, active: true },
      { source: 'hmi2', target: 'plc', protocol: 'Modbus/TCP', port: 502, active: true },
      { source: 'atk', target: 'plc', protocol: 'Modbus/TCP', port: 502, active: true, malicious: true }
    ]
  });
});

// ── Alert Lifecycle ──
app.post('/api/alerts/:id/acknowledge', (req, res) => {
  res.json({ success: true, alert_id: req.params.id, state: 'acknowledged', timestamp: new Date().toISOString() });
});

app.post('/api/alerts/:id/mute', (req, res) => {
  const { duration_minutes = 15 } = req.body;
  res.json({ success: true, alert_id: req.params.id, state: 'muted', muted_until: new Date(Date.now() + duration_minutes * 60000).toISOString() });
});

app.post('/api/alerts/:id/escalate', (req, res) => {
  res.json({ success: true, alert_id: req.params.id, state: 'escalated', timestamp: new Date().toISOString() });
});

// ── HMAC Authorization ──
app.post('/api/hmac/authorize', (req, res) => {
  const { register, value, client_id } = req.body;
  const token = require('crypto').createHmac('sha256', process.env.HMAC_SECRET || 'maritime-demo-secret')
    .update(`${register}:${value}:${client_id}:${Date.now()}`).digest('hex');
  res.json({ success: true, token, expires_at: new Date(Date.now() + 30000).toISOString(), register, value });
});

app.post('/api/hmac/verify', (req, res) => {
  const { token } = req.body;
  res.json({ success: true, valid: !!token, token });
});

// ── Incident Reports ──
app.get('/api/incidents', (req, res) => {
  res.json({ success: true, reports: [], message: 'Use TUI key i to generate a report' });
});

// ── Historical Replay ──
app.post('/api/replay/start', (req, res) => {
  const { file, speed = 1.0 } = req.body;
  res.json({ success: true, status: 'started', file, speed, message: 'Replay started' });
});

app.get('/api/replay/status', (req, res) => {
  res.json({ success: true, is_replaying: false, progress: 0.0, total_packets: 0, replayed_packets: 0 });
});

// ── Firmware Integrity ──
app.get('/api/firmware/status', (req, res) => {
  res.json({ success: true, is_healthy: true, last_check: new Date().toISOString(), hash: 'sha256:demo', check_count: 0 });
});

app.get('/api/system/health', (req, res) => {
  res.json({
    success: true,
    system: {
      status: 'healthy',
      uptime: '2h 15m',
      components: {
        'Modbus Server': 'running',
        'Packet Capture': 'running',
        'Rule Engine': 'running',
        'API Server': 'running'
      },
      last_check: new Date().toISOString()
    }
  });
});

// ── WebSocket for real-time alerts ──
io.on('connection', (socket) => {
  console.log('[Alert API] Client connected:', socket.id);
  
  socket.on('join_team', (teamId) => {
    socket.join(`team_${teamId}`);
    console.log(`[Alert API] Client ${socket.id} joined team_${teamId}`);
  });
  
  socket.on('alert_acknowledgment', (alertId) => {
    console.log(`[Alert API] Alert ${alertId} acknowledged by ${socket.id}`);
  });
  
  socket.on('disconnect', () => {
    console.log('[Alert API] Client disconnected:', socket.id);
  });
});

// Helper function for mock alerts
function generateMockAlerts() {
  const alertTypes = ['function_code_anomaly', 'value_anomaly', 'source_ip_anomaly', 'safety_critical_violation'];
  const severities = ['critical', 'high', 'warning', 'info'];
  const messages = [
    'Unauthorized function code detected',
    'Value anomaly in register 40001',
    'Unknown source IP accessing system',
    'Safety critical register compromised'
  ];
  
  const alerts = [];
  for (let i = 0; i < 50; i++) {
    alerts.push({
      id: `alert_${Date.now()}_${i}`,
      timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString(),
      type: alertTypes[Math.floor(Math.random() * alertTypes.length)],
      severity: severities[Math.floor(Math.random() * severities.length)],
      message: messages[Math.floor(Math.random() * messages.length)],
      source_ip: `192.168.1.${Math.floor(Math.random() * 255)}`,
      register: Math.floor(Math.random() * 100) + 40000,
      function_code: `0x${Math.floor(Math.random() * 255).toString(16).padStart(2, '0')}`,
      is_read: false
    });
  }
  
  return alerts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
}

httpServer.listen(PORT, () => {
  console.log(`\n  🚀 MariTime Alert API Server running on http://localhost:${PORT}`);
});
