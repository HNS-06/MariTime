import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { createServer } from 'http';
import { Server } from 'socket.io';
import alertRoutes from './routes/alertRoutes';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Setup HTTP Server and Socket.io
export const httpServer = createServer(app);
export const io = new Server(httpServer, {
  cors: { origin: '*', methods: ['GET', 'POST', 'PUT', 'DELETE'] },
});

app.use(cors());
app.use(express.json());

// ── Alert Routes ──
app.use('/api/alerts', alertRoutes);

// ── WebSocket for real-time alerts ──
io.on('connection', (socket) => {
  console.log('[Alert Server] Client connected:', socket.id);
  socket.on('disconnect', () => console.log('[Alert Server] Client disconnected:', socket.id));
});

httpServer.listen(PORT, () => {
  console.log(`\n  🚀 MariTime Alert Server running on http://localhost:${PORT}`);
});
