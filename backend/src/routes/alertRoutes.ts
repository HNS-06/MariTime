import express from 'express';
const router = express.Router();

// Test rule engine integration
router.get('/test', (req, res) => {
  res.json({
    success: true,
    message: 'Alert API is working correctly',
    timestamp: new Date().toISOString()
  });
});

export default router;
