/**
 * PhishGuard Express Application Core
 * Shared between standalone server (server.ts) and Vercel serverless function (api/index.ts)
 */

import express from 'express';
import dotenv from 'dotenv';
import { analyzeThreatWithGemini } from './services/geminiService.js';
import { BASELINE_MODEL_METRICS, predictBaseline } from './services/mlBaseline.js';
import { getAllScans, getScanById, saveScan, deleteScan, toggleStarScan, getStats } from './services/storageService.js';
import { parseUrlSafely } from './services/heuristicAnalyzer.js';

dotenv.config();

export function createServerApp() {
  const app = express();

  // CORS Middleware for universal deployment compatibility
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    if (req.method === 'OPTIONS') {
      return res.sendStatus(200);
    }
    next();
  });

  // Body parsing with size guards
  app.use(express.json({ limit: '2mb' }));
  app.use(express.urlencoded({ extended: true, limit: '2mb' }));

  // In-memory rate limiter per IP
  const requestCounts = new Map<string, { count: number; resetAt: number }>();
  function rateLimiter(req: express.Request, res: express.Response, next: express.NextFunction) {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const record = requestCounts.get(ip);

    if (!record || now > record.resetAt) {
      requestCounts.set(ip, { count: 1, resetAt: now + 60 * 1000 });
      return next();
    }

    if (record.count >= 100) {
      return res.status(429).json({
        error: 'Rate limit exceeded. Please wait a minute before running more threat scans.'
      });
    }

    record.count++;
    next();
  }

  const apiRouter = express.Router();
  apiRouter.use(rateLimiter);

  // 1. Health check endpoint
  apiRouter.get('/health', (req, res) => {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      geminiConfigured: !!process.env.GEMINI_API_KEY,
      storageStatus: 'connected',
      environment: process.env.VERCEL ? 'vercel-serverless' : 'node-runtime',
      modelVersion: 'gemini-3.8-flash + PhishGuard-LR-v2.4'
    });
  });

  // 2. Scan URL Endpoint
  apiRouter.post('/scan/url', async (req, res) => {
    try {
      const { url } = req.body || {};
      if (!url || typeof url !== 'string') {
        return res.status(400).json({ error: 'A valid URL string is required.' });
      }

      const trimmed = url.trim();
      if (trimmed.length > 2048) {
        return res.status(400).json({ error: 'URL exceeds maximum length of 2048 characters.' });
      }

      // Safety validation
      const parsed = parseUrlSafely(trimmed);
      if (!parsed.isValid) {
        return res.status(400).json({ error: 'Invalid URL syntax. Please enter a valid web address.' });
      }

      // Run Dual-Engine Analysis
      const scanResult = await analyzeThreatWithGemini(trimmed, 'url');
      
      // Persist scan to history
      saveScan(scanResult);

      res.json(scanResult);
    } catch (err: any) {
      console.error('URL Scan error:', err);
      res.status(500).json({
        error: 'An unexpected error occurred during threat scanning.',
        details: err?.message || 'Internal server error'
      });
    }
  });

  // 3. Scan Message Endpoint (Email / SMS / Chat)
  apiRouter.post('/scan/message', async (req, res) => {
    try {
      const { message, subtype } = req.body || {};
      if (!message || typeof message !== 'string') {
        return res.status(400).json({ error: 'A valid message string is required.' });
      }

      const trimmed = message.trim();
      if (trimmed.length < 5) {
        return res.status(400).json({ error: 'Message content is too short for threat pattern extraction.' });
      }
      if (trimmed.length > 30000) {
        return res.status(400).json({ error: 'Message exceeds maximum length of 30,000 characters.' });
      }

      const validSubtype = ['email', 'sms', 'chat'].includes(subtype) ? subtype : 'email';

      // Run Dual-Engine Analysis
      const scanResult = await analyzeThreatWithGemini(trimmed, 'message', validSubtype);

      // Persist scan to history
      saveScan(scanResult);

      res.json(scanResult);
    } catch (err: any) {
      console.error('Message Scan error:', err);
      res.status(500).json({
        error: 'An unexpected error occurred during message scanning.',
        details: err?.message || 'Internal server error'
      });
    }
  });

  // 4. ML Benchmark Data
  apiRouter.get('/ml/benchmark', (req, res) => {
    res.json(BASELINE_MODEL_METRICS);
  });

  // 5. Predict via pure Baseline ML Model (without AI call)
  apiRouter.post('/ml/predict', (req, res) => {
    try {
      const { target, isUrl } = req.body || {};
      if (!target || typeof target !== 'string') {
        return res.status(400).json({ error: 'Target string is required' });
      }
      const prediction = predictBaseline(target, !!isUrl);
      res.json(prediction);
    } catch (err: any) {
      res.status(500).json({ error: err?.message });
    }
  });

  // 6. Get All Scans / Filter History
  apiRouter.get('/scans', (req, res) => {
    try {
      const { search, type, verdict, starred } = req.query;
      const scans = getAllScans({
        search: typeof search === 'string' ? search : undefined,
        type: (type === 'url' || type === 'message') ? type : undefined,
        verdict: typeof verdict === 'string' ? verdict : undefined,
        starredOnly: starred === 'true'
      });
      res.json(scans);
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to retrieve scan history' });
    }
  });

  // 7. Get Single Scan Details
  apiRouter.get('/scans/:id', (req, res) => {
    const scan = getScanById(req.params.id);
    if (!scan) {
      return res.status(404).json({ error: 'Scan record not found' });
    }
    res.json(scan);
  });

  // 8. Delete Scan
  apiRouter.delete('/scans/:id', (req, res) => {
    const success = deleteScan(req.params.id);
    if (!success) {
      return res.status(404).json({ error: 'Scan record not found' });
    }
    res.json({ success: true, message: 'Scan record deleted.' });
  });

  // 9. Toggle Star Scan
  apiRouter.post('/scans/:id/star', (req, res) => {
    const updated = toggleStarScan(req.params.id);
    if (!updated) {
      return res.status(404).json({ error: 'Scan record not found' });
    }
    res.json(updated);
  });

  // 10. Dashboard Telemetry & Aggregate Stats
  apiRouter.get('/stats', (req, res) => {
    try {
      const stats = getStats();
      res.json(stats);
    } catch (err: any) {
      res.status(500).json({ error: 'Failed to compute dashboard metrics' });
    }
  });

  // Dual-mount router to seamlessly handle both `/api/*` and direct `/*` rewrites on Vercel
  app.use('/api', apiRouter);
  app.use('/', apiRouter);

  return app;
}
