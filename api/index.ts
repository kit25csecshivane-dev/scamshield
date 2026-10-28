/**
 * Vercel Serverless Function Handler
 * Automatically detected and executed by Vercel for /api/* routes
 */

import { createServerApp } from '../src/serverApp.js';

const app = createServerApp();

export default app;
