// /backend/src/routes/oauthRoutes.ts
import express from 'express';
import { oauthController } from '../controllers/oauthController';

const router = express.Router();

// Initiate OAuth flow
router.get('/:provider/authorize', oauthController.authorize);

// Handle OAuth callback
router.get('/:provider/callback', oauthController.callback);

export { router as oauthRoutes };