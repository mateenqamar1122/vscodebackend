const express = require('express');
const { z } = require('zod');
const { securityChat } = require('../services/openaiService');
const logger = require('../utils/logger');

const router = express.Router();

const ChatSchema = z.object({
  messages: z.array(
    z.object({
      role: z.enum(['user', 'assistant']),
      content: z.string().min(1).max(10000),
    })
  ).min(1).max(20),
  context: z.any().optional(), // Scan result context
});

// ── POST /api/chat ─────────────────────────────────────────────────────────────
router.post('/', async (req, res) => {
  const parsed = ChatSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid request', details: parsed.error.flatten() });
  }

  try {
    const { messages, context } = parsed.data;
    const result = await securityChat({ messages, context });
    return res.json(result);
  } catch (err) {
    logger.error('Chat completion failed', { error: err.message });
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;
