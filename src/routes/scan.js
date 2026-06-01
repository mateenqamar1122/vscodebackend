const express = require('express');
const { z } = require('zod');
const { analyseCode } = require('../services/openaiService');
const { vectorSearchVulnPatterns } = require('../services/vectorSearch');
const { supabaseAdmin } = require('../config/supabase');
const logger = require('../utils/logger');
const { v4: uuidv4 } = require('uuid');

const router = express.Router();

// ── Validation Schemas ─────────────────────────────────────────────────────────
const ScanRequestSchema = z.object({
  code: z.string().min(1).max(100000),
  language: z.string().min(1).max(50),
  filePath: z.string().optional(),
  sessionId: z.string().optional(),
});

// ── POST /api/scan/code ────────────────────────────────────────────────────────
router.post('/code', async (req, res) => {
  const parsed = ScanRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid request', details: parsed.error.flatten() });
  }

  const { code, language, filePath, sessionId } = parsed.data;

  try {
    // Run AI analysis
    const analysis = await analyseCode({ code, language, filePath });

    // Enhance with vector-matched patterns
    if (analysis.vulnerabilities?.length) {
      for (const vuln of analysis.vulnerabilities) {
        const patterns = await vectorSearchVulnPatterns(
          `${vuln.category} ${vuln.title} ${vuln.description}`,
          { threshold: 0.75, limit: 2 }
        );
        vuln.relatedPatterns = patterns;
      }
    }

    // Save scan to history
    const scanId = uuidv4();
    const { error: dbErr } = await supabaseAdmin.from('scan_history').insert({
      id: scanId,
      session_id: sessionId || null,
      file_path: filePath || null,
      language,
      code_hash: Buffer.from(code).toString('base64').slice(0, 64),
      result: analysis,
      vulnerability_count: analysis.summary?.total || 0,
      secure_score: analysis.secure_score || 0,
      created_at: new Date().toISOString(),
    });

    if (dbErr) {
      logger.warn('Failed to save scan history', { error: dbErr.message });
    }

    return res.json({ scanId, ...analysis });
  } catch (err) {
    logger.error('Code scan failed', { error: err.message });
    return res.status(500).json({ error: err.message });
  }
});

// ── GET /api/scan/history ──────────────────────────────────────────────────────
router.get('/history', async (req, res) => {
  const { sessionId, limit = 20, offset = 0 } = req.query;

  let query = supabaseAdmin
    .from('scan_history')
    .select('id, file_path, language, vulnerability_count, secure_score, created_at')
    .order('created_at', { ascending: false })
    .range(Number(offset), Number(offset) + Number(limit) - 1);

  if (sessionId) {
    query = query.eq('session_id', sessionId);
  }

  const { data, error, count } = await query;
  if (error) return res.status(500).json({ error: error.message });

  return res.json({ history: data, total: count });
});

// ── GET /api/scan/:id ──────────────────────────────────────────────────────────
router.get('/:id', async (req, res) => {
  const { data, error } = await supabaseAdmin
    .from('scan_history')
    .select('*')
    .eq('id', req.params.id)
    .single();

  if (error || !data) return res.status(404).json({ error: 'Scan not found' });

  return res.json(data);
});

module.exports = router;
