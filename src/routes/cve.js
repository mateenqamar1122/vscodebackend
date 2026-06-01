const express = require('express');
const { z } = require('zod');
const { searchCVEs, getCVEById, auditDependencies } = require('../services/cveService');
const { vectorSearchCVEs } = require('../services/vectorSearch');
const logger = require('../utils/logger');

const router = express.Router();

// ── GET /api/cve/search ────────────────────────────────────────────────────────
router.get('/search', async (req, res) => {
  const { package: pkg, version, ecosystem = 'npm', q } = req.query;

  if (!pkg && !q) {
    return res.status(400).json({ error: 'Either "package" or "q" query parameter is required' });
  }

  try {
    let results;
    if (q) {
      // Semantic / vector search
      results = await vectorSearchCVEs(q, { threshold: 0.65, limit: 15 });
    } else {
      results = await searchCVEs({ packageName: pkg, version, ecosystem });
    }

    return res.json({ results, count: results.length });
  } catch (err) {
    logger.error('CVE search failed', { error: err.message });
    return res.status(500).json({ error: err.message });
  }
});

// ── GET /api/cve/:id ───────────────────────────────────────────────────────────
router.get('/:cveId', async (req, res) => {
  try {
    const cve = await getCVEById(req.params.cveId);
    if (!cve) return res.status(404).json({ error: `CVE ${req.params.cveId} not found` });
    return res.json(cve);
  } catch (err) {
    logger.error('CVE lookup failed', { error: err.message });
    return res.status(500).json({ error: err.message });
  }
});

// ── POST /api/cve/audit ────────────────────────────────────────────────────────
const AuditSchema = z.object({
  dependencies: z.record(z.string()),
  ecosystem: z.enum(['npm', 'pypi', 'maven', 'nuget', 'rubygems', 'cargo', 'go']),
});

router.post('/audit', async (req, res) => {
  const parsed = AuditSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid request', details: parsed.error.flatten() });
  }

  try {
    const results = await auditDependencies(parsed.data);
    const summary = {
      total_packages: Object.keys(parsed.data.dependencies).length,
      vulnerable_packages: results.length,
      critical: results.filter(r => r.maxSeverity === 'CRITICAL').length,
      high: results.filter(r => r.maxSeverity === 'HIGH').length,
      medium: results.filter(r => r.maxSeverity === 'MEDIUM').length,
      low: results.filter(r => r.maxSeverity === 'LOW').length,
    };

    return res.json({ summary, results });
  } catch (err) {
    logger.error('Dependency audit failed', { error: err.message });
    return res.status(500).json({ error: err.message });
  }
});

module.exports = router;
