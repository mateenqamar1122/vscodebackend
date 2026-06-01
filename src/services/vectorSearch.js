const { supabaseAdmin } = require('../config/supabase');
const { generateEmbedding } = require('./openaiService');
const logger = require('../utils/logger');

/**
 * Perform semantic vector search on CVE descriptions.
 * Uses Supabase pgvector via a stored RPC function.
 */
async function vectorSearchCVEs(queryText, options = {}) {
  const { threshold = 0.7, limit = 10, ecosystem } = options;

  logger.info(`Vector search: "${queryText.slice(0, 60)}..."`);

  const embedding = await generateEmbedding(queryText);

  const { data, error } = await supabaseAdmin.rpc('match_cves', {
    query_embedding: embedding,
    match_threshold: threshold,
    match_count: limit,
    filter_ecosystem: ecosystem || null,
  });

  if (error) {
    logger.error('Vector search RPC failed', { error: error.message });
    throw new Error(`Vector search failed: ${error.message}`);
  }

  return data || [];
}

/**
 * Search vulnerability patterns semantically.
 * Used to find relevant past scan results or known patterns.
 */
async function vectorSearchVulnPatterns(queryText, options = {}) {
  const { threshold = 0.7, limit = 5 } = options;

  const embedding = await generateEmbedding(queryText);

  const { data, error } = await supabaseAdmin.rpc('match_vuln_patterns', {
    query_embedding: embedding,
    match_threshold: threshold,
    match_count: limit,
  });

  if (error) {
    logger.warn('Vuln pattern vector search failed', { error: error.message });
    return [];
  }

  return data || [];
}

/**
 * Store a vulnerability pattern with its embedding for future searches.
 */
async function storeVulnPattern({ title, description, category, severity, recommendation, cwe }) {
  const text = `${title} ${description} ${category} ${cwe || ''}`;
  const embedding = await generateEmbedding(text);

  const { error } = await supabaseAdmin
    .from('vuln_patterns')
    .upsert({
      title,
      description,
      category,
      severity,
      recommendation,
      cwe,
      embedding,
      updated_at: new Date().toISOString(),
    }, { onConflict: 'cwe', ignoreDuplicates: false });

  if (error) {
    logger.error('Failed to store vuln pattern', { error: error.message });
  }
}

module.exports = { vectorSearchCVEs, vectorSearchVulnPatterns, storeVulnPattern };
