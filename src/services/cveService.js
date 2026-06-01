const { supabaseAdmin } = require('../config/supabase');
const { generateEmbedding } = require('./openaiService');
const axios = require('axios');
const logger = require('../utils/logger');

const NVD_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';

/**
 * Search CVEs from Supabase (fast local DB).
 * Falls back to NVD API if not enough results are found.
 */
async function searchCVEs({ packageName, version, ecosystem }) {
  logger.info(`Searching CVEs for ${packageName}@${version} [${ecosystem}]`);

  // 1. Try Supabase first
  const { data: localResults, error } = await supabaseAdmin
    .from('cve_entries')
    .select('*')
    .ilike('affected_packages', `%${packageName}%`)
    .eq('ecosystem', ecosystem)
    .order('cvss_score', { ascending: false })
    .limit(20);

  if (error) {
    logger.error('Supabase CVE query failed', { error: error.message });
  }

  // 2. Vector similarity search for related CVEs
  let vectorResults = [];
  try {
    const queryText = `${packageName} ${version} ${ecosystem} vulnerability`;
    const embedding = await generateEmbedding(queryText);
    const { data: vecData } = await supabaseAdmin.rpc('match_cves', {
      query_embedding: embedding,
      match_threshold: 0.75,
      match_count: 10,
    });
    vectorResults = vecData || [];
  } catch (e) {
    logger.warn('Vector search failed, using text-only results', { error: e.message });
  }

  // 3. Merge and deduplicate results
  const combined = mergeResults(localResults || [], vectorResults);

  // 4. Filter by version if possible
  const filtered = filterByVersion(combined, version);

  // 5. If we have few results, hit NVD API for fresh data
  if (filtered.length < 3 && process.env.NVD_API_KEY) {
    const nvdResults = await fetchFromNVD(packageName, ecosystem);
    const nvdFormatted = nvdResults.map(formatNVDEntry);
    // Store new CVEs in Supabase for future use
    await storeCVEs(nvdFormatted);
    return mergeResults(filtered, nvdFormatted);
  }

  return filtered;
}

/**
 * Fetch CVEs directly from NVD API.
 */
async function fetchFromNVD(packageName, ecosystem) {
  try {
    const response = await axios.get(NVD_BASE, {
      params: {
        keywordSearch: `${packageName} ${ecosystem}`,
        resultsPerPage: 10,
      },
      headers: {
        apiKey: process.env.NVD_API_KEY,
      },
      timeout: 10000,
    });

    return response.data?.vulnerabilities || [];
  } catch (e) {
    logger.error('NVD API request failed', { error: e.message });
    return [];
  }
}

/**
 * Format an NVD CVE entry to our schema.
 */
function formatNVDEntry(nvdItem) {
  const cve = nvdItem.cve;
  const metrics = cve.metrics?.cvssMetricV31?.[0] ||
    cve.metrics?.cvssMetricV30?.[0] ||
    cve.metrics?.cvssMetricV2?.[0];

  return {
    cve_id: cve.id,
    description: cve.descriptions?.find(d => d.lang === 'en')?.value || '',
    cvss_score: metrics?.cvssData?.baseScore || null,
    severity: metrics?.cvssData?.baseSeverity || 'UNKNOWN',
    published_date: cve.published,
    last_modified: cve.lastModified,
    references: cve.references?.map(r => r.url) || [],
    affected_packages: JSON.stringify(
      cve.configurations?.flatMap(c =>
        c.nodes?.flatMap(n => n.cpeMatch?.map(m => m.criteria) || []) || []
      ) || []
    ),
    ecosystem: 'unknown',
    source: 'nvd',
  };
}

/**
 * Store CVE entries in Supabase (upsert).
 */
async function storeCVEs(cves) {
  if (!cves.length) return;

  const { error } = await supabaseAdmin
    .from('cve_entries')
    .upsert(cves, { onConflict: 'cve_id', ignoreDuplicates: true });

  if (error) {
    logger.error('Failed to store CVEs in Supabase', { error: error.message });
  } else {
    logger.info(`Stored/updated ${cves.length} CVE entries`);
  }
}

/**
 * Get a specific CVE by ID.
 */
async function getCVEById(cveId) {
  const { data, error } = await supabaseAdmin
    .from('cve_entries')
    .select('*')
    .eq('cve_id', cveId.toUpperCase())
    .single();

  if (error || !data) {
    // Try NVD
    const nvdData = await fetchFromNVD(cveId, '');
    if (nvdData.length) {
      const formatted = formatNVDEntry(nvdData[0]);
      await storeCVEs([formatted]);
      return formatted;
    }
    return null;
  }
  return data;
}

/**
 * Analyse a full dependency manifest (package.json, requirements.txt, etc.).
 */
async function auditDependencies({ dependencies, ecosystem }) {
  const results = [];

  for (const [pkg, version] of Object.entries(dependencies)) {
    const cves = await searchCVEs({
      packageName: pkg,
      version: cleanVersion(version),
      ecosystem,
    });

    if (cves.length > 0) {
      results.push({
        package: pkg,
        version: cleanVersion(version),
        vulnerabilities: cves,
        maxSeverity: getMaxSeverity(cves),
      });
    }
  }

  // Sort by severity
  results.sort((a, b) => severityWeight(b.maxSeverity) - severityWeight(a.maxSeverity));
  return results;
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function mergeResults(arr1, arr2) {
  const seen = new Set();
  return [...arr1, ...arr2].filter(item => {
    const key = item.cve_id || item.id;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function filterByVersion(cves, version) {
  if (!version || version === '*' || version === 'latest') return cves;
  return cves; // Full semver range matching would require the 'semver' package per-CVE
}

function cleanVersion(version) {
  return version?.replace(/[\^~>=<]/g, '').trim() || '*';
}

function getMaxSeverity(cves) {
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  for (const sev of order) {
    if (cves.some(c => (c.severity || '').toUpperCase() === sev)) return sev;
  }
  return 'UNKNOWN';
}

function severityWeight(sev) {
  const weights = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, UNKNOWN: 1 };
  return weights[(sev || '').toUpperCase()] || 0;
}

module.exports = { searchCVEs, getCVEById, auditDependencies, fetchFromNVD, storeCVEs };
