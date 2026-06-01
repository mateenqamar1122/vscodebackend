/**
 * Seed script: Generates OpenAI embeddings for existing vuln_patterns in Supabase
 * Run once after applying migration 003:  node src/scripts/seedEmbeddings.js
 */

const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });
const { createClient } = require('@supabase/supabase-js');
const OpenAI = require('openai');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
);

const openai = new OpenAI({ apiKey: process.env.AI_API_KEY });

async function generateEmbedding(text) {
  const res = await openai.embeddings.create({
    model: 'text-embedding-3-small',
    input: text.slice(0, 8192),
  });
  return res.data[0].embedding;
}

async function seedEmbeddings() {
  console.log('🔄 Fetching vuln_patterns without embeddings...');

  const { data: patterns, error } = await supabase
    .from('vuln_patterns')
    .select('id, title, description, category, cwe')
    .is('embedding', null);

  if (error) {
    console.error('❌ Failed to fetch patterns:', error.message);
    process.exit(1);
  }

  console.log(`Found ${patterns.length} patterns to embed`);

  for (const pattern of patterns) {
    const text = `${pattern.title} ${pattern.description} ${pattern.category} ${pattern.cwe || ''}`;
    console.log(`  → Embedding: ${pattern.title} (${pattern.cwe})`);

    try {
      const embedding = await generateEmbedding(text);

      const { error: updateErr } = await supabase
        .from('vuln_patterns')
        .update({ embedding })
        .eq('id', pattern.id);

      if (updateErr) {
        console.error(`  ❌ Failed to update ${pattern.id}:`, updateErr.message);
      } else {
        console.log(`  ✅ Done`);
      }

      // Rate limit: text-embedding-3-small = 1M tokens/min
      await new Promise(r => setTimeout(r, 200));
    } catch (err) {
      console.error(`  ❌ Embedding failed for ${pattern.title}:`, err.message);
    }
  }

  console.log('\n✅ Embedding seed complete!');
}

seedEmbeddings().catch(console.error);
