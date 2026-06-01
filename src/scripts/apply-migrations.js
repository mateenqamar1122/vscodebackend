/**
 * apply-migrations.js
 * Applies all three SQL migrations to your Supabase project.
 * 
 * Usage:  node src/scripts/apply-migrations.js
 */

require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const fs = require('fs');
const path = require('path');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false }, db: { schema: 'public' } }
);

const MIGRATIONS_DIR = path.resolve(__dirname, '../../../supabase/migrations');

// ──────────────────────────────────────────────────────────────────────────────
// Helper: Split a SQL file into individual statements (naively on ';')
// ──────────────────────────────────────────────────────────────────────────────
function splitStatements(sql) {
  // Remove single-line comments
  const noComments = sql.replace(/--[^\n]*/g, '');
  // Split on semicolons followed by whitespace or end-of-string
  return noComments
    .split(/;\s*(?:\r?\n|$)/)
    .map(s => s.trim())
    .filter(s => s.length > 2);
}

// ──────────────────────────────────────────────────────────────────────────────
// Execute SQL via Supabase PostgREST (raw SQL via rpc or direct)
// ──────────────────────────────────────────────────────────────────────────────
async function executeSql(sql) {
  // PostgREST doesn't support DDL; use the Management API or pg directly.
  // With service_role we can use the /sql endpoint via fetch.
  const url = `${process.env.SUPABASE_URL}/rest/v1/`;
  
  // Attempt via the Supabase client's built-in rpc – works for simple DML
  // For DDL (CREATE TABLE, CREATE INDEX, etc.) we need the Management API.
  // We'll use a raw fetch call to the Supabase SQL query endpoint.
  const apiUrl = `${process.env.SUPABASE_URL}/pg/query`;
  const response = await fetch(apiUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY,
      'Authorization': `Bearer ${process.env.SUPABASE_SERVICE_ROLE_KEY}`,
    },
    body: JSON.stringify({ query: sql }),
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`HTTP ${response.status}: ${text}`);
  }
  return response.json();
}

async function run() {
  console.log('\n🛡️  SecureGuard – Applying Supabase Migrations\n');
  console.log(`📂 Migrations dir: ${MIGRATIONS_DIR}\n`);

  if (!fs.existsSync(MIGRATIONS_DIR)) {
    console.error(`❌ Migrations directory not found: ${MIGRATIONS_DIR}`);
    process.exit(1);
  }

  const files = fs.readdirSync(MIGRATIONS_DIR)
    .filter(f => f.endsWith('.sql'))
    .sort();

  if (!files.length) {
    console.log('No migration files found.');
    return;
  }

  let succeeded = 0;
  let failed = 0;

  for (const file of files) {
    const fullPath = path.join(MIGRATIONS_DIR, file);
    const sql = fs.readFileSync(fullPath, 'utf-8');

    console.log(`▶  ${file}`);

    try {
      await executeSql(sql);
      console.log(`   ✅ Applied successfully\n`);
      succeeded++;
    } catch (err) {
      console.error(`   ❌ Failed: ${err.message}\n`);
      failed++;
    }
  }

  console.log('─'.repeat(50));
  console.log(`✅ ${succeeded} migration(s) succeeded`);
  if (failed) {
    console.log(`❌ ${failed} migration(s) failed`);
    console.log('\n📋 Manual instructions:');
    console.log('   Open https://supabase.com/dashboard/project/blkqsiydykrdpqpeocpe/sql/new');
    console.log('   and run these files in order:');
    files.forEach(f => console.log(`   → ${f}`));
  }
  console.log('');
}

run().catch(err => {
  console.error('Fatal error:', err.message);
  process.exit(1);
});
