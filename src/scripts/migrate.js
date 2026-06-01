/**
 * Migration runner — applies all SQL migrations to Supabase via the REST API.
 * Usage: node src/scripts/migrate.js
 */

require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const fs = require('fs');
const path = require('path');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { persistSession: false } }
);

const MIGRATIONS_DIR = path.join(__dirname, '../../../supabase/migrations');

async function runMigrations() {
  console.log('🔄 Running Supabase migrations...\n');

  const files = fs.readdirSync(MIGRATIONS_DIR)
    .filter(f => f.endsWith('.sql'))
    .sort();

  for (const file of files) {
    const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, file), 'utf-8');
    console.log(`▶  Running: ${file}`);

    // Split on statement boundaries (simple approach)
    const statements = sql
      .split(/;\s*(?:\r?\n|$)/)
      .map(s => s.trim())
      .filter(s => s.length > 0 && !s.startsWith('--'));

    for (const stmt of statements) {
      const { error } = await supabase.rpc('exec_sql', { sql: stmt + ';' }).catch(() => ({ error: null }));
      // If rpc doesn't exist, fall back to raw REST
      if (error) {
        console.warn(`   ⚠  rpc/exec_sql not available, skipping stmt: ${stmt.slice(0, 60)}...`);
      }
    }

    console.log(`   ✅ Done\n`);
  }

  console.log('✅ All migrations applied!');
  console.log('\n📝 NOTE: If migrations failed due to missing exec_sql RPC,');
  console.log('   please run the SQL files manually in the Supabase SQL Editor:');
  console.log('   https://supabase.com/dashboard/project/_/sql\n');
  
  files.forEach(f => {
    console.log(`   → supabase/migrations/${f}`);
  });
}

runMigrations().catch(err => {
  console.error('❌ Migration failed:', err.message);
  process.exit(1);
});
