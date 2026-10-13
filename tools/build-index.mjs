// Validates every query file and builds index.json.
//   node tools/build-index.mjs           -> validate + write index.json
//   node tools/build-index.mjs --check   -> validate + fail if index.json is not up to date
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const QUERIES = join(ROOT, 'queries');
const INDEX = join(ROOT, 'index.json');
const check = process.argv.includes('--check');

const TACTICS = new Set([
  'Reconnaissance', 'ResourceDevelopment', 'InitialAccess', 'Execution', 'Persistence', 'PrivilegeEscalation',
  'DefenseEvasion', 'CredentialAccess', 'Discovery', 'LateralMovement', 'Collection', 'CommandAndControl',
  'Exfiltration', 'Impact',
]);
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TECHNIQUE = /^T\d{4}(\.\d{3})?$/;
const SEMVER = /^\d+\.\d+\.\d+$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;

const errors = [];
const groups = JSON.parse(readFileSync(join(QUERIES, 'groups.json'), 'utf8'));
const groupKeys = new Set(groups.map(g => g.key));
const ids = new Map();
const queries = [];

for (const folder of readdirSync(QUERIES, { withFileTypes: true }).filter(d => d.isDirectory()).map(d => d.name).sort()) {
  if (!groupKeys.has(folder)) errors.push(`queries/${folder}: folder not declared in groups.json`);
  for (const file of readdirSync(join(QUERIES, folder)).filter(f => f.endsWith('.yaml')).sort()) {
    const rel = relative(ROOT, join(QUERIES, folder, file)).replace(/\\/g, '/');
    let q;
    try {
      q = parse(readFileSync(join(QUERIES, folder, file), 'utf8'), { schema: 'core' });
    } catch (e) {
      errors.push(`${rel}: invalid YAML (${e.message.split('\n')[0]})`);
      continue;
    }
    const err = m => errors.push(`${rel}: ${m}`);
    const str = v => (typeof v === 'string' && v.trim() ? v.trim() : null);
    const arr = v => (Array.isArray(v) ? v : []);
    const date = v => (v instanceof Date ? v.toISOString().slice(0, 10) : String(v ?? ''));

    if (!GUID.test(q.id ?? '')) err('id must be a lowercase GUID');
    else if (ids.has(q.id)) err(`duplicate id (also in ${ids.get(q.id)})`);
    else ids.set(q.id, rel);
    if (!str(q.name)) err('name is required');
    if (!str(q.description)) err('description is required');
    if (!str(q.query)) err('query is required');
    if (q.group !== folder) err(`group must be "${folder}" (the folder name)`);
    if (!SEMVER.test(String(q.version ?? ''))) err('version must be MAJOR.MINOR.PATCH');
    if (!DATE.test(date(q.added))) err('added must be YYYY-MM-DD');
    if (q.updated != null && !DATE.test(date(q.updated))) err('updated must be YYYY-MM-DD');
    if (!str(q.author)) err('author is required');
    for (const t of arr(q.tactics)) if (!TACTICS.has(t)) err(`unknown tactic "${t}"`);
    for (const t of arr(q.relevantTechniques)) if (!TECHNIQUE.test(t)) err(`invalid technique "${t}"`);

    queries.push({
      id: q.id,
      name: str(q.name),
      description: str(q.description),
      group: folder,
      tactics: arr(q.tactics),
      relevantTechniques: arr(q.relevantTechniques),
      tags: arr(q.tags),
      requiredDataConnectors: arr(q.requiredDataConnectors),
      version: String(q.version),
      added: date(q.added),
      updated: q.updated != null ? date(q.updated) : null,
      author: str(q.author),
      credits: str(q.credits),
      legacyId: str(q.legacyId),
      path: rel,
      query: String(q.query).replace(/\s+$/, ''),
    });
  }
}

if (errors.length) {
  console.error(errors.join('\n'));
  console.error(`\n${errors.length} error(s)`);
  process.exit(1);
}

const index = JSON.stringify({ schemaVersion: 1, count: queries.length, groups, queries }, null, 2) + '\n';
if (check) {
  if (!existsSync(INDEX) || readFileSync(INDEX, 'utf8').replace(/\r\n/g, '\n') !== index) {
    console.error('index.json is out of date: run "npm run build" and commit the result');
    process.exit(1);
  }
  console.log(`OK: ${queries.length} queries, index.json up to date`);
} else {
  writeFileSync(INDEX, index);
  console.log(`index.json written: ${queries.length} queries in ${groups.length} groups`);
}
