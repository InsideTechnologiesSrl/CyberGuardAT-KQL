// Refreshes tools/attack-enterprise.json from the official MITRE ATT&CK Enterprise STIX bundle.
//   node tools/update-attack.mjs
// Keeps only what validation needs: tactics and active (not revoked, not deprecated) techniques.
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const URL_STIX = 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json';
const OUT = fileURLToPath(new URL('./attack-enterprise.json', import.meta.url));

const res = await fetch(URL_STIX);
if (!res.ok) throw new Error(`download failed: HTTP ${res.status}`);
const { objects } = await res.json();

const active = o => !o.revoked && !o.x_mitre_deprecated;
const extId = o => o.external_references?.find(r => r.source_name === 'mitre-attack')?.external_id;
// "command-and-control" -> "CommandAndControl" (tactic naming used by Sentinel)
const camel = s => s.split('-').map(w => w[0].toUpperCase() + w.slice(1)).join('');

const version = objects.find(o => o.type === 'x-mitre-collection')?.x_mitre_version;
const matrix = objects.find(o => o.type === 'x-mitre-matrix' && active(o));
const tacticById = new Map(objects.filter(o => o.type === 'x-mitre-tactic' && active(o)).map(o => [o.id, o]));
const tactics = (matrix?.tactic_refs ?? [...tacticById.keys()]).map(id => tacticById.get(id)).filter(Boolean)
  .map(t => ({ id: extId(t), name: camel(t.x_mitre_shortname), displayName: t.name }));

const techniques = {};
for (const o of objects.filter(o => o.type === 'attack-pattern' && active(o)).sort((a, b) => extId(a).localeCompare(extId(b)))) {
  techniques[extId(o)] = {
    name: o.name,
    tactics: (o.kill_chain_phases ?? []).filter(p => p.kill_chain_name === 'mitre-attack').map(p => camel(p.phase_name)),
  };
}

writeFileSync(OUT, JSON.stringify({ version, tactics, techniques }, null, 1) + '\n');
console.log(`ATT&CK Enterprise ${version}: ${tactics.length} tactics, ${Object.keys(techniques).length} techniques`);
