/**
 * Descoberta de endpoints sob /api/admin/ por fuzzing autenticado (POST).
 * Estilo ffuf: testa cada palavra da wordlist e mostra o que responde != 404.
 *
 * Uso:  node scripts/fuzz-admin.js [baseUrl] [token]
 *   ex: node scripts/fuzz-admin.js http://127.0.0.1:3000 eyJhbGci...
 *
 * O token é o de um usuário COMUM (ex.: João). Pegue na resposta do login.
 * Sem token, a API responde 401 para tudo e não dá para distinguir.
 * Somente para o laboratório local da VulnStore.
 */
const fs = require('fs');
const path = require('path');

const base = process.argv[2] || 'http://127.0.0.1:3000';
const token = process.argv[3] || '';
if (!/^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(base)) {
  console.error('Este script só roda contra o laboratório local.'); process.exit(1);
}
if (!token) { console.error('Faltou o token. Uso: node scripts/fuzz-admin.js <baseUrl> <token>'); process.exit(1); }

const words = fs.readFileSync(path.join(__dirname, 'admin-wordlist.txt'), 'utf8')
  .split(/\r?\n/).map((w) => w.trim()).filter(Boolean);

const label = (code) =>
  code === 403 ? '  <= existe, mas é protegida (403)'
  : code === 200 ? '  <= existe e respondeu 200'
  : code === 401 ? '  <= precisa de autenticação'
  : '';

(async () => {
  console.log(`Fuzzing  POST ${base}/api/admin/FUZZ`);
  console.log(`Wordlist: ${words.length} palavras · filtro: escondendo 404\n`);
  let achados = 0;
  for (const w of words) {
    const r = await fetch(`${base}/api/admin/${w}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
    });
    if (r.status !== 404) {
      achados++;
      console.log(`  ${w.padEnd(14)} [Status: ${r.status}]${label(r.status)}`);
    }
  }
  console.log(`\n:: Concluído [${words.length}/${words.length}] · ${achados} endpoint(s) encontrado(s)`);
  if (!achados) console.log('Nada != 404. Token expirado? Refaça o login e use o novo token.');
})();