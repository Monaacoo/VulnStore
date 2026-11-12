# VulnStore — laboratório de vulnerabilidades em APIs REST

API fictícia de e-commerce, **propositalmente vulnerável**, usada na palestra
"A jornada de uma API: do login ao acesso indevido". Ela roda em dois modos:

| Modo | Porta | O que é |
|---|---|---|
| `vuln` | 3000 | Com as 5 falhas da palestra |
| `secure` | 3001 | Mesmas rotas, com as correções |

> ⚠️ Rode apenas em `127.0.0.1`. Não exponha na rede do evento.

## Subindo

**Com Node 18+** (mais simples):
```bash
npm install
npm run vuln      # http://127.0.0.1:3000
npm run secure    # http://127.0.0.1:3001  (em outro terminal)
```

**Com Docker:**
```bash
docker compose up --build
```

Abra `http://127.0.0.1:3000` para ver o front-end e use o DevTools (F12 → Network) para ver o tráfego.

## Contas

| Usuário | Senha | Papel |
|---|---|---|
| joao@vulnstore.test | joao123 | cliente (**atacante**) |
| ana@vulnstore.test | ana@2026 | cliente (vítima) |
| bruno@vulnstore.test | bruno123 | cliente (vítima) |
| carla@vulnstore.test | Carla#2026 | cliente (alvo do DELETE no BFLA) |
| admin@vulnstore.test | Adm!n#2026 | admin |

Pedidos: 1001 (Ana), 1002 (Bruno), 1003 (João), 1004 (Admin).

## Mapa das vulnerabilidades

No `server.js`, procure por `[VULN-n]` e `[FIX-n]`.

| # | Vulnerabilidade | OWASP API Top 10 (2023) | Rota |
|---|---|---|---|
| 1 | BOLA / IDOR | API1 | `GET /api/orders/:id`, `POST /api/orders/:id/cancel` |
| 2 | Broken Function Level Authorization | API5 | `GET/DELETE /api/admin/users` |
| 3 | Excessive Data Exposure | API3 (BOPLA) | `GET /api/products/:id/reviews`, `/api/users/me`, login |
| 4 | Mass Assignment | API3 (BOPLA) | `PATCH /api/users/me` |
| 5 | Falta de Rate Limiting | API4 | `POST /api/auth/login`, `/api/auth/reset-password` |

## Material da demo

A demo é feita com **Postman + DevTools do navegador (F12) + terminal**.

- `postman/VulnStore.postman_collection.json`: importe no Postman. Pastas na ordem da palestra
  (00 Setup → 05 Rate Limiting). O login salva o token sozinho na variável `token`.
  Troque a variável `baseUrl` para `http://127.0.0.1:3001` para mostrar as correções.
- `postman/ids-pedidos.csv`: dados para o Collection Runner (BOLA em escala, IDs 1000–1010).
- `scripts/enum-orders.js`: BOLA em escala pelo terminal.
- `scripts/brute-login.js`: enumeração de usuário + força bruta no login.
- `scripts/brute-otp.js`: força bruta no código de recuperação de senha (4 dígitos).
- `http/requisicoes.http`: as mesmas requisições em texto (VS Code + extensão REST Client), como plano B.

```bash
node scripts/enum-orders.js http://127.0.0.1:3000 1000 1010
node scripts/brute-login.js http://127.0.0.1:3000
node scripts/brute-otp.js   http://127.0.0.1:3000 ana@vulnstore.test
# repita com :3001 para ver o 404 / HTTP 429
```

O código de recuperação também aparece no console do servidor (simulando o e-mail):
deixe esse terminal fora do telão.

## Roteiro rápido no Postman

| Etapa | Onde | O que mostrar |
|---|---|---|
| Login | Navegador (F12 → Network) e `00 → Login como João` | Resposta traz `password` e `cpf` |
| Exposição de dados | F12 → `reviews` e `01 → Avaliações` | Rota pública devolve o autor inteiro |
| BOLA | `02 → Pedido de outro cliente (1002)` + `enum-orders.js` | Pedidos de todos os clientes |
| BFLA | Ctrl+U no navegador (acha `/api/admin/users`) + `03` | Cliente lista e apaga usuários |
| Mass Assignment | `04` na ordem: cupom 403 → PATCH com `role` → cupom 201 | Cliente vira admin |
| Rate limiting | `05` (mensagens) + `brute-login.js` + `brute-otp.js` | Senha de outras contas |

Para cada etapa, troque `baseUrl` para a porta 3001, refaça o login e repita: a correção aparece.

## Resetar entre ensaios

```bash
curl -X POST http://127.0.0.1:3000/api/__reset
```
Ou rode `00 — Setup → Resetar laboratório` no Postman, ou reinicie o processo (a base é em memória).

## Indo além: Burp Suite

No pentest profissional, o Burp Suite Community (gratuito) faz o mesmo papel como proxy:
Repeater para editar e reenviar, Intruder para automatizar e a extensão **Autorize**, que repete
cada requisição com o token de outro usuário (ótima para achar BOLA e BFLA).
