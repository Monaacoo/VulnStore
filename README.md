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

Abra `http://127.0.0.1:3000` para ver o front-end. Na demo, use o navegador embutido do Burp (Proxy → Open browser) e veja o tráfego no Proxy → HTTP history.

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

A demo é feita com o **Burp Suite** (navegador embutido + Repeater + Intruder). Os scripts
entram na parte de força bruta, e o Postman fica como plano B.

- `scripts/enum-orders.js`: BOLA em escala pelo terminal (percorre IDs de pedido).
- `scripts/brute-login.js`: enumeração de usuário + força bruta no login.
- `scripts/brute-otp.js`: força bruta no código de recuperação (4 dígitos). O Intruder do
  Burp Community é lento demais para os 10.000 códigos, então use este script.
- `postman/VulnStore.postman_collection.json`: **plano B**. Importe no Postman; o login salva o
  token na variável `token`. Troque `baseUrl` para `http://127.0.0.1:3001` nas correções.
- `postman/ids-pedidos.csv`: dados para o Collection Runner (plano B do BOLA em escala).
- `http/requisicoes.http`: as mesmas requisições em texto (VS Code + extensão REST Client), plano B.

```bash
node scripts/enum-orders.js http://127.0.0.1:3000 1000 1010
node scripts/brute-login.js http://127.0.0.1:3000
node scripts/brute-otp.js   http://127.0.0.1:3000 ana@vulnstore.test
# repita com :3001 para ver o 404 / HTTP 429
```

O código de recuperação também aparece no console do servidor (simulando o e-mail):
deixe esse terminal fora do telão.

## Configurando o Burp (uma vez)

1. A VulnStore é HTTP em `localhost`, então você **não** precisa instalar o certificado CA do
   Burp (ele só é necessário para HTTPS).
2. Abra o Burp → **Temporary project in memory** → **Use Burp defaults** → **Start Burp**.
3. **Target → Scope**: adicione `http://127.0.0.1:3000` e `:3001`. No **Proxy → HTTP history**,
   ligue **Show only in-scope items** para cortar o ruído.
4. **Proxy → Open browser** e acesse `http://127.0.0.1:3000`. O navegador embutido captura até o
   tráfego de `127.0.0.1` (um Chrome normal ignoraria o localhost).
5. Deixe o **Intercept off** para navegar; ligue só para pausar e editar uma requisição ao vivo.
6. Para o telão: aumente a fonte em **Settings → User interface → Font**.

## Roteiro rápido no Burp

| Etapa | No Burp | O que mostrar |
|---|---|---|
| Login | HTTP history → `login` → aba Response | Resposta traz `password` (hash) e `cpf` |
| Exposição de dados | HTTP history → `reviews` → Send to Repeater, apague o `Authorization` | Rota pública devolve o autor inteiro |
| BOLA | Repeater: `GET /api/orders/1003` → troque para `1002`; depois Intruder nos IDs | Pedidos de todos os clientes |
| BFLA | Repeater: troque o caminho para `GET /api/admin/users`, depois `DELETE .../5` | Cliente lista e apaga usuários |
| Mass Assignment | Repeater: cupom 403 → `PATCH /api/users/me` com `role` e `credits` → cupom 201 | Cliente vira admin |
| Rate limiting | Repeater (compare as mensagens) + `brute-login.js` + `brute-otp.js` | Senha de outras contas |

Para cada etapa, troque o alvo do Repeater para a porta `3001` e repita: a correção aparece
(404, 403, 400 ou 429).

Extensão recomendada: **Autorize** (BApp Store). Ela repete cada requisição com o token de outro
usuário e sinaliza BOLA/BFLA sozinha. Precisa do Jython configurado, então deixe como opcional.

## Resetar entre ensaios

```bash
curl -X POST http://127.0.0.1:3000/api/__reset
```
Rode também na `:3001` (ou reinicie os processos; a base é em memória). O Burp Community não salva
o projeto, então remonte as abas do Repeater pouco antes de apresentar.

## Plano B: Postman e scripts

Se o Burp der problema no dia, a mesma demo roda pela coleção do Postman (pasta `postman/`, pastas
`00` a `05`, na ordem da palestra) ou pelos scripts no terminal. O `http/requisicoes.http` tem as
requisições cruas para o VS Code com a extensão REST Client.
