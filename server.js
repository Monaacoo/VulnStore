/**
 * VulnStore API — API REST propositalmente vulnerável para fins didáticos.
 *
 *  MODE=vuln   (padrão)  -> expõe BOLA, BFLA, Excessive Data Exposure,
 *                           Mass Assignment e ausência de Rate Limiting.
 *  MODE=secure           -> mesmas rotas, com as correções aplicadas.
 *
 *  NÃO exponha esta aplicação na internet. Use apenas em localhost / lab.
 *
 *  Cada trecho vulnerável está marcado com  // [VULN-x]
 *  e a correção correspondente com          // [FIX-x]
 *    1 = BOLA / IDOR
 *    2 = Broken Function Level Authorization
 *    3 = Excessive Data Exposure
 *    4 = Mass Assignment
 *    5 = Rate Limiting / brute force
 */
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

const MODE = (process.argv[2] || process.env.MODE || 'vuln').toLowerCase();
const SECURE = MODE === 'secure';
const PORT = Number(process.env.PORT || (SECURE ? 3001 : 3000));
const JWT_SECRET = process.env.JWT_SECRET || 'segredo-de-demo-nao-use-em-producao';

const app = express();
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------------------------------------------------------------------------
// "Banco de dados" em memória
// ---------------------------------------------------------------------------
const hash = (s) => crypto.createHash('sha256').update(s).digest('hex'); // só para demo!

let db;
function seed() {
  db = {
    users: [
      { id: 1, name: 'Admin VulnStore', email: 'admin@vulnstore.test', password: hash('Adm!n#2026'), role: 'admin',
        cpf: '111.222.333-44', phone: '(11) 90000-0001', address: 'Av. Paulista, 1000 - São Paulo/SP', credits: 0, resetCode: null },
      { id: 2, name: 'Ana Souza', email: 'ana@vulnstore.test', password: hash('ana@2026'), role: 'customer',
        cpf: '222.333.444-55', phone: '(11) 98888-2222', address: 'Rua das Flores, 25 - Campinas/SP', credits: 150, resetCode: null },
      { id: 3, name: 'Bruno Lima', email: 'bruno@vulnstore.test', password: hash('bruno123'), role: 'customer',
        cpf: '333.444.555-66', phone: '(21) 97777-3333', address: 'Rua do Catete, 90 - Rio de Janeiro/RJ', credits: 40, resetCode: null },
      { id: 4, name: 'João Atacante', email: 'joao@vulnstore.test', password: hash('joao123'), role: 'customer',
        cpf: '444.555.666-77', phone: '(11) 96666-4444', address: 'Rua Fictícia, 1 - Santos/SP', credits: 10, resetCode: null },
      { id: 5, name: 'Carla Mendes', email: 'carla@vulnstore.test', password: hash('Carla#2026'), role: 'customer',
        cpf: '555.666.777-88', phone: '(31) 95555-5555', address: 'Av. Afonso Pena, 500 - Belo Horizonte/MG', credits: 75, resetCode: null },
    ],
    products: [
      { id: 1, name: 'Notebook Gamer X', price: 7999.9 },
      { id: 2, name: 'Fone Bluetooth Pro', price: 349.9 },
      { id: 3, name: 'Teclado Mecânico', price: 459.0 },
    ],
    reviews: [
      { id: 1, productId: 1, userId: 2, rating: 5, comment: 'Roda tudo no ultra!' },
      { id: 2, productId: 1, userId: 3, rating: 4, comment: 'Esquenta um pouco.' },
      { id: 3, productId: 2, userId: 2, rating: 5, comment: 'Bateria ótima.' },
    ],
    orders: [
      { id: 1001, userId: 2, items: [{ productId: 1, qty: 1 }], total: 7999.9, status: 'entregue',
        shippingAddress: 'Rua das Flores, 25 - Campinas/SP', cardLast4: '4821' },
      { id: 1002, userId: 3, items: [{ productId: 2, qty: 2 }], total: 699.8, status: 'em transporte',
        shippingAddress: 'Rua do Catete, 90 - Rio de Janeiro/RJ', cardLast4: '1177' },
      { id: 1003, userId: 4, items: [{ productId: 3, qty: 1 }], total: 459.0, status: 'pago',
        shippingAddress: 'Rua Fictícia, 1 - Santos/SP', cardLast4: '9090' },
      { id: 1004, userId: 1, items: [{ productId: 2, qty: 1 }], total: 349.9, status: 'pago',
        shippingAddress: 'Av. Paulista, 1000 - São Paulo/SP', cardLast4: '0001' },
    ],
    coupons: [],
  };
}
seed();

const findUser = (id) => db.users.find((u) => u.id === Number(id));

// ---------------------------------------------------------------------------
// Serializers (DTOs) — usados apenas no modo seguro
// ---------------------------------------------------------------------------
const publicUser = (u) => ({ id: u.id, name: u.name.split(' ')[0] });          // [FIX-3]
const selfUser = (u) => ({ id: u.id, name: u.name, email: u.email, phone: u.phone,
  address: u.address, credits: u.credits, role: u.role });                     // [FIX-3]
const adminUserView = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role });

// ---------------------------------------------------------------------------
// Rate limiter simples em memória (janela fixa)              [FIX-5]
// ---------------------------------------------------------------------------
const buckets = new Map();
function rateLimit({ windowMs, max, key }) {
  return (req, res, next) => {
    if (!SECURE) return next();                                // [VULN-5] sem limite nenhum
    const k = `${req.path}|${key(req)}`;
    const now = Date.now();
    let b = buckets.get(k);
    if (!b || now > b.reset) { b = { count: 0, reset: now + windowMs }; buckets.set(k, b); }
    b.count++;
    res.set('RateLimit-Limit', String(max));
    res.set('RateLimit-Remaining', String(Math.max(0, max - b.count)));
    if (b.count > max) {
      res.set('Retry-After', String(Math.ceil((b.reset - now) / 1000)));
      return res.status(429).json({ error: 'Muitas tentativas. Tente novamente mais tarde.' });
    }
    next();
  };
}

// ---------------------------------------------------------------------------
// Autenticação
// ---------------------------------------------------------------------------
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Token ausente' });
  try {
    const payload = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
    const user = findUser(payload.sub);
    if (!user) return res.status(401).json({ error: 'Usuário inválido' });
    req.user = user; // sempre recarrega do "banco": o papel vem do servidor, não do token
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido' });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) return res.status(403).json({ error: 'Acesso negado' });
    next();
  };
}

// ---------------------------------------------------------------------------
// Rotas públicas
// ---------------------------------------------------------------------------
app.get('/api/health', (req, res) => res.json({ status: 'ok', mode: MODE }));

app.post('/api/auth/login',
  rateLimit({ windowMs: 60_000, max: 5, key: (r) => `${r.ip}|${(r.body?.email || '').toLowerCase()}` }),
  (req, res) => {
    const { email, password } = req.body || {};
    const user = db.users.find((u) => u.email === String(email || '').toLowerCase());
    if (!SECURE) {
      // [VULN-5] mensagens diferentes permitem enumerar usuários + sem limite de tentativas
      if (!user) return res.status(404).json({ error: 'Usuário não encontrado' });
      if (user.password !== hash(String(password || ''))) return res.status(401).json({ error: 'Senha incorreta' });
    } else if (!user || user.password !== hash(String(password || ''))) {
      return res.status(401).json({ error: 'Credenciais inválidas' });             // [FIX-5] mensagem genérica
    }
    const token = jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET, { algorithm: 'HS256', expiresIn: '2h' });
    res.json({ token, user: SECURE ? selfUser(user) : user }); // [VULN-3] devolve o objeto inteiro (hash, cpf...)
  });

// Fluxo de "esqueci minha senha" com código numérico
app.post('/api/auth/forgot-password',
  rateLimit({ windowMs: 15 * 60_000, max: 3, key: (r) => r.ip }),
  (req, res) => {
    const user = db.users.find((u) => u.email === String(req.body?.email || '').toLowerCase());
    if (user) {
      if (!SECURE) {
        // [VULN-5] código de 4 dígitos, sem expiração e sem limite de tentativas
        user.resetCode = { code: String(crypto.randomInt(0, 10000)).padStart(4, '0'), attempts: 0, exp: Infinity };
      } else {
        // [FIX-5] 6 dígitos, expira em 5 min, no máximo 5 tentativas
        user.resetCode = { code: String(crypto.randomInt(0, 1_000_000)).padStart(6, '0'), attempts: 0, exp: Date.now() + 5 * 60_000 };
      }
      console.log(`[forgot-password] código para ${user.email}: ${user.resetCode.code} (simulando envio por e-mail)`);
    }
    res.json({ message: 'Se o e-mail existir, enviaremos um código.' });
  });

app.post('/api/auth/reset-password',
  rateLimit({ windowMs: 15 * 60_000, max: 10, key: (r) => r.ip }),
  (req, res) => {
    const { email, code, newPassword } = req.body || {};
    const user = db.users.find((u) => u.email === String(email || '').toLowerCase());
    const rc = user?.resetCode;
    if (!rc || Date.now() > rc.exp) return res.status(400).json({ error: 'Código inválido ou expirado' });
    if (SECURE && rc.attempts >= 5) { user.resetCode = null; return res.status(400).json({ error: 'Código inválido ou expirado' }); }
    rc.attempts++;
    const ok = SECURE
      ? crypto.timingSafeEqual(Buffer.from(hash(String(code || ''))), Buffer.from(hash(rc.code)))
      : String(code) === rc.code;
    if (!ok) return res.status(400).json({ error: 'Código inválido ou expirado' });
    if (SECURE && (typeof newPassword !== 'string' || newPassword.length < 8)) {
      return res.status(400).json({ error: 'Senha deve ter ao menos 8 caracteres' });
    }
    user.password = hash(String(newPassword || ''));
    user.resetCode = null;
    res.json({ message: 'Senha alterada com sucesso' });
  });

app.get('/api/products', (req, res) => res.json(db.products));

// Avaliações de um produto (rota pública)
app.get('/api/products/:id/reviews', (req, res) => {
  const reviews = db.reviews.filter((r) => r.productId === Number(req.params.id));
  if (!SECURE) {
    // [VULN-3] embute o objeto completo do autor; o front-end só mostra o nome...
    return res.json(reviews.map((r) => ({ ...r, author: findUser(r.userId) })));
  }
  res.json(reviews.map((r) => ({ id: r.id, rating: r.rating, comment: r.comment, author: publicUser(findUser(r.userId)) }))); // [FIX-3]
});

// ---------------------------------------------------------------------------
// Rotas autenticadas
// ---------------------------------------------------------------------------
app.get('/api/users/me', auth, (req, res) => {
  res.json(SECURE ? selfUser(req.user) : req.user); // [VULN-3] / [FIX-3]
});

app.patch('/api/users/me', auth, (req, res) => {
  if (!SECURE) {
    // [VULN-4] Mass Assignment: copia TUDO que vier no corpo para o objeto do usuário
    Object.assign(req.user, req.body);
    return res.json(req.user);
  }
  // [FIX-4] allowlist de campos editáveis + validação de tipo/tamanho
  const allowed = ['name', 'phone', 'address'];
  const extra = Object.keys(req.body || {}).filter((k) => !allowed.includes(k));
  if (extra.length) return res.status(400).json({ error: `Campos não permitidos: ${extra.join(', ')}` });
  for (const k of allowed) {
    if (req.body[k] === undefined) continue;
    if (typeof req.body[k] !== 'string' || req.body[k].length > 120) return res.status(400).json({ error: `Valor inválido para ${k}` });
    req.user[k] = req.body[k].trim();
  }
  res.json(selfUser(req.user));
});

// Lista apenas os pedidos do usuário logado
app.get('/api/orders', auth, (req, res) => {
  res.json(db.orders.filter((o) => o.userId === req.user.id));
});

// Detalhe de um pedido
app.get('/api/orders/:id', auth, (req, res) => {
  const order = db.orders.find((o) => o.id === Number(req.params.id));
  if (!SECURE) {
    // [VULN-1] BOLA/IDOR: verifica que existe, mas não verifica de QUEM é
    if (!order) return res.status(404).json({ error: 'Pedido não encontrado' });
    return res.json({ ...order, customer: findUser(order.userId) });
  }
  // [FIX-1] o objeto precisa pertencer ao usuário (ou ser admin). 404 para não revelar existência.
  if (!order || (order.userId !== req.user.id && req.user.role !== 'admin')) {
    return res.status(404).json({ error: 'Pedido não encontrado' });
  }
  res.json(order);
});

// Cancelar pedido
app.post('/api/orders/:id/cancel', auth, (req, res) => {
  const order = db.orders.find((o) => o.id === Number(req.params.id));
  if (!order || (SECURE && order.userId !== req.user.id)) return res.status(404).json({ error: 'Pedido não encontrado' }); // [FIX-1]
  // [VULN-1] no modo vuln qualquer usuário cancela o pedido de qualquer um
  order.status = 'cancelado';
  res.json(order);
});

// ---------------------------------------------------------------------------
// Rotas administrativas
// ---------------------------------------------------------------------------
const admin = express.Router();
if (SECURE) admin.use(auth, requireRole('admin'));  // [FIX-2] deny-by-default no router inteiro
else admin.use(auth);                                // [VULN-2] só checa se está logado — "o botão nem aparece no front"

admin.get('/users', (req, res) => {
  res.json(SECURE ? db.users.map(adminUserView) : db.users);
});

admin.delete('/users/:id', (req, res) => {
  const idx = db.users.findIndex((u) => u.id === Number(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Usuário não encontrado' });
  const [removed] = db.users.splice(idx, 1);
  res.json({ message: `Usuário ${removed.email} removido` });
});

// Esta rota checa o papel mesmo no modo vulnerável — o "dev lembrou" só aqui.
// Serve para mostrar que o Mass Assignment (role=admin) abre portas.
admin.post('/coupons', requireRole('admin'), (req, res) => {
  const coupon = { code: String(req.body?.code || 'DESCONTO').slice(0, 30), discount: Math.min(100, Number(req.body?.discount) || 10) };
  db.coupons.push(coupon);
  res.status(201).json(coupon);
});

app.use('/api/admin', admin);

// Reset do laboratório (útil entre ensaios da palestra)
app.post('/api/__reset', (req, res) => { seed(); buckets.clear(); res.json({ message: 'Base restaurada' }); });

app.use((req, res) => res.status(404).json({ error: 'Rota não encontrada' }));

const HOST = process.env.HOST || '127.0.0.1';
app.listen(PORT, HOST, () => {
  console.log(`VulnStore API [${MODE.toUpperCase()}] em http://${HOST}:${PORT}`);
});
