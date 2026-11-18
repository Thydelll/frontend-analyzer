// Servidor Express: serve o dashboard e expõe POST /api/analyze
// Config por variáveis de ambiente: PORT, HOST, API_TOKEN, RATE_LIMIT_PER_MIN, MAX_CONCURRENT, TRUST_PROXY
const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const { analyze, closeBrowser } = require('./src/scraper');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '127.0.0.1'; // só local por padrão
const API_TOKEN = process.env.API_TOKEN || '';
const RATE_LIMIT_PER_MIN = Number(process.env.RATE_LIMIT_PER_MIN) || 10;
const MAX_CONCURRENT = Number(process.env.MAX_CONCURRENT) || 2;

// Segurança: fora do loopback, exige token. Sem isso o servidor viraria um proxy de scraping aberto.
const isLoopback = ['127.0.0.1', 'localhost', '::1'].includes(HOST);
if (!isLoopback && !API_TOKEN) {
  console.error('ERRO: defina API_TOKEN ao expor o servidor fora do localhost (HOST=' + HOST + ').');
  process.exit(1);
}

const app = express();
// Atrás de proxy reverso (Railway etc.) o IP real vem em X-Forwarded-For.
if (process.env.TRUST_PROXY) app.set('trust proxy', Number(process.env.TRUST_PROXY) || process.env.TRUST_PROXY);

app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// --- Autenticação por token (Authorization: Bearer <token>) ---
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}
function requireAuth(req, res, next) {
  if (!API_TOKEN) return next(); // modo local sem token
  const m = /^Bearer (.+)$/.exec(req.get('authorization') || '');
  if (!m || !safeEqual(m[1], API_TOKEN)) {
    return res.status(401).json({ error: 'Token inválido ou ausente.' });
  }
  next();
}

// --- Rate limit simples em memória (janela de 1 min por IP) ---
const hits = new Map();
setInterval(() => {
  const cutoff = Date.now() - 60_000;
  for (const [ip, arr] of hits) {
    const fresh = arr.filter((t) => t > cutoff);
    fresh.length ? hits.set(ip, fresh) : hits.delete(ip);
  }
}, 60_000).unref();

function rateLimit(req, res, next) {
  const now = Date.now();
  const arr = (hits.get(req.ip) || []).filter((t) => t > now - 60_000);
  if (arr.length >= RATE_LIMIT_PER_MIN) {
    res.set('Retry-After', '30');
    return res.status(429).json({ error: 'Limite de requisições atingido. Aguarde um instante.' });
  }
  arr.push(now);
  hits.set(req.ip, arr);
  next();
}

let running = 0;

// JSZip servido localmente (exportar .zip no navegador, sem depender de CDN)
app.get('/vendor/jszip.min.js', (_req, res) => res.sendFile(require.resolve('jszip/dist/jszip.min.js')));

// Health check sem autenticação (usado pela plataforma de deploy)
app.get('/api/health', (_req, res) => res.json({ ok: true, running }));

// Informa ao dashboard se um token é necessário
app.get('/api/config', (_req, res) => res.json({ authRequired: Boolean(API_TOKEN) }));

app.post('/api/analyze', rateLimit, requireAuth, async (req, res) => {
  const { url, light, screenshot } = req.body || {};
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'Informe "url" no corpo JSON.' });
  }
  if (running >= MAX_CONCURRENT) {
    return res.status(429).json({ error: 'Muitas análises em andamento. Tente novamente em instantes.' });
  }
  running++;
  try {
    res.json(await analyze(url, { light: light !== false, screenshot: !!screenshot })); // modo leve é o padrão
  } catch (err) {
    console.error('[analyze]', err.message);
    res.status(502).json({ error: err.message });
  } finally {
    running--;
  }
});

// Mesma análise, mas com progresso em tempo real: resposta em NDJSON (uma linha JSON por evento).
// Eventos: {type:'progress',step,message,pct} | {type:'ping'} | {type:'result',data} | {type:'error',error}
app.post('/api/analyze/stream', rateLimit, requireAuth, async (req, res) => {
  const { url, light, screenshot } = req.body || {};
  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'Informe "url" no corpo JSON.' });
  }
  if (running >= MAX_CONCURRENT) {
    return res.status(429).json({ error: 'Muitas análises em andamento. Tente novamente em instantes.' });
  }
  running++;
  res.status(200).set({
    'Content-Type': 'application/x-ndjson; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    'X-Accel-Buffering': 'no', // evita buffer em proxies (nginx etc.)
  });
  res.flushHeaders();

  let cancelled = false; // o cliente fechou a aba/conexão antes do fim
  res.on('close', () => { if (!res.writableFinished) cancelled = true; });
  const send = (obj) => { if (!cancelled && !res.writableEnded) res.write(JSON.stringify(obj) + '\n'); };
  const heartbeat = setInterval(() => send({ type: 'ping' }), 10_000); // mantém a conexão viva

  try {
    const data = await analyze(url, {
      light: light !== false,
      screenshot: !!screenshot,
      onProgress: (p) => send({ type: 'progress', ...p }),
      isCancelled: () => cancelled,
    });
    send({ type: 'result', data });
  } catch (err) {
    if (!cancelled) console.error('[analyze]', err.message);
    send({ type: 'error', error: err.message });
  } finally {
    clearInterval(heartbeat);
    running--;
    if (!res.writableEnded) res.end();
  }
});

const server = app.listen(PORT, HOST, () => {
  console.log(`Frontend Analyzer em http://${HOST}:${PORT} (auth: ${API_TOKEN ? 'ligada' : 'desligada'})`);
});

// Encerramento limpo (Railway envia SIGTERM em redeploy)
process.on('SIGTERM', () => server.close(async () => { await closeBrowser(); process.exit(0); }));
