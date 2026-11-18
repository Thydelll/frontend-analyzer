// Motor de extração: abre a página com Playwright + Stealth, intercepta a rede,
// captura o DOM renderizado e baixa/beautifica os arquivos .js.
//
// Memória (importante em planos de 512 MB):
//  - um único Chromium compartilhado, com um contexto novo (isolado) por análise;
//  - o navegador é recriado se morrer e fechado após um período ocioso;
//  - "modo leve" (padrão): não baixa imagens, fontes e mídia (só registra a URL).
const { chromium } = require('playwright-extra');
const stealth = require('puppeteer-extra-plugin-stealth');
const beautify = require('js-beautify');
const { assertPublicUrl } = require('./security');

chromium.use(stealth()); // mitiga detecções básicas de headless (navigator.webdriver etc.)

const LIMITS = {
  navTimeoutMs: 45_000,
  settleMs: 2_500,             // espera extra após o carregamento (requisições tardias)
  maxJsFiles: 40,
  maxJsBytes: 2 * 1024 * 1024, // 2 MB por arquivo JS
  maxBodyPreview: 20_000,      // caracteres do corpo de resposta XHR guardados
  maxPostPreview: 5_000,
  maxHtmlChars: 2_000_000,
  browserIdleMs: 60_000,       // fecha o Chromium após 60 s sem uso (libera memória)
};

const TEXTUAL = /json|text|xml|javascript|graphql|html/i;
const BUCKETS = { image: 'images', font: 'fonts', stylesheet: 'stylesheets', media: 'media' };
const LIGHT_BLOCKED = new Set(['image', 'font', 'media']);

const LAUNCH_ARGS = [
  '--no-sandbox',
  '--disable-dev-shm-usage',
  '--disable-gpu',
  '--disable-extensions',
  '--disable-background-networking',
  '--disable-default-apps',
  '--disable-sync',
  '--mute-audio',
  '--no-first-run',
];

// O plugin de stealth envia comandos CDP em segundo plano. Se o contexto fecha nesse
// meio-tempo (ex.: navegação que falha de imediato), a promessa rejeita sem dono e,
// no Node 15+, isso derrubaria o processo inteiro. Ignoramos só esse erro benigno.
const BENIGN_CLOSED = /Target page, context or browser has been closed|Target closed|cdpSession\.send/i;
process.on('unhandledRejection', (reason) => {
  const msg = String((reason && reason.message) || reason);
  if (BENIGN_CLOSED.test(msg)) return;
  console.error('[unhandledRejection]', msg);
});

// ---------- Navegador compartilhado ----------
let browser = null;
let launching = null;
let active = 0;
let idleTimer = null;

async function getBrowser() {
  if (browser && browser.isConnected()) return browser;
  if (!launching) {
    launching = chromium
      .launch({
        headless: true,
        args: LAUNCH_ARGS,
        executablePath: process.env.CHROMIUM_PATH || undefined,
      })
      .then((b) => {
        browser = b;
        b.on('disconnected', () => { if (browser === b) browser = null; });
        return b;
      })
      .finally(() => { launching = null; });
  }
  return launching;
}

function scheduleIdleClose() {
  clearTimeout(idleTimer);
  if (active > 0) return;
  idleTimer = setTimeout(() => { if (active === 0) closeBrowser(); }, LIMITS.browserIdleMs);
  idleTimer.unref();
}

async function closeBrowser() {
  clearTimeout(idleTimer);
  const b = browser;
  browser = null;
  if (b) await b.close().catch(() => {});
}

// ---------- Erros legíveis ----------
function friendlyError(err) {
  const m = String(err && err.message || err);
  if (/ERR_NAME_NOT_RESOLVED|ENOTFOUND/i.test(m)) return 'Domínio não encontrado. Confira o endereço.';
  if (/ERR_UNSAFE_PORT/i.test(m)) return 'Porta não permitida pelo navegador. Use uma porta comum (80/443).';
  if (/ERR_CONNECTION_REFUSED|ERR_CONNECTION_RESET|ERR_CONNECTION_CLOSED|ERR_EMPTY_RESPONSE/i.test(m)) return 'O site recusou ou interrompeu a conexão.';
  if (/ERR_CERT|SSL|certificate/i.test(m)) return 'Problema com o certificado HTTPS do site.';
  if (/blockedbyclient|ERR_BLOCKED_BY_CLIENT/i.test(m)) return 'Acesso bloqueado: o endereço aponta para uma rede interna ou privada.';
  if (/Timeout|timed out/i.test(m)) return 'O site demorou demais para responder (timeout).';
  if (/crash|Target closed|Target page, context or browser has been closed|Browser has been closed|Connection closed|disconnected/i.test(m)) {
    return 'O navegador caiu, provavelmente por falta de memória. Tente de novo com o "Modo leve" ligado ou um site mais simples.';
  }
  return m.split('\n')[0].replace(/^page\.\w+: /, '');
}

/**
 * @param {string} targetUrl
 * @param {{light?: boolean}} [opts]  light (padrão true): não baixa imagens/fontes/mídia
 */
async function analyze(targetUrl, opts = {}) {
  const light = opts.light !== false;
  let startUrl;
  try { startUrl = await assertPublicUrl(targetUrl); }
  catch (e) { throw new Error(friendlyError(e)); }
  const startedAt = Date.now();

  active++;
  clearTimeout(idleTimer);
  let context;
  try {
    // Uma nova tentativa se o Chromium compartilhado tiver morrido entre análises.
    for (let attempt = 0; ; attempt++) {
      try {
        const b = await getBrowser();
        context = await b.newContext({
          viewport: { width: 1366, height: 768 },
          locale: 'pt-BR',
          timezoneId: 'America/Sao_Paulo',
          userAgent:
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
            '(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
          ignoreHTTPSErrors: false,
        });
        break;
      } catch (e) {
        await closeBrowser();
        if (attempt >= 1) throw e;
      }
    }

    const assets = { images: [], fonts: [], stylesheets: [], media: [], other: [] };
    const apiCalls = [];
    const scripts = [];
    const jobs = [];
    const seenAssets = new Set();
    const seenJs = new Set();
    const hostVerdict = new Map(); // hostname -> Promise<boolean> (cache por análise)
    let blockedCount = 0;

    const hostIsPublic = (url) => {
      const host = new URL(url).hostname;
      if (!hostVerdict.has(host)) {
        hostVerdict.set(host, assertPublicUrl(url).then(() => true, () => false));
      }
      return hostVerdict.get(host);
    };

    // Intercepta TODAS as requisições: bloqueia hosts internos (SSRF) e,
    // no modo leve, evita baixar imagens/fontes/mídia.
    await context.route('**/*', async (route) => {
      const req = route.request();
      const url = req.url();
      if (!/^https?:/i.test(url)) return route.continue();
      try {
        if (!(await hostIsPublic(url))) { blockedCount++; return route.abort('blockedbyclient'); }
      } catch { return route.abort('blockedbyclient'); }

      const type = req.resourceType();
      if (light && LIGHT_BLOCKED.has(type)) {
        if (!seenAssets.has(url)) {
          seenAssets.add(url);
          assets[BUCKETS[type]].push({ url, status: null, contentType: null, size: null, skipped: true });
        }
        return route.abort('blockedbyclient');
      }
      return route.continue();
    });

    const page = await context.newPage();

    page.on('response', (response) => {
      const request = response.request();
      const type = request.resourceType();
      const url = response.url();
      if (url.startsWith('data:')) return;

      // --- Assets ---
      const bucket = BUCKETS[type];
      if (bucket && !seenAssets.has(url)) {
        seenAssets.add(url);
        assets[bucket].push({
          url,
          status: response.status(),
          contentType: response.headers()['content-type'] || null,
          size: Number(response.headers()['content-length']) || null,
        });
      }

      // --- XHR / Fetch (APIs) ---
      if (type === 'xhr' || type === 'fetch') {
        const entry = {
          method: request.method(),
          url,
          status: response.status(),
          resourceType: type,
          requestHeaders: request.headers(),
          postData: (request.postData() || '').slice(0, LIMITS.maxPostPreview) || null,
          contentType: response.headers()['content-type'] || null,
          bodyPreview: null,
        };
        apiCalls.push(entry);
        if (TEXTUAL.test(entry.contentType || '')) {
          jobs.push(
            response.text()
              .then((t) => { entry.bodyPreview = t.slice(0, LIMITS.maxBodyPreview); })
              .catch(() => {})
          );
        }
      }

      // --- Arquivos JS ---
      if (type === 'script' && !seenJs.has(url) && seenJs.size < LIMITS.maxJsFiles) {
        seenJs.add(url);
        jobs.push(
          response.body()
            .then((buf) => {
              const truncated = buf.length > LIMITS.maxJsBytes;
              const raw = buf.subarray(0, LIMITS.maxJsBytes).toString('utf8');
              let pretty;
              try { pretty = beautify.js(raw, { indent_size: 2, preserve_newlines: true, max_preserve_newlines: 2 }); }
              catch { pretty = raw; }
              scripts.push({ url, bytes: buf.length, truncated, code: pretty });
            })
            .catch(() => {})
        );
      }
    });

    // Navegação: tenta networkidle e cai para o que carregou se o site nunca "quietar".
    let navError = null;
    let mainStatus = null;
    try {
      const resp = await page.goto(startUrl, { waitUntil: 'networkidle', timeout: LIMITS.navTimeoutMs });
      mainStatus = resp ? resp.status() : null;
    } catch (e) {
      navError = friendlyError(e);
      if (page.url() === 'about:blank') throw new Error(navError);
    }
    await page.waitForTimeout(LIMITS.settleMs);

    // Scroll para disparar lazy-loading
    await page.evaluate(async () => {
      for (let y = 0; y < document.body.scrollHeight; y += 600) {
        window.scrollTo(0, y);
        await new Promise((r) => setTimeout(r, 120));
      }
      window.scrollTo(0, 0);
    }).catch(() => {});
    await page.waitForTimeout(800);

    // DOM final renderizado
    const title = await page.title();
    let html = await page.content();
    const htmlTruncated = html.length > LIMITS.maxHtmlChars;
    if (htmlTruncated) html = html.slice(0, LIMITS.maxHtmlChars);

    await Promise.allSettled(jobs);
    scripts.sort((a, b) => a.url.localeCompare(b.url));

    const warnings = [];
    if (navError) warnings.push(navError);
    if ([401, 403, 429, 503].includes(mainStatus)) {
      warnings.push(`O site respondeu ${mainStatus}: provavelmente bloqueou o acesso automatizado (WAF/CAPTCHA). O resultado pode estar incompleto.`);
    }
    if (blockedCount) warnings.push(`${blockedCount} requisição(ões) para redes internas foram bloqueadas.`);

    return {
      meta: {
        requestedUrl: startUrl,
        finalUrl: page.url(),
        title,
        durationMs: Date.now() - startedAt,
        mainStatus,
        light,
        navigationWarning: warnings.length ? warnings.join(' ') : null,
        htmlTruncated,
      },
      html,
      assets,
      apiCalls,
      scripts,
      stats: {
        images: assets.images.length,
        fonts: assets.fonts.length,
        stylesheets: assets.stylesheets.length,
        apiCalls: apiCalls.length,
        scripts: scripts.length,
        htmlChars: html.length,
      },
    };
  } catch (err) {
    const wrapped = new Error(friendlyError(err));
    wrapped.cause = err;
    throw wrapped;
  } finally {
    if (context) await context.close().catch(() => {});
    active--;
    scheduleIdleClose();
  }
}

module.exports = { analyze, closeBrowser };
