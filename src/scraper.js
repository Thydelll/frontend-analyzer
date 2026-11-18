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

// ---------- Source maps ----------
const SM = {
  maxMaps: 15,
  maxMapBytes: 8 * 1024 * 1024,
  contentBudget: 6 * 1024 * 1024, // total de código-fonte original devolvido (todas as maps)
  maxFileChars: 400_000,
  maxListed: 1500,
  timeoutMs: 8_000,
  parallel: 5,
};
const SM_COMMENT = /(?:\/\/|\/\*)[#@]\s*sourceMappingURL=([^\s'"*]+)/g;

/** Procura o último comentário sourceMappingURL nos ~3 MB finais do arquivo. */
function findSourceMapRef(buf) {
  const tail = buf.subarray(Math.max(0, buf.length - 3 * 1024 * 1024)).toString('utf8');
  let ref = null;
  let m;
  SM_COMMENT.lastIndex = 0;
  while ((m = SM_COMMENT.exec(tail))) ref = m[1];
  return ref;
}

function normalizeSourcePath(src, root) {
  let p = String(root ? root.replace(/\/?$/, '/') + src : src);
  try { p = decodeURIComponent(p); } catch { /* mantém */ }
  p = p.replace(/^[a-z][a-z0-9+.-]*:\/\/\/?/i, '').replace(/\?.*$/, '');
  p = p.split('/').filter((seg) => seg && seg !== '.' && seg !== '..').join('/');
  return p || 'unknown';
}

function readInlineMap(ref) {
  const m = /^data:[^,]*?(;base64)?,(.*)$/s.exec(ref);
  if (!m) return null;
  try { return m[1] ? Buffer.from(m[2], 'base64').toString('utf8') : decodeURIComponent(m[2]); }
  catch { return null; }
}

function parseSourceMap(text, budget) {
  let j;
  try { j = JSON.parse(text); } catch { return { error: 'JSON inválido' }; }
  if (!Array.isArray(j.sources)) return { error: 'formato de source map não suportado' };
  const contents = Array.isArray(j.sourcesContent) ? j.sourcesContent : [];
  const files = [];
  const seen = new Set();
  let withContent = 0;
  j.sources.forEach((src, i) => {
    let path = normalizeSourcePath(src, j.sourceRoot);
    if (seen.has(path)) path = `${path}#${i}`;
    seen.add(path);
    // Código de terceiros/bundler: só lista o nome (poupa memória e ruído).
    const vendor = /(^|\/)(node_modules|webpack\/(runtime|bootstrap))(\/|$)/.test(path);
    const has = typeof contents[i] === 'string';
    const entry = { path, vendor, size: has ? contents[i].length : null };
    if (!vendor && has && budget.left > 0) {
      let c = contents[i];
      if (c.length > SM.maxFileChars) { c = c.slice(0, SM.maxFileChars); entry.truncated = true; }
      budget.left -= c.length;
      entry.content = c;
      withContent++;
    }
    if (files.length < SM.maxListed) files.push(entry);
  });
  return { file: j.file || null, total: j.sources.length, withContent, files, budgetExhausted: budget.left <= 0 };
}

/** Baixa e interpreta os source maps referenciados pelos scripts capturados. */
async function attachSourceMaps(context, scripts, hostIsPublic) {
  const budget = { left: SM.contentBudget };
  const work = async (s) => {
    try {
      let text;
      let mapUrl;
      if (/^data:/i.test(s.smRef)) {
        text = readInlineMap(s.smRef);
        mapUrl = 'inline';
      } else {
        mapUrl = new URL(s.smRef, s.url).href;
        if (!/^https?:/i.test(mapUrl)) throw new Error('esquema não suportado');
        if (!(await hostIsPublic(mapUrl))) throw new Error('host bloqueado (rede interna)');
        const r = await context.request.get(mapUrl, { timeout: SM.timeoutMs, maxRedirects: 0, failOnStatusCode: false });
        if (!r.ok()) throw new Error(`HTTP ${r.status()}`);
        const buf = await r.body();
        if (buf.length > SM.maxMapBytes) throw new Error('arquivo grande demais');
        text = buf.toString('utf8');
      }
      if (!text) throw new Error('vazio');
      const parsed = parseSourceMap(text, budget);
      if (parsed.error) throw new Error(parsed.error);
      s.sourceMap = { url: mapUrl, ...parsed };
    } catch (e) {
      s.sourceMapError = `${s.smRef.slice(0, 100)} → ${String(e.message).split('\n')[0]}`;
    }
  };
  const todo = scripts.filter((s) => s.smRef).slice(0, SM.maxMaps);
  for (let i = 0; i < todo.length; i += SM.parallel) {
    await Promise.all(todo.slice(i, i + SM.parallel).map(work));
  }
  scripts.forEach((s) => { delete s.smRef; });
}

// ---------- Detecção de tecnologias ----------
async function detectTechInPage(page) {
  try {
    return await page.evaluate(() => {
      const out = [];
      const add = (name, version, type, via) => out.push({ name, version: version ? String(version) : null, type, via });
      const w = window;
      const safe = (fn) => { try { fn(); } catch { /* ignora */ } };
      const q = (s) => document.querySelector(s);

      safe(() => { if (w.React && w.React.version) add('React', w.React.version, 'framework', 'global'); });
      safe(() => {
        const h = w.__REACT_DEVTOOLS_GLOBAL_HOOK__;
        if (h && h.renderers) for (const r of h.renderers.values()) if (r && r.version) add('React', r.version, 'framework', 'devtools-hook');
      });
      safe(() => {
        const roots = [q('#root'), q('#__next'), q('#app'), document.body && document.body.firstElementChild].filter(Boolean);
        if (roots.some((el) => Object.keys(el).some((k) => k.startsWith('__reactContainer') || k.startsWith('_reactRootContainer')))) add('React', null, 'framework', 'dom');
      });
      safe(() => { if (w.__NEXT_DATA__ || q('#__next')) add('Next.js', (w.next && w.next.version) || null, 'framework', 'global'); });
      safe(() => { if (w.__NUXT__ || w.$nuxt) add('Nuxt', null, 'framework', 'global'); });
      safe(() => { if (w.Vue && w.Vue.version) add('Vue', w.Vue.version, 'framework', 'global'); });
      safe(() => {
        const a = q('#app');
        if (a && a.__vue_app__) add('Vue', a.__vue_app__.version, 'framework', 'dom');
        else if (a && a.__vue__) add('Vue', a.__vue__.$root.constructor.version || '2.x', 'framework', 'dom');
      });
      safe(() => { const el = q('[ng-version]'); if (el) add('Angular', el.getAttribute('ng-version'), 'framework', 'dom'); });
      safe(() => { if (w.angular && w.angular.version) add('AngularJS', w.angular.version.full, 'framework', 'global'); });
      safe(() => { if (q('[class*="svelte-"]')) add('Svelte', null, 'framework', 'dom'); });
      safe(() => { if (q('#___gatsby')) add('Gatsby', null, 'framework', 'dom'); });
      safe(() => { if (w.__remixContext) add('Remix', null, 'framework', 'global'); });
      safe(() => { if (q('astro-island, [data-astro-cid]')) add('Astro', null, 'framework', 'dom'); });
      safe(() => { if (w.jQuery && w.jQuery.fn) add('jQuery', w.jQuery.fn.jquery, 'library', 'global'); });
      safe(() => {
        const v = (w.bootstrap && w.bootstrap.Tooltip && w.bootstrap.Tooltip.VERSION) ||
          (w.jQuery && w.jQuery.fn && w.jQuery.fn.tooltip && w.jQuery.fn.tooltip.Constructor && w.jQuery.fn.tooltip.Constructor.VERSION);
        if (v) add('Bootstrap', v, 'library', 'global');
      });
      safe(() => { if (w._ && w._.VERSION) add('Lodash', w._.VERSION, 'library', 'global'); });
      safe(() => { if (w.moment && w.moment.version) add('Moment.js', w.moment.version, 'library', 'global'); });
      safe(() => { if (w.axios) add('Axios', null, 'library', 'global'); });
      safe(() => { if (w.Alpine) add('Alpine.js', w.Alpine.version, 'library', 'global'); });
      safe(() => { if (w.htmx) add('htmx', w.htmx.version, 'library', 'global'); });
      safe(() => { if (w.THREE && w.THREE.REVISION) add('Three.js', 'r' + w.THREE.REVISION, 'library', 'global'); });
      safe(() => {
        const g = q('meta[name="generator"]');
        if (g && g.content) {
          const name = g.content.replace(/\s*\d.*$/, '').trim() || g.content;
          add(name, (g.content.match(/\d+(?:\.\d+)+/) || [null])[0], 'cms', 'meta generator');
        }
      });
      safe(() => { if (w.Shopify) add('Shopify', null, 'cms', 'global'); });
      safe(() => { if (q('html[data-wf-site]')) add('Webflow', null, 'cms', 'dom'); });
      safe(() => { if (w.google_tag_manager) add('Google Tag Manager', null, 'analytics', 'global'); });
      safe(() => { if (w.gtag || w.ga || w.dataLayer) add('Google Analytics/gtag', null, 'analytics', 'global'); });
      safe(() => { if (w.fbq) add('Meta Pixel', null, 'analytics', 'global'); });
      safe(() => { if (w.hj) add('Hotjar', null, 'analytics', 'global'); });
      return out;
    });
  } catch { return []; }
}

function techFromHeaders(h) {
  const out = [];
  const add = (name, version, via) => out.push({ name, version: version || null, type: 'infra', via });
  const split = (v) => { const [n, ver] = String(v).split('/'); return [n.trim(), ver && ver.split(/\s/)[0]]; };
  if (h.server) add(...split(h.server), 'header server');
  if (h['x-powered-by']) add(...split(h['x-powered-by']), 'header x-powered-by');
  if (h['cf-ray']) add('cloudflare', null, 'header cf-ray');
  if (h['x-vercel-id']) add('Vercel', null, 'header x-vercel-id');
  if (h['x-nf-request-id']) add('Netlify', null, 'header x-nf-request-id');
  if (h['x-amz-cf-id']) add('Amazon CloudFront', null, 'header x-amz-cf-id');
  return out;
}

const URL_HINT = /(jquery|react-dom|react|vue|angular|bootstrap|lodash|moment|axios|alpine|htmx)(?:\.min)?[-@./]v?(\d+\.\d+(?:\.\d+)?)/i;
const HINT_NAMES = { jquery: 'jQuery', 'react-dom': 'React', react: 'React', vue: 'Vue', angular: 'Angular', bootstrap: 'Bootstrap', lodash: 'Lodash', moment: 'Moment.js', axios: 'Axios', alpine: 'Alpine.js', htmx: 'htmx' };
function techFromUrls(urls) {
  const out = [];
  for (const u of urls) {
    const m = URL_HINT.exec(u);
    if (m) out.push({ name: HINT_NAMES[m[1].toLowerCase()], version: m[2], type: 'library', via: 'nome do arquivo' });
  }
  return out;
}

const TECH_ORDER = { framework: 0, library: 1, cms: 2, infra: 3, analytics: 4 };
function mergeTech(list) {
  const map = new Map();
  for (const t of list) {
    const k = t.name.toLowerCase();
    const cur = map.get(k);
    if (!cur) map.set(k, t);
    else if (!cur.version && t.version) map.set(k, { ...cur, version: t.version, via: t.via });
  }
  return [...map.values()].sort((a, b) => (TECH_ORDER[a.type] ?? 9) - (TECH_ORDER[b.type] ?? 9) || a.name.localeCompare(b.name));
}

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
        const hdrs = response.headers();
        const smHeader = hdrs.sourcemap || hdrs['x-sourcemap'] || null;
        jobs.push(
          response.body()
            .then((buf) => {
              const truncated = buf.length > LIMITS.maxJsBytes;
              const raw = buf.subarray(0, LIMITS.maxJsBytes).toString('utf8');
              let pretty;
              try { pretty = beautify.js(raw, { indent_size: 2, preserve_newlines: true, max_preserve_newlines: 2 }); }
              catch { pretty = raw; }
              scripts.push({
                url, bytes: buf.length, truncated, code: pretty,
                smRef: smHeader || findSourceMapRef(buf), // removido depois de resolver o map
              });
            })
            .catch(() => {})
        );
      }
    });

    // Navegação: tenta networkidle e cai para o que carregou se o site nunca "quietar".
    let navError = null;
    let mainStatus = null;
    let mainHeaders = {};
    try {
      const resp = await page.goto(startUrl, { waitUntil: 'networkidle', timeout: LIMITS.navTimeoutMs });
      mainStatus = resp ? resp.status() : null;
      mainHeaders = resp ? resp.headers() : {};
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

    // Source maps (código original) e tecnologias detectadas
    await attachSourceMaps(context, scripts, hostIsPublic);
    const tech = mergeTech([
      ...(await detectTechInPage(page)),
      ...techFromHeaders(mainHeaders),
      ...techFromUrls(scripts.map((s) => s.url)),
    ]);

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
      tech,
      stats: {
        techCount: tech.length,
        sourceMaps: scripts.filter((s) => s.sourceMap).length,
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
