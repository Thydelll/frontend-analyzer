// Motor de extração: abre a página com Playwright + Stealth, intercepta a rede,
// captura o DOM renderizado e baixa/beautifica os arquivos .js.
const { chromium } = require('playwright-extra');
const stealth = require('puppeteer-extra-plugin-stealth');
const beautify = require('js-beautify');
const { assertPublicUrl } = require('./security');

chromium.use(stealth()); // mitiga detecções básicas de headless (navigator.webdriver etc.)

const LIMITS = {
  navTimeoutMs: 45_000,
  settleMs: 2_500,            // espera extra após o carregamento (requisições tardias)
  maxJsFiles: 40,
  maxJsBytes: 2 * 1024 * 1024, // 2 MB por arquivo JS
  maxBodyPreview: 20_000,      // caracteres do corpo de resposta XHR guardados
  maxPostPreview: 5_000,
  maxHtmlChars: 2_000_000,
};

const TEXTUAL = /json|text|xml|javascript|graphql|html/i;

async function analyze(targetUrl) {
  const startUrl = await assertPublicUrl(targetUrl);
  const startedAt = Date.now();

  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });

  try {
    const context = await browser.newContext({
      viewport: { width: 1366, height: 768 },
      locale: 'pt-BR',
      timezoneId: 'America/Sao_Paulo',
      userAgent:
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
        '(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
      ignoreHTTPSErrors: false,
    });

    // Bloqueia redirecionamentos de navegação para hosts internos (SSRF).
    await context.route('**/*', async (route) => {
      const req = route.request();
      if (req.isNavigationRequest()) {
        try { await assertPublicUrl(req.url()); }
        catch { return route.abort('blockedbyclient'); }
      }
      return route.continue();
    });

    const page = await context.newPage();

    const assets = { images: [], fonts: [], stylesheets: [], media: [], other: [] };
    const apiCalls = [];
    const jsJobs = [];
    const seenAssets = new Set();
    const seenJs = new Set();

    page.on('response', (response) => {
      const request = response.request();
      const type = request.resourceType();
      const url = response.url();
      if (url.startsWith('data:')) return;

      // --- Assets ---
      const bucket = { image: 'images', font: 'fonts', stylesheet: 'stylesheets', media: 'media' }[type];
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
          jsJobs.push(
            response.text()
              .then((t) => { entry.bodyPreview = t.slice(0, LIMITS.maxBodyPreview); })
              .catch(() => {})
          );
        }
      }

      // --- Arquivos JS ---
      if (type === 'script' && !seenJs.has(url) && seenJs.size < LIMITS.maxJsFiles) {
        seenJs.add(url);
        jsJobs.push(
          response.body()
            .then((buf) => {
              const truncated = buf.length > LIMITS.maxJsBytes;
              const raw = buf.subarray(0, LIMITS.maxJsBytes).toString('utf8');
              let pretty;
              try { pretty = beautify.js(raw, { indent_size: 2, preserve_newlines: true, max_preserve_newlines: 2 }); }
              catch { pretty = raw; }
              assets.__js = assets.__js || [];
              assets.__js.push({ url, bytes: buf.length, truncated, code: pretty });
            })
            .catch(() => {})
        );
      }
    });

    // Navegação: tenta networkidle e cai para domcontentloaded se o site nunca "quietar".
    let navError = null;
    try {
      await page.goto(startUrl, { waitUntil: 'networkidle', timeout: LIMITS.navTimeoutMs });
    } catch (e) {
      navError = e.message.split('\n')[0];
      if (page.url() === 'about:blank') throw new Error(`Falha ao carregar: ${navError}`);
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

    await Promise.allSettled(jsJobs);

    const scripts = (assets.__js || []).sort((a, b) => a.url.localeCompare(b.url));
    delete assets.__js;

    return {
      meta: {
        requestedUrl: startUrl,
        finalUrl: page.url(),
        title,
        durationMs: Date.now() - startedAt,
        navigationWarning: navError,
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
  } finally {
    await browser.close();
  }
}

module.exports = { analyze };
