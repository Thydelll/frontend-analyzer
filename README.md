# Frontend Analyzer (MVP)

Dashboard local que recebe uma URL e devolve: DOM renderizado, assets (imagens/fontes/CSS), chamadas XHR/Fetch e arquivos JS beautificados.

## Rodar

```bash
cd frontend-analyzer
npm install          # o postinstall baixa o Chromium do Playwright
npm start            # http://127.0.0.1:3000
```

Requer Node.js 18+.

## Estrutura

```
frontend-analyzer/
├── package.json
├── server.js            # Express + rota POST /api/analyze
├── src/
│   ├── scraper.js       # Playwright + Stealth, intercepta rede, extrai DOM/JS
│   └── security.js      # Proteção SSRF (bloqueia localhost/IPs privados)
└── public/
    └── index.html       # Dashboard (HTML/CSS/JS puro)
```

## Variáveis de ambiente

| Variável | Padrão | Descrição |
|---|---|---|
| `HOST` | `127.0.0.1` | Fora do loopback, `API_TOKEN` passa a ser obrigatório (o servidor se recusa a subir sem) |
| `PORT` | `3000` | Porta HTTP |
| `API_TOKEN` | vazio | Token Bearer exigido em `POST /api/analyze` |
| `RATE_LIMIT_PER_MIN` | `10` | Requisições por IP por minuto |
| `MAX_CONCURRENT` | `2` | Análises simultâneas |
| `TRUST_PROXY` | vazio | `1` atrás de proxy reverso, para o rate limit ver o IP real |

## Recursos do dashboard

- **Source maps:** se o site publica `.map` (comentário `sourceMappingURL`, cabeçalho `SourceMap` ou mapa embutido), o código original é recuperado. Dependências (`node_modules`) são só listadas; há limites de tamanho (8 MB por map, 6 MB de código no total).
- **Tecnologias:** frameworks, bibliotecas, CMS, servidor/CDN e analytics, detectados por variáveis globais, DOM, cabeçalhos e nomes de arquivo.
- **Busca:** texto ou regex no HTML, JS, URLs/headers/respostas das APIs e código original.
- **Baixar tudo (.zip):** DOM, JS formatado, JSON das APIs/assets e código original dos source maps. O zip é gerado no navegador (JSZip servido em `/vendor/jszip.min.js`).
- **Recentes:** as últimas 10 URLs analisadas, guardadas só no navegador.

## Modo leve e memória

- **Modo leve** (padrão, caixa no dashboard ou `"light": false` na API para desligar): não baixa imagens, fontes e mídia; só lista as URLs. Usa bem menos memória. Desligado, o DOM fica mais fiel.
- Um único Chromium é compartilhado entre análises (contexto isolado por análise), é recriado se cair e fecha após 60 s ocioso.
- Toda requisição feita pela página passa pela validação anti-SSRF (hosts internos são bloqueados).
- `CHROMIUM_PATH` (opcional): caminho de um Chrome/Chromium já instalado.

## Deploy (Railway)

1. Suba o projeto para um repositório no GitHub (o `.gitignore` já ignora `node_modules`).
2. No Railway: **New Project → Deploy from GitHub repo**. O `railway.json` já aponta para o `Dockerfile` e para o health check `/api/health`.
3. Em **Variables**, defina `API_TOKEN` com um valor forte (`openssl rand -hex 32`). O Dockerfile já define `HOST=0.0.0.0` e `TRUST_PROXY=1`.
4. Em **Settings → Networking**, gere um domínio público.
5. Reserve pelo menos ~1 GB de RAM: o Chromium consome bastante memória.

Teste local da imagem:

```bash
docker build -t frontend-analyzer .
docker run --rm -p 3000:3000 -e API_TOKEN=meu-token frontend-analyzer
```

## Uso responsável

Analise apenas sites seus ou que você tenha autorização para testar. Respeite termos de uso, robots.txt e leis aplicáveis (ex.: LGPD). O stealth reduz falsos positivos de detecção de headless, mas não deve ser usado para burlar controles de acesso.

## Limites do MVP

- Beautifier apenas formata o código; não desfaz ofuscação real (nomes minificados, string arrays).
- Sites com CAPTCHA/WAF agressivo continuarão bloqueando.
- Sem fila/persistência: cada análise abre um navegador novo (máx. 2 simultâneas).
- Para expor fora da máquina local, adicione autenticação e rate limit.
