// Proteção contra SSRF: impede que a ferramenta seja usada para acessar
// localhost, rede interna ou metadados de cloud (169.254.169.254).
const dns = require('node:dns').promises;
const net = require('node:net');

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return (
      a === 0 || a === 10 || a === 127 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) // CGNAT
    );
  }
  if (net.isIPv6(ip)) {
    const v = ip.toLowerCase();
    return v === '::1' || v === '::' || v.startsWith('fc') || v.startsWith('fd') ||
           v.startsWith('fe80') || v.startsWith('::ffff:127.') || v.startsWith('::ffff:10.') ||
           v.startsWith('::ffff:192.168.');
  }
  return true;
}

/** Valida a URL e garante que resolve apenas para IPs públicos. */
async function assertPublicUrl(raw) {
  let u;
  try { u = new URL(raw); } catch { throw new Error('URL inválida'); }
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Apenas http/https são permitidos');
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal')) {
    throw new Error('Host não permitido');
  }
  const addrs = net.isIP(host) ? [{ address: host }] : await dns.lookup(host, { all: true });
  if (!addrs.length || addrs.some(a => isPrivateIp(a.address))) {
    throw new Error('Host resolve para endereço privado/reservado');
  }
  return u.href;
}

module.exports = { assertPublicUrl, isPrivateIp };
