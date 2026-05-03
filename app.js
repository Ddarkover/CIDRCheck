/**
 * CIDRCheck — IP Whitelist Checker
 * Fully static frontend, GitHub Pages compatible
 */

const WHITELIST_LOCAL_URL = 'data/cidrwhitelist.txt';
const WHITELIST_URL = 'https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/cidrwhitelist.txt';
const WHITELIST_FALLBACK_URL = 'https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/main/cidrwhitelist.txt';
const DOH_URL = 'https://cloudflare-dns.com/dns-query';
const IPINFO_PROVIDERS = [
  { name: 'ipapi.is', url: (ip) => 'https://api.ipapi.is/?q=' + ip, parser: parseIpapiIs },
  { name: 'iplocate.io', url: (ip) => 'https://www.iplocate.io/api/lookup/' + ip, parser: parseIplocate },
  { name: 'api.ip.sb', url: (ip) => 'https://api.ip.sb/geoip/' + ip, parser: parseIpSb },
];

let cidrList = [];
let listLoaded = false;
let hasManualTheme = false;
let systemThemeMedia = null;

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  hideError();
  loadWhitelist();
  bindEvents();
});

function bindEvents() {
  const input = document.getElementById('queryInput');
  const btn = document.getElementById('checkBtn');
  input.addEventListener('input', () => {
    normalizeInputField();
    onInputChange();
  });
  input.addEventListener('blur', normalizeInputField);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') runCheck(); });
  btn.addEventListener('click', runCheck);
  document.getElementById('themeToggle').addEventListener('click', toggleTheme);
}

// Theme
function initTheme() {
  const saved = localStorage.getItem('cidrcheck-theme');
  hasManualTheme = !!saved;
  const preferred = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  setTheme(saved || preferred);
  systemThemeMedia = window.matchMedia('(prefers-color-scheme: light)');
  const syncTheme = function(e) {
    if (!hasManualTheme) setTheme(e.matches ? 'light' : 'dark');
  };
  if (systemThemeMedia.addEventListener) systemThemeMedia.addEventListener('change', syncTheme);
  else if (systemThemeMedia.addListener) systemThemeMedia.addListener(syncTheme);
}
function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('cidrcheck-theme', theme);
}
function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme');
  hasManualTheme = true;
  setTheme(current === 'dark' ? 'light' : 'dark');
}

// Load whitelist
async function loadWhitelist() {
  setStatus('loading', 'Загрузка списка...');
  try {
    const sources = [WHITELIST_LOCAL_URL, WHITELIST_URL, WHITELIST_FALLBACK_URL];
    let res = null;
    let lastErr = null;
    for (const source of sources) {
      try {
        const candidate = await fetchWithTimeout(source, {}, 12000);
        if (candidate.ok) {
          res = candidate;
          break;
        }
        lastErr = new Error('HTTP ' + candidate.status + ' from ' + source);
      } catch (err) {
        lastErr = err;
      }
    }
    if (!res) throw (lastErr || new Error('Не удалось загрузить whitelist из источников'));
    const text = await res.text();
    const bytes = new Blob([text]).size;
    parseCIDRList(text);
    listLoaded = true;
    setStatus('ready', 'Готово · ' + cidrList.length.toLocaleString('ru-RU') + ' записей');
    document.getElementById('statEntries').textContent = cidrList.length.toLocaleString('ru-RU');
    document.getElementById('statSize').textContent = formatBytes(bytes);
    document.getElementById('statsBar').hidden = false;
  } catch (err) {
    setStatus('error', 'Ошибка загрузки списка');
    console.error('Whitelist load error:', err);
  }
}

function parseCIDRList(text) {
  const lines = text.split('\n');
  const parsed = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const entry = parseCIDR(trimmed);
    if (entry) parsed.push(entry);
  }
  parsed.sort((a, b) => (a.network >>> 0) - (b.network >>> 0));
  cidrList = parsed;
}

function parseCIDR(cidr) {
  const slash = cidr.indexOf('/');
  if (slash === -1) return null;
  const ip = cidr.slice(0, slash);
  const prefix = parseInt(cidr.slice(slash + 1), 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 32) return null;
  const ipNum = ipToNumber(ip);
  if (ipNum === null) return null;
  const mask = prefix === 0 ? 0 : ((0xFFFFFFFF << (32 - prefix)) >>> 0);
  const network = (ipNum & mask) >>> 0;
  return { network, mask, cidr };
}

function ipToNumber(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let num = 0;
  for (const part of parts) {
    const n = parseInt(part, 10);
    if (isNaN(n) || n < 0 || n > 255) return null;
    num = ((num * 256) + n) >>> 0;
  }
  return num >>> 0;
}

function checkIPInWhitelist(ip) {
  const ipNum = ipToNumber(ip);
  if (ipNum === null) return null;

  // Binary search to find the closest network <= ipNum
  let lo = 0, hi = cidrList.length - 1;
  let found = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if ((cidrList[mid].network >>> 0) <= (ipNum >>> 0)) {
      found = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }

  // Check candidates near found index (wider masks may match)
  for (let i = found; i >= Math.max(0, found - 64); i--) {
    const { network, mask } = cidrList[i];
    if ((ipNum & mask) >>> 0 === network) return cidrList[i];
    if ((network >>> 0) < ((ipNum & 0xFF000000) >>> 0)) break;
  }
  return null;
}

// Input detection
function detectInputType(value) {
  const t = value.trim();
  if (!t) return null;
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(t)) return 'ip';
  if (/^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(t)) return 'domain';
  return 'unknown';
}

function onInputChange() {
  const val = document.getElementById('queryInput').value;
  const badge = document.getElementById('inputTypeBadge');
  const type = detectInputType(val);
  if (type === 'ip') {
    badge.textContent = 'IPv4'; badge.className = 'input-type-badge visible type-ip';
  } else if (type === 'domain') {
    badge.textContent = 'Domain'; badge.className = 'input-type-badge visible type-domain';
  } else {
    badge.className = 'input-type-badge';
  }
}

// DNS via DoH
async function resolveDoH(domain) {
  const url = DOH_URL + '?name=' + encodeURIComponent(domain) + '&type=A';
  const res = await fetchWithTimeout(url, { headers: { 'Accept': 'application/dns-json' } }, 8000);
  if (!res.ok) throw new Error('DoH HTTP ' + res.status);
  const data = await res.json();
  if (data.Status && data.Status !== 0) throw new Error('DNS status ' + data.Status);
  if (!data.Answer || !data.Answer.length) throw new Error('DNS не нашёл записей для "' + domain + '"');
  const aRecords = data.Answer.filter(r => r.type === 1);
  if (!aRecords.length) throw new Error('Нет A-записей для "' + domain + '"');
  return aRecords[0].data;
}

// IP info
async function fetchIPInfo(ip) {
  for (const provider of IPINFO_PROVIDERS) {
    try {
      const res = await fetchWithTimeout(provider.url(ip), {}, 7000);
      if (!res.ok) continue;
      const data = await res.json();
      const parsed = provider.parser(data);
      if (parsed) return parsed;
    } catch (e) { /* try next provider */ }
  }
  return null;
}

// Main check
async function runCheck() {
  normalizeInputField();
  const raw = document.getElementById('queryInput').value.trim();
  if (!raw) return;
  if (!listLoaded) { showError('Список CIDR ещё загружается. Подождите...'); return; }

  hideError(); hideResults(); setSteps(-1);
  document.getElementById('loaderContainer').hidden = false;
  document.getElementById('checkBtn').disabled = true;

  let ip = null;
  const type = detectInputType(raw);

  try {
    setSteps(0); await delay(150);
    if (type === 'unknown') throw new Error('Неверный формат. Введите IPv4-адрес или домен.');
    setSteps(1);
    if (type === 'ip') {
      ip = raw;
      if (!isValidIPv4(ip)) throw new Error('Неверный IPv4-адрес');
    } else {
      try { ip = await resolveDoH(raw); }
      catch (e) { throw new Error('Не удалось разрезолвить домен: ' + e.message); }
    }
    setSteps(2); await delay(80);
    const match = checkIPInWhitelist(ip);
    setSteps(3);
    const info = await fetchIPInfo(ip);
    setSteps(4); await delay(200);
    document.getElementById('loaderContainer').hidden = true;
    showResults(raw, ip, match, info, type);
  } catch (err) {
    document.getElementById('loaderContainer').hidden = true;
    showError(err.message);
  } finally {
    document.getElementById('checkBtn').disabled = false;
  }
}

function showResults(query, ip, match, info, type) {
  const allowed = !!match;
  const card = document.getElementById('verdictCard');
  card.className = 'verdict-card ' + (allowed ? 'allowed' : 'blocked');
  document.getElementById('verdictIcon').textContent = allowed ? '✓' : '✗';
  document.getElementById('verdictQuery').textContent = query;
  document.getElementById('verdictIp').textContent = (type === 'domain') ? '→ ' + ip : '';
  document.getElementById('verdictStatus').textContent = allowed ? 'РАЗРЕШЁН' : 'НЕ В СПИСКЕ';
  document.getElementById('verdictCidr').textContent = allowed ? 'Совпадение: ' + match.cidr : 'Не найден в whitelist';

  document.getElementById('ipInfoBody').innerHTML = renderInfoRows([
    ['IP-адрес', ip, 'highlight'],
    ['Провайдер (ISP)', info && info.isp ? info.isp : (info && info.organization ? info.organization : '—')],
    ['ASN', info ? (normalizeASN(info.asn) || extractASN(info.organization) || '—') : '—'],
    ['Тип сети', formatIPVersion(info && info.version)],
  ]);

  document.getElementById('geoBody').innerHTML = renderInfoRows([
    ['Страна', info ? ((info.country || '—') + ' ' + countryFlag(info.country_code)) : '—'],
    ['Регион', info && info.region ? info.region : '—'],
    ['Город', info && info.city ? info.city : '—'],
    ['Часовой пояс', info && info.timezone ? info.timezone : '—'],
    ['Координаты', info && info.latitude ? info.latitude + ', ' + info.longitude : '—'],
  ]);

  document.getElementById('networkBody').innerHTML = renderInfoRows([
    ['Статус whitelist', allowed ? 'В WHITELIST' : 'НЕ В WHITELIST', allowed ? 'green' : 'red'],
    ['Совпавший CIDR', match ? match.cidr : '—'],
    ['IP-версия', 'IPv4'],
    ['Hostname', info && (info.hostname || info.ip) ? (info.hostname || info.ip) : 'не определён'],
    ['Сеть', (info && info.network) ? info.network : (match ? match.cidr : '—')],
    ['Записей в списке', cidrList.length.toLocaleString('ru-RU')],
  ]);

  document.getElementById('results').hidden = false;
  document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function renderInfoRows(rows) {
  return rows.map(function(r) {
    var label = r[0], val = r[1], cls = r[2] || '';
    return '<div class="info-row"><span class="info-label">' + escapeHtml(label) + '</span><span class="info-val ' + cls + '">' + escapeHtml(String(val)) + '</span></div>';
  }).join('');
}

function extractASN(org) {
  if (!org) return null;
  var m = org.match(/^(AS\d+)/i);
  return m ? m[1].toUpperCase() : null;
}

function normalizeASN(value) {
  if (value === null || value === undefined || value === '') return null;
  var v = String(value).trim();
  if (!v) return null;
  if (/^AS\d+/i.test(v)) return v.match(/^AS\d+/i)[0].toUpperCase();
  if (/^\d+$/.test(v)) return 'AS' + v;
  var m = v.match(/AS\d+/i);
  return m ? m[0].toUpperCase() : null;
}

function parseIpSb(data) {
  if (!data || !data.ip) return null;
  return {
    ip: data.ip,
    isp: data.isp || data.organization || null,
    organization: data.organization || data.asn_organization || null,
    asn: data.asn,
    country: data.country,
    country_code: data.country_code,
    region: data.region,
    city: data.city,
    timezone: data.timezone,
    latitude: data.latitude,
    longitude: data.longitude,
    network: null,
    version: null,
  };
}





function parseIpapiIs(data) {
  if (!data || !data.ip) return null;
  var company = data.company || {};
  var location = data.location || {};
  return {
    ip: data.ip,
    isp: company.name || (data.asn && data.asn.org) || null,
    organization: company.name || (data.asn && data.asn.org) || null,
    asn: data.asn && (data.asn.asn || data.asn.number || data.asn.org),
    country: location.country || data.location_country || null,
    country_code: location.country_code || null,
    region: location.state || location.region || null,
    city: location.city || null,
    timezone: location.timezone || null,
    latitude: location.latitude || null,
    longitude: location.longitude || null,
    network: data.company && data.company.network ? data.company.network : null,
    version: data.is_ipv6 ? 'IPv6' : 'IPv4',
  };
}

function parseIplocate(data) {
  if (!data || !data.ip) return null;
  return {
    ip: data.ip,
    isp: (data.company && data.company.name) || (data.asn && data.asn.name) || data.org || data.isp || null,
    organization: (data.company && data.company.name) || (data.asn && data.asn.name) || data.org || data.isp || null,
    asn: data.asn && data.asn.asn ? data.asn.asn : (data.asn || null),
    country: data.country || null,
    country_code: data.country_code || null,
    region: data.subdivision || data.region || null,
    city: data.city || null,
    timezone: data.time_zone || data.timezone || null,
    latitude: data.latitude || null,
    longitude: data.longitude || null,
    network: (data.abuse && data.abuse.network) || data.network || null,
    version: data.ip_version || null,
  };
}


function countryFlag(code) {
  if (!code || code.length !== 2) return '';
  try {
    return String.fromCodePoint.apply(String, code.toUpperCase().split('').map(function(c) { return c.charCodeAt(0) + 127397; }));
  } catch(e) { return ''; }
}

function escapeHtml(str) {
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function setStatus(type, text) {
  var badge = document.getElementById('listStatus');
  badge.querySelector('.dot').className = 'dot ' + type;
  badge.querySelector('.status-text').textContent = text;
}

function showError(msg) {
  document.getElementById('errorMsg').textContent = msg;
  document.getElementById('errorCard').hidden = false;
}

function hideError() {
  var errorCard = document.getElementById('errorCard');
  if (!errorCard) return;
  errorCard.hidden = true;
}
function hideResults() { document.getElementById('results').hidden = true; }

function setSteps(activeIndex) {
  for (var i = 1; i <= 4; i++) {
    var el = document.getElementById('step' + i);
    if (!el) continue;
    var idx = i - 1;
    el.className = 'step' + (idx < activeIndex ? ' done' : idx === activeIndex ? ' active' : '');
  }
}

function setExample(val) {
  document.getElementById('queryInput').value = val;
  onInputChange();
  document.getElementById('queryInput').focus();
}

function normalizeInputField() {
  var input = document.getElementById('queryInput');
  if (!input) return;
  input.value = normalizeQueryInput(input.value);
}

function normalizeQueryInput(value) {
  var v = String(value || '').trim();
  if (!v) return '';
  v = v.replace(/^https?:\/\//i, '');
  v = v.replace(/\/.*$/, '');
  return v.trim();
}

function isValidIPv4(ip) {
  var parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every(function(p) {
    var n = parseInt(p, 10);
    return !isNaN(n) && n >= 0 && n <= 255 && String(n) === p;
  });
}

function formatBytes(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';
  return (bytes/(1024*1024)).toFixed(2) + ' MB';
}

function delay(ms) { return new Promise(function(r) { setTimeout(r, ms); }); }

async function fetchWithTimeout(url, options, timeoutMs) {
  var controller = new AbortController();
  var id = setTimeout(function() { controller.abort(); }, timeoutMs || 10000);
  try {
    return await fetch(url, Object.assign({}, options || {}, { signal: controller.signal }));
  } finally {
    clearTimeout(id);
  }
}

function formatIPVersion(version) {
  if (!version) return 'IPv4';
  var v = String(version).trim();
  return /^ipv/i.test(v) ? v : ('IPv' + v);
}
