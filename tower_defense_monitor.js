const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const https = require('https');

const BASE = `${process.env.HOME}/firewall/logs`;
const WHITELIST = `${BASE}/whitelist.txt`;
const BLACKLIST = `${BASE}/blacklist.txt`;
const REPUTATION_FILE = `${BASE}/dayreputation.json`;
const ABATIDOS = `${BASE}/abatidos`;
const DEATH_NOTE = `${BASE}/death_note.txt`;

const PORTAS_CRITICAS = ['21', '22', '23', '3305'];
const LIMITE_PONTOS = 100;
const PONTOS_POR_PORTA = 5;
const PONTOS_POR_CRITICA = 20;
const TIMEOUT_MINUTOS = 10;
const RESET_INTERVAL_MS = 24 * 60 * 60 * 1000;

fs.mkdirSync(BASE, { recursive: true });
fs.mkdirSync(ABATIDOS, { recursive: true });
if (!fs.existsSync(WHITELIST)) fs.writeFileSync(WHITELIST, '127.0.0.1\n');
if (!fs.existsSync(BLACKLIST)) fs.writeFileSync(BLACKLIST, '');
if (!fs.existsSync(DEATH_NOTE)) fs.writeFileSync(DEATH_NOTE, '');
if (!fs.existsSync(REPUTATION_FILE)) fs.writeFileSync(REPUTATION_FILE, '{}');

let historico = JSON.parse(fs.readFileSync(REPUTATION_FILE, 'utf8'));
let bloqueiosTemp = {};

function salvarReputacao() {
  fs.writeFileSync(REPUTATION_FILE, JSON.stringify(historico, null, 2));
}

function isWhitelisted(ip) {
  return fs.readFileSync(WHITELIST, 'utf8').split('\n').includes(ip.trim());
}

function isBlacklisted(ip) {
  return fs.readFileSync(BLACKLIST, 'utf8').split('\n').includes(ip.trim());
}

function limparBlacklistEReputacao() {
  fs.writeFileSync(BLACKLIST, '');
  fs.writeFileSync(REPUTATION_FILE, '{}');
  historico = {};
  console.log(`\x1b[44m🧹 Blacklist e reputação resetadas (${new Date().toISOString()})\x1b[0m`);
}
setInterval(limparBlacklistEReputacao, RESET_INTERVAL_MS);

function fetchIpInfo(ip, callback) {
  if (ip.startsWith('100.')) {
    return callback({
      IP: ip, País: 'CGNAT', Região: 'Endereço interno de operadora',
      Cidade: '-', Org: 'IP compartilhado', ASN: '-', Datacenter: 'Não'
    });
  }

  https.get(`https://ipinfo.io/${ip}/json`, res => {
    let raw = '';
    res.on('data', chunk => raw += chunk);
    res.on('end', () => {
      try {
        const data = JSON.parse(raw);
        const org = data.org || '';
        callback({
          IP: ip,
          País: data.country || '-', Região: data.region || '-', Cidade: data.city || '-',
          Org: org, ASN: org.split(' ')[0] || '-',
          Datacenter: /digitalocean|amazon|ovh|hetzner|linode|google|microsoft/i.test(org) ? 'Sim' : 'Não'
        });
      } catch {
        callback({ IP: ip, País: '-', Região: '-', Cidade: '-', Org: '-', ASN: '-', Datacenter: 'Erro' });
      }
    });
  }).on('error', () => {
    callback({ IP: ip, País: '-', Região: '-', Cidade: '-', Org: '-', ASN: '-', Datacenter: 'Erro' });
  });
}

function registrarConexao(ip, porta) {
  const agora = Date.now();
  if (isWhitelisted(ip)) return;

  if (!historico[ip]) {
    historico[ip] = {
      inicio: agora,
      portas: [],
      contagem: 0,
      pontuacao: 0
    };
  }

  const reputacao = historico[ip];
  if (!reputacao.portas.includes(porta)) reputacao.portas.push(porta);
  reputacao.contagem++;
  reputacao.pontuacao += PORTAS_CRITICAS.includes(porta)
    ? PONTOS_POR_CRITICA
    : PONTOS_POR_PORTA;

  salvarReputacao();

  if (!isBlacklisted(ip) && reputacao.pontuacao >= LIMITE_PONTOS) {
    fetchIpInfo(ip, (info) => {
      const delta = ((Date.now() - reputacao.inicio) / 1000).toFixed(2);
      const dia = new Date().toISOString().slice(0, 10);
      const pastaDia = path.join(ABATIDOS, dia);
      fs.mkdirSync(pastaDia, { recursive: true });

      const relatorio = `
🧠 IP: ${info.IP}
🌐 País: ${info.País}
📍 Região: ${info.Região}
🏙️ Cidade: ${info.Cidade}
🏢 Org (ISP): ${info.Org}
🔢 ASN: ${info.ASN}
🏢 Datacenter: ${info.Datacenter}

🎯 Portas acessadas: ${reputacao.portas.join(', ')}
📈 Requisições: ${reputacao.contagem}
⚖️ Pontuação: ${reputacao.pontuacao}
⏱️ Tempo até punição: ${delta}s
🛡️ Tipo de bloqueio: TEMPORÁRIO (${TIMEOUT_MINUTOS} min)
📅 Quando: ${new Date().toISOString()}
      `.trim();

      fs.writeFileSync(path.join(pastaDia, `${ip}.txt`), relatorio + '\n');
      fs.appendFileSync(DEATH_NOTE, `\n===== IP: ${ip} (${dia}) =====\n${relatorio}\n`);
      fs.appendFileSync(BLACKLIST, ip + '\n');

      // 🔥 Adiciona bloqueio à cadeia TDROP (controlada pelo seu firewall)
      spawn('iptables', ['-I', 'TDROP', '1', '-s', ip, '-j', 'DROP']);

      console.log(`\x1b[41m💀 TEMP BLOCK: ${ip} (${info.País}) - ${info.Org} — RIP (${delta}s)\x1b[0m`);

      bloqueiosTemp[ip] = setTimeout(() => {
        spawn('iptables', ['-D', 'TDROP', '-s', ip, '-j', 'DROP']);
        console.log(`\x1b[32m✅ Desbloqueado: ${ip} após ${TIMEOUT_MINUTOS}min\x1b[0m`);
      }, TIMEOUT_MINUTOS * 60 * 1000);
    });

    delete historico[ip];
    salvarReputacao();
  }
}

const tcpdump = spawn('tcpdump', ['-lni', 'any', 'tcp']);

tcpdump.stdout.on('data', (data) => {
  const lines = data.toString().trim().split('\n');
  lines.forEach(line => {
    const match = line.match(/IP (\d+\.\d+\.\d+\.\d+)\.\d+ > \d+\.\d+\.\d+\.\d+\.(\d+):/);
    if (!match) return;
    const ip = match[1];
    const porta = match[2];
    registrarConexao(ip, porta);
  });
});

tcpdump.stderr.on('data', (err) => {
  const msg = err.toString();
  if (!msg.includes('listening') && !msg.includes('verbose')) {
    console.error(`\x1b[41mERRO TCPDUMP:\x1b[0m ${msg}`);
  }
});

process.on('SIGINT', () => {
  console.log('\x1b[33mDesligando tower defense monitor...\x1b[0m');
  tcpdump.kill('SIGINT');
  for (const ip in bloqueiosTemp) clearTimeout(bloqueiosTemp[ip]);
  salvarReputacao();
  process.exit();
});
