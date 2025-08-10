const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const BASE = `${process.env.HOME}/firewall/logs`;
const PORTAS = `${BASE}/portas`;
const TODAY = `${BASE}/today`;
const BRUTE_ALL = `${BASE}/BruteLogs_tcpdump.txt`;
const BRUTE_OK = `${BASE}/BruteLogs_aceitas.txt`;
const BRUTE_BLOCK = `${BASE}/BruteLogs_rejeitadas.txt`;
const RELATORIO_DIR = `${BASE}/relatorios`;

const CURRENT_DATE = new Date().toISOString().slice(0, 10);
const logsHoje = `${TODAY}/acessos.txt`;
const logsPorta = `${TODAY}/por_porta.txt`;
const logsIP = `${TODAY}/por_ip.txt`;

fs.mkdirSync(PORTAS, { recursive: true });
fs.mkdirSync(TODAY, { recursive: true });
fs.mkdirSync(RELATORIO_DIR, { recursive: true });

let contadorPorPorta = {};
let contadorPorIP = {};
let conexoesPendentes = {};

function salvarRelatorio() {
  const portas = Object.entries(contadorPorPorta)
    .sort((a, b) => b[1] - a[1])
    .map(([porta, count]) => `${porta}: ${count} tentativas`)
    .join('\n');
  fs.writeFileSync(logsPorta, portas);

  const ips = Object.entries(contadorPorIP)
    .sort((a, b) => b[1] - a[1])
    .map(([ip, count]) => `${ip}: ${count} tentativas`)
    .join('\n');
  fs.writeFileSync(logsIP, ips);
}

function salvarRelatorioGordo() {
  const relatorioPath = `${RELATORIO_DIR}/${CURRENT_DATE}.txt`;

  const ipsOrdenados = Object.entries(contadorPorIP)
    .sort((a, b) => b[1] - a[1])
    .map(([ip, count]) => `- ${ip}: ${count} conexões`)
    .slice(0, 10)
    .join('\n');

  const portasOrdenadas = Object.entries(contadorPorPorta)
    .sort((a, b) => b[1] - a[1])
    .map(([porta, count]) => `- ${porta}: ${count} tentativas`)
    .slice(0, 10)
    .join('\n');

  const totalAceitas = fs.existsSync(BRUTE_OK) ? fs.readFileSync(BRUTE_OK, 'utf8').split('\n').filter(Boolean).length : 0;
  const totalBloqueadas = fs.existsSync(BRUTE_BLOCK) ? fs.readFileSync(BRUTE_BLOCK, 'utf8').split('\n').filter(Boolean).length : 0;
  const totalPendentes = Object.keys(conexoesPendentes).length;

  const timestamp = new Date().toISOString().slice(11, 19);

  const conteudo = `
📅 Relatório de Conexões – ${CURRENT_DATE}

🔢 Top IPs por tentativas:
${ipsOrdenados || '- Nenhum'}

🎯 Portas mais visadas:
${portasOrdenadas || '- Nenhuma'}

✅ Conexões aceitas: ${totalAceitas}
❌ Conexões bloqueadas: ${totalBloqueadas}
⏳ Conexões pendentes: ${totalPendentes}

🕒 Última atualização: ${timestamp}
`.trim();

  fs.writeFileSync(relatorioPath, conteudo + '\n');
}

const INTERFACE = 'eth0';
const tcpdump = spawn('tcpdump', ['-lni', INTERFACE, 'tcp']);

tcpdump.stdout.on('data', (data) => {
  const lines = data.toString().trim().split('\n');

  lines.forEach((line) => {
    const match = line.match(/IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > \d+\.\d+\.\d+\.\d+\.(\d+): Flags \[([^\]]+)]/);
    if (!match) return;

    const ip = match[1];
    const porta = match[3];
    const flags = match[4];
    const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
    const chave = `${ip}->${porta}`;

    if (flags === 'S') {
      conexoesPendentes[chave] = timestamp;

      const logLine = `[${timestamp}] IP: ${ip} → Porta: ${porta} ⏳ NOVA`;
      fs.appendFileSync(BRUTE_ALL, logLine + '\n');
      fs.appendFileSync(logsHoje, logLine + '\n');
      console.log(`\x1b[34m🔵 ${logLine}\x1b[0m`);

      const portaDir = path.join(PORTAS, porta);
      fs.mkdirSync(portaDir, { recursive: true });
      fs.appendFileSync(path.join(portaDir, `${CURRENT_DATE}.log`), logLine + '\n');

      contadorPorPorta[porta] = (contadorPorPorta[porta] || 0) + 1;
      contadorPorIP[ip] = (contadorPorIP[ip] || 0) + 1;

      salvarRelatorio();
      salvarRelatorioGordo();

      setTimeout(() => {
        if (conexoesPendentes[chave]) {
          const logLine = `[${conexoesPendentes[chave]}] IP: ${ip} → Porta: ${porta} ❌ BLOQUEADA`;
          fs.appendFileSync(BRUTE_BLOCK, logLine + '\n');
          console.log(`\x1b[31m🔴 ${logLine}\x1b[0m`);
          delete conexoesPendentes[chave];
          salvarRelatorioGordo();
        }
      }, 8000);
    }

    if (flags.includes('S.') || flags === '.') {
      if (conexoesPendentes[chave]) {
        const logLine = `[${conexoesPendentes[chave]}] IP: ${ip} → Porta: ${porta} ✅ ACEITA`;
        fs.appendFileSync(BRUTE_OK, logLine + '\n');
        console.log(`\x1b[32m🟢 ${logLine}\x1b[0m`);
        delete conexoesPendentes[chave];
        salvarRelatorioGordo();
      }
    }
  });
});

tcpdump.stderr.on('data', (err) => {
  const msg = err.toString();
  if (!msg.includes('verbose output') && !msg.includes('listening on') && !msg.includes('promiscuous')) {
    console.error(`\x1b[41mERRO TCPDUMP:\x1b[0m ${msg}`);
  }
});

process.on('SIGINT', () => {
  console.log('\x1b[33mEncerrando monitoramento...\x1b[0m');
  tcpdump.kill('SIGINT');
  process.exit();
});

