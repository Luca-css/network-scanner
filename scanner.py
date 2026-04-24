"""
Network Scanner — descoberta e inventário de dispositivos na rede.
Escaneia ranges CIDR, coleta hostname, portas abertas e gera relatório HTML.
"""

import socket
import subprocess
import ipaddress
import json
import os
import sys
import concurrent.futures
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional


TIMEOUT_PING  = 1      # segundos
TIMEOUT_PORT  = 0.5
WORKERS       = 100
PORTAS_COMUNS = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 3389, 5985, 8080]


@dataclass
class Dispositivo:
    ip:        str
    hostname:  str           = "N/A"
    mac:       str           = "N/A"
    portas:    List[int]     = field(default_factory=list)
    latencia:  Optional[int] = None

    @property
    def ativo(self) -> bool:
        return self.latencia is not None


def ping(ip: str) -> Optional[int]:
    try:
        param = "-n" if sys.platform == "win32" else "-c"
        cmd = ["ping", param, "1", "-w", str(TIMEOUT_PING * 1000), ip]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT_PING + 1)
        if r.returncode == 0:
            for linha in r.stdout.splitlines():
                if "ms" in linha.lower() and ("tempo" in linha.lower() or "time" in linha.lower()):
                    import re
                    m = re.search(r"(\d+)ms", linha)
                    if m:
                        return int(m.group(1))
            return 0
    except Exception:
        pass
    return None


def resolver_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"


def resolver_mac(ip: str) -> str:
    try:
        r = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=3)
        for linha in r.stdout.splitlines():
            if ip in linha:
                partes = linha.split()
                for p in partes:
                    if "-" in p and len(p) == 17:
                        return p.upper()
                    if ":" in p and len(p) == 17:
                        return p.upper()
    except Exception:
        pass
    return "N/A"


def scan_portas(ip: str, portas: List[int]) -> List[int]:
    abertas = []
    for porta in portas:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(TIMEOUT_PORT)
                if s.connect_ex((ip, porta)) == 0:
                    abertas.append(porta)
        except Exception:
            pass
    return abertas


def escanear_host(ip: str) -> Dispositivo:
    dispositivo = Dispositivo(ip=ip)
    latencia = ping(ip)
    if latencia is None:
        return dispositivo
    dispositivo.latencia  = latencia
    dispositivo.hostname  = resolver_hostname(ip)
    dispositivo.mac       = resolver_mac(ip)
    dispositivo.portas    = scan_portas(ip, PORTAS_COMUNS)
    return dispositivo


def escanear_rede(cidr: str) -> List[Dispositivo]:
    rede  = ipaddress.IPv4Network(cidr, strict=False)
    hosts = list(rede.hosts())
    print(f"  Escaneando {len(hosts)} hosts em {cidr}...")

    resultados = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futuros = {executor.submit(escanear_host, str(h)): str(h) for h in hosts}
        concluidos = 0
        for futuro in concurrent.futures.as_completed(futuros):
            concluidos += 1
            if concluidos % 20 == 0:
                print(f"  Progresso: {concluidos}/{len(hosts)}")
            d = futuro.result()
            if d.ativo:
                resultados.append(d)

    return sorted(resultados, key=lambda d: [int(p) for p in d.ip.split(".")])


def gerar_html(dispositivos: List[Dispositivo], cidr: str, gerado_em: str) -> str:
    linhas = ""
    for d in dispositivos:
        portas_str = ", ".join(str(p) for p in d.portas) if d.portas else "—"
        rdp = "RDP" if 3389 in d.portas else ""
        ssh = "SSH" if 22    in d.portas else ""
        smb = "SMB" if 445   in d.portas else ""
        tags = " ".join(f'<span style="background:#1b4332;color:#6ee7b7;padding:2px 7px;border-radius:10px;font-size:.73rem">{t}</span>'
                        for t in [rdp, ssh, smb] if t)
        linhas += f"""
        <tr>
          <td><code>{d.ip}</code></td>
          <td>{d.hostname}</td>
          <td style="font-family:monospace;color:#8b949e">{d.mac}</td>
          <td>{d.latencia} ms</td>
          <td style="font-size:.8rem;color:#8b949e">{portas_str}</td>
          <td>{tags}</td>
        </tr>"""

    return f"""<!DOCTYPE html><html lang="pt-BR">
<head><meta charset="UTF-8"><title>Network Scan — {cidr}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#e6edf3}}
header{{background:linear-gradient(135deg,#1a237e,#283593);padding:20px 32px}}
header h1{{font-size:1.4rem}}header p{{opacity:.7;margin-top:4px;font-size:.85rem}}
.container{{max-width:1200px;margin:28px auto;padding:0 20px}}
.stats{{display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap}}
.stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px 20px;flex:1;min-width:120px}}
.stat .num{{font-size:1.8rem;font-weight:700;color:#58a6ff}}
.stat .label{{font-size:.78rem;color:#8b949e;margin-top:4px}}
.card{{background:#161b22;border:1px solid #30363d;border-radius:10px;overflow:hidden}}
table{{width:100%;border-collapse:collapse;font-size:.83rem}}
th{{background:#21262d;text-align:left;padding:10px 14px;color:#8b949e;font-weight:500}}
td{{padding:9px 14px;border-bottom:1px solid #21262d}}
tr:hover td{{background:#1c2128}}
tr:last-child td{{border:none}}
code{{background:#21262d;padding:2px 6px;border-radius:4px;font-size:.82rem}}
footer{{text-align:center;padding:20px;color:#484f58;font-size:.75rem}}
</style></head>
<body>
<header>
  <h1>Network Scanner — {cidr}</h1>
  <p>Gerado em: {gerado_em} &nbsp;|&nbsp; Hosts ativos: {len(dispositivos)}</p>
</header>
<div class="container">
  <div class="stats">
    <div class="stat"><div class="num">{len(dispositivos)}</div><div class="label">Hosts ativos</div></div>
    <div class="stat"><div class="num">{sum(1 for d in dispositivos if 3389 in d.portas)}</div><div class="label">RDP exposto</div></div>
    <div class="stat"><div class="num">{sum(1 for d in dispositivos if 22 in d.portas)}</div><div class="label">SSH exposto</div></div>
    <div class="stat"><div class="num">{sum(1 for d in dispositivos if 445 in d.portas)}</div><div class="label">SMB exposto</div></div>
  </div>
  <div class="card">
    <table>
      <thead><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Latência</th><th>Portas Abertas</th><th>Serviços</th></tr></thead>
      <tbody>{linhas}</tbody>
    </table>
  </div>
</div>
<footer>Network Scanner · github.com/Luca-css/network-scanner · {gerado_em}</footer>
</body></html>"""


def main():
    cidr = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.0/24"
    print(f"\n  NETWORK SCANNER")
    print(f"  Range: {cidr}\n")

    dispositivos = escanear_rede(cidr)
    gerado_em    = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

    print(f"\n  {len(dispositivos)} hosts ativos encontrados.\n")
    for d in dispositivos:
        print(f"  {d.ip:<16} {d.hostname:<30} portas: {d.portas}")

    saida = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html")
    with open(saida, "w", encoding="utf-8") as f:
        f.write(gerar_html(dispositivos, cidr, gerado_em))

    print(f"\n  Relatório: {saida}")
    try:
        os.startfile(saida)
    except Exception:
        pass


if __name__ == "__main__":
    main()
