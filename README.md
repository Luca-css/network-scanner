# Network Scanner

Ferramenta de descoberta e inventário de rede. Escaneia ranges CIDR com multithreading, coleta hostname, endereço MAC, portas abertas e gera relatório HTML interativo.

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![Networking](https://img.shields.io/badge/Networking-0078D6?style=flat&logo=cisco&logoColor=white)

## Funcionalidades

- Scan paralelo com até 100 threads simultâneas
- Resolução de hostname via DNS reverso
- Coleta de MAC address via ARP
- Scan de portas comuns (SSH, RDP, SMB, HTTP, HTTPS...)
- Identificação visual de serviços expostos
- Relatório HTML com estatísticas de segurança

## Uso

```bash
# Instalar dependências (nenhuma externa necessária)
# Escanear rede padrão
python scanner.py

# Escanear range específico
python scanner.py 192.168.1.0/24
python scanner.py 10.0.0.0/16
```

## Saída

```
  NETWORK SCANNER
  Range: 192.168.1.0/24

  Escaneando 254 hosts...
  192.168.1.1    router.local          portas: [80, 443]
  192.168.1.10   servidor01.empresa    portas: [135, 445, 3389]
  192.168.1.25   workstation05         portas: [135, 139, 445]

  Relatório: scan_20260423_143022.html
```

## Requisitos

- Python 3.8+
- Permissão de administrador (para ARP e ICMP)
- Windows / Linux
