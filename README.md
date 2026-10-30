# FlowFinder

Ferramenta em Bash para análise rápida de arquivos **PCAP/PCAPNG** usando o `tshark`. Ideal para CTFs, investigação de incidentes e estudo de redes: em poucos segundos mostra quem mais conversou, quais protocolos e portas foram usados, credenciais em texto claro, varreduras de portas e muito mais.

## Funcionalidades

| # | Análise |
|---|---|
| 1-2 | IPs com mais pacotes de origem/destino (IPv4 e IPv6) |
| 3 | Protocolos mais usados |
| 4 | IPs com maior tráfego em bytes |
| 5 | Portas de destino mais acessadas (TCP e UDP) |
| 6 | Período de captura, duração e total de pacotes |
| 7 | Pacotes ICMP e quem os enviou |
| 8 | Conversas mais ativas (origem → destino) |
| 9 | Domínios consultados via DNS |
| 10 | Hosts HTTP e SNI de conexões TLS |
| 11 | Requisições HTTP (método + URL) |
| 12 | User-Agents |
| 13 | **Credenciais em texto claro**: FTP, HTTP Basic, formulários POST, POP3, IMAP, SMTP e Telnet |
| 14 | **Detecção de varredura de portas** (muitos SYN para portas diferentes) |
| 15 | **Exportação de arquivos** transferidos via HTTP, SMB, TFTP, FTP e e-mail |
| 16 | Busca de texto no conteúdo dos pacotes (ex: `flag{`, `password`) |
| 17 | Seguir stream TCP (igual ao *Follow TCP Stream* do Wireshark) |
| 18 | Executar todas as análises |

Também é possível:
- aplicar um **filtro do Wireshark** em todas as análises (`-f`);
- gerar um **relatório** em arquivo, sem códigos de cor (`-o`);
- rodar tudo sem menu (`-a`), útil em scripts.

## Instalação

```bash
sudo apt install tshark figlet   # figlet é opcional (apenas o banner)
git clone https://github.com/knxbrenno/FlowFinder.git
cd FlowFinder
chmod +x FF.sh
```

## Uso

```bash
./FF.sh [opções] <arquivo.pcap>
```

| Opção | Descrição |
|---|---|
| `-n <quantidade>` | Quantidade de itens nos rankings (padrão: 5) |
| `-f <filtro>` | Filtro do Wireshark aplicado a tudo |
| `-a` | Executa todas as análises e sai |
| `-o <arquivo>` | Salva o relatório em um arquivo |
| `-h` | Ajuda |

### Exemplos

```bash
# Menu interativo
./FF.sh captura.pcap

# Relatório completo em arquivo
./FF.sh -a -o relatorio.txt captura.pcap

# Top 10, apenas tráfego de um host
./FF.sh -n 10 -f "ip.addr == 192.168.0.10" captura.pcapng
```

## Aviso

Ferramenta para fins educacionais e análise de tráfego autorizado.
