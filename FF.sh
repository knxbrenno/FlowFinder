#!/usr/bin/env bash
# FlowFinder - análise rápida de arquivos PCAP usando tshark.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TOP=5             # Quantidade de itens exibidos nos rankings (alterável com -n)
FILTER=""         # Filtro de exibição do Wireshark aplicado a todas as análises (-f)
SCAN_THRESHOLD=15 # Portas distintas a partir das quais um par origem/destino é considerado varredura

banner() {
  if command -v figlet &> /dev/null; then
    figlet -f slant "FlowFinder"
  else
    echo -e "${BLUE}=== FlowFinder ===${NC}"
  fi
}

usage() {
  echo -e "Uso: $0 [opções] <arquivo.pcap>"
  echo "  -n <quantidade>   Quantidade de itens nos rankings (padrão: 5)"
  echo "  -f <filtro>       Filtro do Wireshark aplicado a tudo (ex: \"ip.addr == 10.0.0.5\")"
  echo "  -a                Executa todas as análises e sai (sem menu)"
  echo "  -o <arquivo>      Salva o relatório em um arquivo (sem cores)"
  echo "  -h                Exibe esta ajuda"
  echo
  echo "Exemplos:"
  echo "  $0 captura.pcap"
  echo "  $0 -a -o relatorio.txt captura.pcap"
  echo "  $0 -f \"tcp.port == 80\" -n 10 captura.pcapng"
  exit "${1:-1}"
}

print_header() {
  echo -e "${BLUE}========================${NC}"
  echo -e "${YELLOW}$1${NC}"
  echo -e "${BLUE}========================${NC}"
}

# Junta o filtro global (-f) com o filtro específico de cada análise.
combine_filter() {
  if [ -n "$FILTER" ] && [ -n "$1" ]; then
    echo "($FILTER) && ($1)"
  else
    echo "${FILTER:-$1}"
  fi
}

# Executa o tshark no pcap aplicando o filtro combinado. Uso: ts "<filtro>" [args do tshark...]
ts() {
  local filter
  filter=$(combine_filter "$1")
  shift
  if [ -n "$filter" ]; then
    tshark -r "$PCAP" -Y "$filter" "$@" 2> /dev/null
  else
    tshark -r "$PCAP" "$@" 2> /dev/null
  fi
}

# Extrai um ou mais campos do pcap, separados por vírgula.
fields() {
  local args=()
  for f in "$@"; do args+=(-e "$f"); done
  ts "" -T fields -E separator=, -E occurrence=f "${args[@]}"
}

# Conta as ocorrências de cada valor (ignorando linhas vazias) e exibe o ranking.
rank() {
  grep -v '^$' | sort | uniq -c | sort -nr | head -n "$TOP" \
    | awk '{c = $1; $1 = ""; printf "%-10s %s\n", c, substr($0, 2)}'
}

top_ip_src() {
  print_header "IPs com mais pacotes de origem"
  echo -e "${GREEN}Pacotes    IP${NC}"
  fields ip.src ipv6.src | tr -d ',' | rank
}

top_ip_dst() {
  print_header "IPs com mais pacotes de destino"
  echo -e "${GREEN}Pacotes    IP${NC}"
  fields ip.dst ipv6.dst | tr -d ',' | rank
}

top_protocols() {
  print_header "Protocolos mais usados"
  echo -e "${GREEN}Pacotes    Protocolo${NC}"
  fields _ws.col.Protocol | rank
}

top_ips_by_bytes() {
  print_header "IPs com maior tráfego em bytes (origem)"
  echo -e "${GREEN}$(printf '%-40s %s' IP Bytes)${NC}"
  fields ip.src ipv6.src frame.len \
    | awk -F, '{ip = $1 $2} ip != "" {arr[ip] += $3}
               END {for (ip in arr) printf "%-40s %d\n", ip, arr[ip]}' \
    | sort -k2 -nr | head -n "$TOP"
}

top_ports() {
  print_header "Portas de destino mais acessadas"
  echo -e "${GREEN}Pacotes    Porta${NC}"
  fields tcp.dstport udp.dstport \
    | awk -F, '$1 != "" {print $1 "/tcp"} $2 != "" {print $2 "/udp"}' \
    | rank
}

top_conversations() {
  print_header "Conversas mais ativas (origem -> destino)"
  echo -e "${GREEN}Pacotes    Conversa${NC}"
  fields ip.src ip.dst | awk -F, '$1 != "" {print $1 " -> " $2}' | rank
}

capture_period() {
  print_header "Período de captura"
  local times start_time end_time
  times=$(fields frame.time_epoch)
  start_time=$(echo "$times" | head -n 1 | cut -d. -f1)
  end_time=$(echo "$times" | tail -n 1 | cut -d. -f1)

  if [ -z "$start_time" ]; then
    echo -e "${RED}Nenhum pacote encontrado.${NC}"
    return
  fi

  echo -e "${GREEN}Início da captura: $(date -d "@$start_time" 2> /dev/null || date -r "$start_time")${NC}"
  echo -e "${GREEN}Fim da captura:    $(date -d "@$end_time" 2> /dev/null || date -r "$end_time")${NC}"
  echo -e "${GREEN}Duração:           $((end_time - start_time)) segundos${NC}"
  echo -e "${GREEN}Total de pacotes:  $(echo "$times" | wc -l)${NC}"
}

icmp_count() {
  print_header "Pacotes ICMP"
  local count
  count=$(ts "icmp || icmpv6" -T fields -e frame.number | wc -l)
  echo -e "${GREEN}Total de pacotes ICMP: $count${NC}"
  echo -e "${GREEN}Pacotes    Origem -> Destino${NC}"
  ts "icmp" -T fields -E separator=, -e ip.src -e ip.dst \
    | awk -F, '{print $1 " -> " $2}' | rank
}

dns_queries() {
  print_header "Domínios mais consultados (DNS)"
  echo -e "${GREEN}Consultas  Domínio${NC}"
  ts "dns.flags.response == 0" -T fields -e dns.qry.name | rank
}

http_hosts() {
  print_header "Hosts HTTP/TLS acessados"
  echo -e "${GREEN}Pacotes    Host${NC}"
  fields http.host tls.handshake.extensions_server_name | tr -d ',' | rank
}

http_requests() {
  print_header "Requisições HTTP"
  echo -e "${GREEN}Pacotes    Método URL${NC}"
  ts "http.request" -T fields -e http.request.method -e http.host -e http.request.uri \
    | awk -F'\t' '{print $1 " http://" $2 $3}' | rank
}

user_agents() {
  print_header "User-Agents HTTP"
  echo -e "${GREEN}Pacotes    User-Agent${NC}"
  ts "http.user_agent" -T fields -e http.user_agent | rank
}

# Procura credenciais trafegando em texto claro (FTP, HTTP, POP, IMAP, SMTP, Telnet).
cleartext_credentials() {
  print_header "Credenciais em texto claro"
  local found=0 out

  out=$(ts 'ftp.request.command == "USER" || ftp.request.command == "PASS"' \
        -T fields -e ip.src -e ip.dst -e ftp.request.command -e ftp.request.arg)
  [ -n "$out" ] && { echo -e "${YELLOW}[FTP]${NC}"; echo "$out"; found=1; }

  out=$(ts "http.authbasic" -T fields -e ip.src -e http.host -e http.authbasic)
  [ -n "$out" ] && { echo -e "${YELLOW}[HTTP Basic Auth]${NC}"; echo "$out" | sort -u; found=1; }

  out=$(ts 'http.request.method == "POST" && urlencoded-form' \
        -T fields -E occurrence=a -E aggregator='&' \
        -e ip.src -e http.host -e http.request.uri -e urlencoded-form.key -e urlencoded-form.value)
  [ -n "$out" ] && { echo -e "${YELLOW}[HTTP POST - formulários]${NC}"; echo "$out"; found=1; }

  out=$(ts 'pop.request.command == "USER" || pop.request.command == "PASS"' \
        -T fields -e ip.src -e ip.dst -e pop.request.command -e pop.request.parameter)
  [ -n "$out" ] && { echo -e "${YELLOW}[POP3]${NC}"; echo "$out"; found=1; }

  out=$(ts 'imap.request contains "LOGIN" || imap.request contains "login"' \
        -T fields -e ip.src -e ip.dst -e imap.request)
  [ -n "$out" ] && { echo -e "${YELLOW}[IMAP]${NC}"; echo "$out"; found=1; }

  out=$(ts "smtp.auth.username || smtp.auth.password" \
        -T fields -e ip.src -e ip.dst -e smtp.auth.username -e smtp.auth.password)
  [ -n "$out" ] && { echo -e "${YELLOW}[SMTP AUTH]${NC}"; echo "$out"; found=1; }

  out=$(ts "telnet.data" -T fields -e ip.src -e ip.dst -e telnet.data | head -n 30)
  [ -n "$out" ] && { echo -e "${YELLOW}[Telnet - primeiros dados]${NC}"; echo "$out"; found=1; }

  [ "$found" -eq 0 ] && echo -e "${GREEN}Nenhuma credencial em texto claro encontrada.${NC}"
}

# Detecta possíveis varreduras de portas: muitos SYN para portas diferentes do mesmo destino.
port_scan_detection() {
  print_header "Possíveis varreduras de portas (limite: $SCAN_THRESHOLD portas)"
  local out
  out=$(ts "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
        -T fields -E separator=, -e ip.src -e ip.dst -e tcp.dstport \
    | awk -F, -v lim="$SCAN_THRESHOLD" '
        !seen[$1 FS $2 FS $3]++ {ports[$1 " -> " $2]++}
        END {for (p in ports) if (ports[p] >= lim) printf "%-10d %s\n", ports[p], p}' \
    | sort -nr)

  if [ -n "$out" ]; then
    echo -e "${RED}Portas     Origem -> Destino${NC}"
    echo "$out"
  else
    echo -e "${GREEN}Nenhuma varredura detectada.${NC}"
  fi
}

# Exporta arquivos transferidos (HTTP, SMB, TFTP, FTP) para uma pasta.
export_objects() {
  print_header "Exportar arquivos transferidos"
  local dir="flowfinder_objetos_$(basename "${PCAP%.*}")"
  mkdir -p "$dir"
  for proto in http smb tftp ftp-data imf; do
    tshark -r "$PCAP" -q --export-objects "$proto,$dir/$proto" &> /dev/null
  done
  find "$dir" -type d -empty -delete 2> /dev/null

  if [ -d "$dir" ] && [ -n "$(find "$dir" -type f)" ]; then
    echo -e "${GREEN}Arquivos exportados para: $dir${NC}"
    find "$dir" -type f -exec ls -lh {} + | awk '{print $5 "\t" $NF}'
  else
    echo -e "${YELLOW}Nenhum arquivo encontrado para exportar.${NC}"
  fi
}

# Procura uma palavra no conteúdo dos pacotes (ex: flag{, password, senha).
search_string() {
  print_header "Buscar texto nos pacotes"
  read -r -p "Texto a procurar: " termo
  [ -z "$termo" ] && return
  termo="${termo//\\/\\\\}"
  termo="${termo//\"/\\\"}"

  echo -e "${GREEN}Frame      Origem -> Destino               Protocolo${NC}"
  ts "frame contains \"$termo\"" -T fields -E separator=, \
     -e frame.number -e ip.src -e ip.dst -e _ws.col.Protocol \
    | awk -F, '{printf "%-10s %-32s %s\n", $1, $2 " -> " $3, $4}' | head -n 50
}

# Mostra o conteúdo de uma conversa TCP (como o "Follow TCP Stream" do Wireshark).
follow_stream() {
  print_header "Seguir stream TCP"
  echo -e "${GREEN}Streams disponíveis (mais pacotes primeiro):${NC}"
  ts "tcp" -T fields -E separator=, -e tcp.stream -e ip.src -e ip.dst -e tcp.dstport \
    | awk -F, '!s[$1]++ {desc[$1] = $2 " -> " $3 ":" $4} {n[$1]++}
               END {for (k in n) printf "%-8s %-8s %s\n", k, n[k], desc[k]}' \
    | sort -k2 -nr | head -n "$TOP"
  read -r -p "Número do stream: " stream
  [[ "$stream" =~ ^[0-9]+$ ]] || { echo -e "${RED}Stream inválido.${NC}"; return; }
  tshark -r "$PCAP" -q -z "follow,tcp,ascii,$stream" 2> /dev/null | head -n 200
}

run_all() {
  top_ip_src; top_ip_dst; top_protocols; top_ips_by_bytes; top_ports
  top_conversations; capture_period; icmp_count; dns_queries; http_hosts
  http_requests; user_agents; cleartext_credentials; port_scan_detection
}

RUN_ALL=0
OUTPUT=""
while getopts ":n:f:ao:h" opt; do
  case $opt in
    n) TOP="$OPTARG" ;;
    f) FILTER="$OPTARG" ;;
    a) RUN_ALL=1 ;;
    o) OUTPUT="$OPTARG" ;;
    h) usage 0 ;;
    *) usage ;;
  esac
done
shift $((OPTIND - 1))

PCAP="$1"

banner

if [ -z "$PCAP" ]; then
  echo -e "${RED}Erro: nenhum arquivo informado.${NC}"
  usage
fi

if [ ! -f "$PCAP" ]; then
  echo -e "${RED}Erro: O arquivo '$PCAP' não existe.${NC}"
  exit 1
fi

if ! [[ "$TOP" =~ ^[0-9]+$ ]]; then
  echo -e "${RED}Erro: -n deve ser um número.${NC}"
  exit 1
fi

if ! command -v tshark &> /dev/null; then
  echo -e "${RED}Erro: tshark não está instalado. Instale-o com 'sudo apt install tshark'.${NC}"
  exit 1
fi

if ! tshark -r "$PCAP" -c 1 &> /dev/null; then
  echo -e "${RED}Erro: '$PCAP' não parece ser um arquivo de captura válido.${NC}"
  exit 1
fi

if [ -n "$FILTER" ] && ! tshark -r "$PCAP" -c 1 -Y "$FILTER" &> /dev/null; then
  echo -e "${RED}Erro: filtro inválido: $FILTER${NC}"
  exit 1
fi

# Com -o, tudo que aparece na tela também vai para o arquivo, sem os códigos de cor.
if [ -n "$OUTPUT" ]; then
  exec > >(tee >(sed -r 's/\x1B\[[0-9;]*m//g' > "$OUTPUT")) 2>&1
fi

echo -e "Arquivo: ${GREEN}$PCAP${NC}${FILTER:+   Filtro: ${GREEN}$FILTER${NC}}"

if [ "$RUN_ALL" -eq 1 ]; then
  run_all
  exit 0
fi

while true; do
  print_header "Escolha uma opção"
  echo -e "${YELLOW}
 1) IPs com mais tráfego de origem      11) Requisições HTTP
 2) IPs com mais tráfego de destino     12) User-Agents
 3) Protocolos mais usados              13) Credenciais em texto claro
 4) IPs com maior tráfego em bytes      14) Detectar varredura de portas
 5) Portas mais acessadas (TCP/UDP)     15) Exportar arquivos transferidos
 6) Período de captura                  16) Buscar texto nos pacotes
 7) Pacotes ICMP                        17) Seguir stream TCP
 8) Conversas mais ativas               18) Executar todas as análises
 9) Domínios consultados (DNS)
10) Hosts HTTP/TLS acessados             0) Sair
${NC}"

  read -r -p "Digite o número da opção desejada: " opcao

  case $opcao in
    1) top_ip_src ;;
    2) top_ip_dst ;;
    3) top_protocols ;;
    4) top_ips_by_bytes ;;
    5) top_ports ;;
    6) capture_period ;;
    7) icmp_count ;;
    8) top_conversations ;;
    9) dns_queries ;;
    10) http_hosts ;;
    11) http_requests ;;
    12) user_agents ;;
    13) cleartext_credentials ;;
    14) port_scan_detection ;;
    15) export_objects ;;
    16) search_string ;;
    17) follow_stream ;;
    18) run_all ;;
    0|q|"") exit 0 ;;
    *) echo -e "${RED}Opção inválida.${NC}" ;;
  esac
  echo
done
