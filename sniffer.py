# ==============================================================================
# PROJETO MODIFICADO PARA O TRABALHO DE REDES
# Alterações realizadas:
# 1. Substituição da biblioteca nativa 'socket' (Linux-only AF_PACKET) pelo 'scapy'
#    para garantir compatibilidade multiplataforma (Windows).
# 2. Inserção do módulo de segurança: Detecção de Ping Flood baseada na 
#    interpretação dos cabeçalhos IPv4 (Source IP) e ICMP (Type 8 - Echo Request).
# ==============================================================================

from scapy.all import sniff, raw
from collections import defaultdict
from general import format_multi_line
from networking.ethernet import Ethernet
from networking.ipv4 import IPv4
from networking.icmp import ICMP
from networking.tcp import TCP
from networking.udp import UDP
from networking.pcap import Pcap
from networking.http import HTTP

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

# --- VARIÁVEIS GLOBAIS DO NOVO MÓDULO DE SEGURANÇA ---
ping_counts = defaultdict(int)
PING_LIMIT = 10 # Alerta disparado após 10 pings do mesmo IP
pcap = None

def process_packet(packet):
    """
    Função de callback do Scapy. 
    Recebe o pacote da placa de rede, extrai os bytes e alimenta as classes originais.
    """
    global ping_counts, pcap
    
    try:
        # Extrai os bytes brutos do pacote do Scapy para manter a compatibilidade com o software base
        raw_data = raw(packet)
        
        if pcap:
            pcap.write(raw_data)
            
        eth = Ethernet(raw_data)

        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(eth.dest_mac, eth.src_mac, eth.proto))

        # IPv4
        if eth.proto == 8:
            ipv4 = IPv4(eth.data)
            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4.version, ipv4.header_length, ipv4.ttl))
            print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(ipv4.proto, ipv4.src, ipv4.target))

            # ICMP
            if ipv4.proto == 1:
                icmp = ICMP(ipv4.data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp.type, icmp.code, icmp.checksum))
                print(TAB_2 + 'ICMP Data:')
                print(format_multi_line(DATA_TAB_3, icmp.data))

                # =========================================================
                # NOVO RECURSO OBRIGATÓRIO: INTERPRETAÇÃO DE CABEÇALHOS
                # Lógica: Se o campo 'Type' do ICMP for 8 (Echo Request), contabiliza.
                # =========================================================
                if icmp.type == 8:  
                    ping_counts[ipv4.src] += 1
                    
                    if ping_counts[ipv4.src] > PING_LIMIT:
                        print('\n' + '='*70)
                        print(f'[!] ALERTA DE SEGURANÇA: Possível Ping Flood detectado!')
                        print(f'[!] ORIGEM SUSPEITA: O IP {ipv4.src} disparou múltiplos pacotes ICMP Type 8.')
                        print('='*70 + '\n')
                        
                        # Zera o contador após alertar para não flodar o terminal
                        ping_counts[ipv4.src] = 0
                # =========================================================

            # TCP
            elif ipv4.proto == 6:
                tcp = TCP(ipv4.data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp.src_port, tcp.dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(tcp.sequence, tcp.acknowledgment))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp.flag_urg, tcp.flag_ack, tcp.flag_psh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(tcp.flag_rst, tcp.flag_syn, tcp.flag_fin))

                if len(tcp.data) > 0:
                    # HTTP
                    if tcp.src_port == 80 or tcp.dest_port == 80:
                        print(TAB_2 + 'HTTP Data:')
                        try:
                            http = HTTP(tcp.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(format_multi_line(DATA_TAB_3, tcp.data))
                    else:
                        print(TAB_2 + 'TCP Data:')
                        print(format_multi_line(DATA_TAB_3, tcp.data))

            # UDP
            elif ipv4.proto == 17:
                udp = UDP(ipv4.data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp.src_port, udp.dest_port, udp.size))

            # Outros IPv4
            else:
                print(TAB_1 + 'Other IPv4 Data:')
                print(format_multi_line(DATA_TAB_2, ipv4.data))

        else:
            print('Ethernet Data:')
            print(format_multi_line(DATA_TAB_1, eth.data))
            
    except Exception as e:
        # Se algum pacote corrompido falhar nas classes originais, o sniffer apenas ignora e continua
        pass

def main():
    global pcap
    pcap = Pcap('capture.pcap')
    
    print("="*60)
    print("Sniffer Iniciado via Scapy (Compatível com Windows)")
    print("Módulo de Defesa: Detecção de Ping Flood ATIVADO!")
    print("Pressione Ctrl+C para encerrar.")
    print("="*60 + "\n")
    
    # Substitui o laço 'while True' original pela função sniff do Scapy
    # store=False é vital para a memória RAM do PC não encher durante a captura
    sniff(prn=process_packet, store=False)

    pcap.close()

if __name__ == '__main__':
    main()