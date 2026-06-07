# Multiplatform Python Packet Sniffer & Ping Flood Detector

Este projeto é um sniffer de rede multiplataforma escrito em Python. Ele atua interceptando o tráfego de rede da interface hospedeira e realizando o unpacking contínuo de protocolos (Ethernet, IPv4, TCP, UDP, ICMP, HTTP). 

Como diferencial de segurança, possui um Módulo Ativo de Detecção de Ping Flood, que interpreta os cabeçalhos IPv4 e ICMP para alertar sobre anomalias e negação de serviço na rede local.

##  Tecnologias e Bibliotecas
- Python 3.x
- [Scapy](https://scapy.net/) (Motor de captura multiplataforma e filtros BPF)
- Estrutura base inspirada no repositório didático de buckyroberts.

## Instalação
1. Clone este repositório:
   `git clone https://github.com/Jfinatto/Python-Packet-Sniffer-com-detector-de-ping-flood.git`
2. Instale as dependências necessárias:
   `pip install scapy`
   *(Nota para usuários Windows: Certifique-se de possuir o driver Npcap instalado, comumente incluído com o Wireshark).*

##  Como Executar
O sniffer precisa de acesso direto à interface de rede, logo, deve ser executado com privilégios de administrador.

**No Windows (Abra o CMD como Administrador):**
```bash
python main.py

**no linux/MacOS:**
sudo python3 main.py