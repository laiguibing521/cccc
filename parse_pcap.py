"""

选拔赛要求：
完成如下要求中的 2 项：
1）能以直观友好的方式呈现出网络中的业务和分布情况；
2）能识别出网络攻击行为；
3）能识别出网络中的恶意软件行为；


# 知识
1、scapy 按照四层 TCP/IP 参考模型显示详细包信息: 链路层 [Ethernet]、网络层[IP]、传输层[TCP/UDP]、应用层[RAW]

2、一般来说流量分类可以基于下面的特征进行分类：源、目标MAC地址，源、目标IP地址，源、目标端口，IP协议版本、TCP源、目标端口，

  TCP报文长度，使用的应用层协议，协议中的关键字段（XMLRPC 的 RPC2，浏览器 HTTP 的 GET）


----------
2020-7-19
来桂兵
---------
"""


import scapy
from scapy.all import *
from scapy.utils import PcapReader

packets_attack = rdpcap("Data/ATTACK/0__a2_out.pcap")
packets_app = rdpcap("Data/APP/0__a2_out.pcap")

def analysis_attack():
    print(len(packets_attack))  # 27
    for data_att in packets_attack:
        # print(data_att)                   # 二进制数据
        print(repr(data_att))              # 以太网格式的数据
        # print(type(data_att))              # 类型
        # print(data_att.payload.name, data_att.payload.proto)       # 打印出 'IP','IPV6','ARP' 或者其他
        # try:
        #     print(data_att['UDP'].sport)
        # except:
        #     pass
        # try:
        #     print(data_att['TCP'].sport)  # 打印 TCP 的端口
        # except:
        #     pass


def analysis_app():
    # print(len(packets_app))    #178
    # for data_app in packets_app:
    #     print(repr(data_app))
    for data_app in packets_app[2]:          # packets_app[0]  是第一条数据
        print('-' * 50)
        data_app.show()
        print('-' * 50)
    # for data_app in packets_app[-1]:         # packets_app[-1]  是最后一条数据
    #     print('-' * 50)
    #     data_app.show()
    #     print('-' * 50)
        #
        # print(data_app.name)                   # 链路层 Ethernet
        # print(data_app.dst)
        # print(data_app.src)
        # print(data_app.type)                   # ARP：2045  IPV4：2048
        # print(data_app.payload.name)           # ip层
        #
        # print(data_app.payload.payload.name)   # tcp层



def analysis_pcap():
    packets = [packets_attack, packets_app]
    for packet in packets:
        for p in packet:
            print("-" * 200)
            # 判断是否包含Ethernet层，用haslayer
            if p.haslayer("Ethernet"):
                dst_eth = p['Ethernet'].dst        # 目的MAC
                src_eth = p['Ethernet'].src        # 源MAC
                type_eth = p['Ethernet'].type      # ARP:2045  IPV4:2048
                print("源MAC: %s" % src_eth)
                print("目的MAC: %s" % dst_eth)
                print("类型MAC: %s" % type_eth)
                print('-' * 30)


            # 判断是否包含ARP层，用haslayer
            if p.haslayer("ARP"):
                type_arp = p['ARP'].ptype         # 协议类型
                hwlen_arp = p['ARP'].hwlen        # MAC长度
                plen_arp = p['ARP'].plen          # 协议长度
                hwsrc_arp = p['ARP'].hwsrc        # 源主机MAC地址
                src_arp = p["ARP"].psrc           # 源主机IP
                hwdst_arp = p['ARP'].hwdst        # 目的主机MAC地址
                dst_arp = p["ARP"].pdst           # 目的主机IP
                print("协议类型: %s" % type_arp)
                print("MAC长度: %s" % hwlen_arp)
                print("协议长度: %s" % plen_arp)
                print("源主机MAC地址: %s" % hwsrc_arp)
                print("源主机IP: %s" % src_arp)
                print("目的主机MAC地址: %s" % hwdst_arp)
                print("目的主机IP: %s" % dst_arp)
                print('-' * 30)


            # 判断是否包含IP层，用haslayer
            if p.haslayer("IP"):
                version_ip = p["IP"].version        # 版本
                ihl_ip = p["IP"].ihl                # 首部长度
                len_ip = p["IP"].len                # IP总长度
                id_ip = p["IP"].src                 # IP标识
                flags_ip = p["IP"].src              # IP标志
                frag_ip = p["IP"].src               # IP片偏移
                ttl_ip = p["IP"].ttl                # IP生存时间
                proto_ip = p["IP"].proto            # IP上层协议
                src_ip = p["IP"].src                # 源IP
                dst_ip = p["IP"].dst                # 目的IP

                print("IP版本: %s" % version_ip)
                print("IP首部长度: %s" % ihl_ip)
                print("IP总长度: %s" % len_ip)
                print("IP标识: %s" % id_ip)
                print("IP标志: %s" % flags_ip)
                print("IP片偏移: %s" % frag_ip)
                print("IP生存时间: %s" % ttl_ip)
                print("IP上层协议: %s" % proto_ip)
                print("源IP: %s" % src_ip)
                print("目的IP: %s" % dst_ip)
                print('-' * 30)


            # 判断是否包含TCP层，用haslayer
            if p.haslayer("TCP"):
                # 获取某一层的原始负载用.payload.original
                raw_http = p["TCP"].payload.original
                sport = p["TCP"].sport               # 源端口
                dport = p["TCP"].dport               # 目的端口
                seq = p["TCP"].seq                   # 序号
                ack = p["TCP"].ack                   # 确认号
                dataofs = p["TCP"].dataofs           # 首部长度

                print("源端口: %s" % sport)
                print("目的端口: %s" % dport)
                print("序号: %s" % seq)
                print("确认号: %s" % ack)
                print("首部长度: %s" % dataofs)
                # print("raw_http:\n%s" % raw_http)
                print('-' * 30)


            #  HttpRequest
            # if p.haslayer("HTTPRequest"):
            #     host = p["HTTPRequest"].Host
            #     uri = p["HTTPRequest"].Path
            #     # 直接获取提取好的字典形式的http数据用fields
            #     http_fields = p["HTTPRequest"].fields
            #     http_payload = p["HTTPRequest"].payload.fields
            #     print("host: %s" % host)
            #     print("uri: %s" % uri)
            #     print("http_fields:\n%s" % http_fields)
            #     print('-' * 30)



if __name__ == '__main__':
    # analysis_attack()
    # print('-' * 200)
    # analysis_app()
    analysis_pcap()
