import struct
import socket
import http

def ethernet_head(raw_data):
    dest,src,proto=struct.unpack('! 6s 6s H',raw_data[:14])
    dest_mac=get_mac_addr(dest)
    src_mac=get_mac_addr(src)
    prototype=socket.htons(proto)
    data=raw_data[14:]
    return dest_mac,src_mac,prototype,data

def icmp_head(raw_data):
    type, code, checksum = struct.unpack('! B B H',raw_data[:4])
    data = raw_data[4:]
    return type, code, checksum, data

def udp_head(raw_data):
    src_port,dest_port,size=struct.unpack('! H H 2x H',raw_data[:8])
    data=raw_data[8:]
    return src_port,dest_port,size,data
   
def get_mac_addr(bytes_addr):
    bytes_str=map('{:02x}'.format,bytes_addr)
    mac_addr=':'.join(bytes_str).upper()
    return mac_addr

def format_multi_line(data):
    return '\n'.join(data.split('\n')[:-1])
    
def get_ip(addr):
    return '.'.join(map(str,addr))

def tcp_head(raw_data):
    src_port,dest_port,seq,ack,flag=struct.unpack('! H H L L H',raw_data[:14])
    offset=(flag>>12)*4
    flag_urg=(flag&32)>>5
    flag_ack=(flag&16)>>4
    flag_psh=(flag&8)>>3
    flag_rst=(flag&4)>>2
    flag_syn=(flag&2)>>1
    flag_fin=flag&1
    data=raw_data[offset:]
    return src_port,dest_port,seq,ack,flag,flag_urg,flag_ack,flag_psh,flag_rst,flag_syn,flag_fin,data

def ipv4_head(raw_data):
    version_header_length=raw_data[0]
    version=version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s',raw_data[:20])
    data = raw_data[header_length:]
    src=get_ip(src)
    target=get_ip(target)
    return version,header_length,ttl, proto, src, target, data

if __name__=='__main__':
    s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003))
    while True:
        raw_data, addr= s.recvfrom(65535)
        eth=ethernet_head(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0],eth[1],eth[2]))
        if eth[2]==8:
            ipv4=ipv4_head(eth[3])
            print('\nIPv4 Packet:')
            print('Version: {}, Header Length: {}, TTL: {}'.format(ipv4[0],ipv4[1],ipv4[2]))
            print('Protocol: {}, Source: {}, Target: {}'.format(ipv4[4],ipv4[5],ipv4[6]))
            if ipv4[4]==6:
                tcp=tcp_head(ipv4[7])
                print('\nTCP Packet:')
                print('Source Port: {}, Destination Port: {}, Sequence Number: {}, Acknowledgement Number: {}'.format(tcp[0],tcp[1],tcp[2],tcp[3]))
                print('Flags:')
                print('URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(tcp[4],tcp[5],tcp[6],tcp[7],tcp[8],tcp[9]))
                if len(tcp[10])>0:
                    if tcp[0]==80 or tcp[1]==80:
                        print('\nHTTP Data:')
                        try:
                            http=tcp[10].decode('utf-8')
                            http_info=str(http[10]).split('\n')
                            for line in http_info:
                                print(line)
                        except:
                            print(format_multi_line(tcp[10]))
                        else:
                            print(format_multi_line(tcp[10]))
                    elif ipv4==1:
                        icpm = icmp_head(ipv4[7])
                        print('\nICMP Packet:')
                        print('Type: {}, Code: {}, Checksum: {}'.format(icpm[0],icpm[1],icpm[2]))
                        print('Data: {}'.format(format_multi_line(icpm[3])))
                    elif ipv4==17:
                        udp=udp_head(ipv4[7])
                        print('\nUDP Packet:')
                        print('Source Port: {}, Destination Port: {}, Length: {}'.format(udp[0],udp[1],udp[2]))
                        print('Data: {}'.format(format_multi_line(udp[3])))


