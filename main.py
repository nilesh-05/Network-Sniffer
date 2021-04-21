import socket
import struct
import textwrap


def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    # ntohs makes sure byte order is correct

    while True:
        raw_data, addr = connection.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\n Ethernet Frame : ')
        print('Destination : {} , Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))


# return formatted mac address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr


# unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# unpack ipv4
def ipv4(data):
    # version_header_len has both, version and IHL(header length)
    version_header_len = data[0]
    # to extract version from it, using right shift bitwise operator which will kick out IHL from the
    # version_header_len.
    version = version_header_len >> 4
    header_length = (version_header_len & 15) * 4
    # length of header is important because after header, the data starts. helpful in reading data
    ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s', data[:20])
    # x - pad bytes, B - unsigned char, s - char[], H - short
    return version, header_length, ttl, protocol, ipv4_format(src), ipv4_format(target), data[header_length:]


# formats ipv4
def ipv4_format(ip):
    return '.'.join(map(str, ip))


main()
