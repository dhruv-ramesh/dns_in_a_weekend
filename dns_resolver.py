from dns_query import header_to_bytes, question_to_bytes, encode_dns_name, build_query
from dns_parser import DNSHeader, DNSPacket, DNSRecord, DNSQuestion
from dns_parser import (
    decode_name,
    parse_header,
    parse_question,
    parse_dns_packet,
    ip_to_string,
    TYPE_NS,
    TYPE_A,
)
import socket


def send_query(ip_address, domain_name, record_type):
    query = build_query(domain_name=domain_name, record_type=record_type)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, (ip_address, 53))

    data, _ = sock.recvfrom(1024)
    return parse_dns_packet(data)


def get_answer(packet):
    for x in packet.answers:
        if x.type_ == TYPE_A:
            return x.data


def get_nameserver_ip(packet):
    for x in packet.additionals:
        if x.type_ == TYPE_A:
            return x.data


def get_nameserver(packet):
    for x in packet.authorities:
        if x.type_ == TYPE_NS:
            return x.data.decode("utf-8")


def resolve(domain_name, record_type):
    name_server = "198.41.0.4"
    while True:
        print(f"Querying {name_server} for {domain_name}")
        response = send_query(name_server, domain_name, record_type)
        if ip := get_answer(response):
            return ip
        elif nsip := get_nameserver_ip(response):
            name_server = nsip
        elif ns_domain := get_nameserver(response):
            name_server = resolve(ns_domain, TYPE_A)
        else:
            raise Exception("Something went wrong")


if __name__ == "__main__":
    print(resolve("google.com", TYPE_A))
