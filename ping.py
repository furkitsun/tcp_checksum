import socket 
import struct 
import random

def chksum(source :bytes):
	if len(source)%2:
		source += b'\x00'
	sum=0
	for i in range(0,len(source),2):
		sum = sum+((source[i]<<8)+(source[i+1]))
	sum = sum + (sum>>16)
	return ~sum & 0xffff		

	
def create_packet(id):
	header = struct.pack('bbHHh',8,0,0,id,1)
	data = 192*bytes('Q','utf-8')

	my_check = chksum(header+data)
	
	header = struct.pack('bbHHh',8,0,socket.htons(my_check),id,1)
	return header+data 

def catch_ping_reply(s,ID):
	while True:
		rec_packet,addr = s.recvfrom(1024)
		ip_header = rec_packet[0:20]
		ip_ihl, ip_type,ip_header_file,ID,ip_flags ,ip_ttl,ip_proto,ip_sum,ip_src, ip_dest = struct.unpack("BBHHHBBH4s4s",ip_header)
		print("ihl: %s" % str(ip_ihl))
		print("ip_type: %s" % str(ip_type))
		print("ip_ttl : %s "% str(ip_ttl))
		print("ip_src: %s "% str(socket.inet_ntoa(ip_src)))
		print("ip_dest: %s" % str(socket.inet_ntoa(ip_dest)))

		icmp = rec_packet[20:28]
		icmp_type,code,check,p_id,sequence = struct.unpack('bbHHh',icmp)
		print("type :%s" % icmp_type)
		print("code :%s" % code)
		print("check : %02x" %check)
		print("p_id : %02x" % p_id)
		print("sequence : %02x" % sequence)
		if p_id == ID : 
			return rec_packet 

def single_ping_request(s,addr=None):
	pkt_id = random.randrange(10000,65000)

	packet = create_packet(pkt_id)
	
	while packet:
		send = s.sendto(packet,(addr,1))
		packet = packet[send:]
	return pkt_id 

def main():
	addr = "192.168.1.1"
	s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
	ID = single_ping_request(s,addr)
	reply = catch_ping_reply(s,ID)
	s.close()
	return


main()
