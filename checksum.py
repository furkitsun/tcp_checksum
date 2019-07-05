
def chksum(source :bytes):
	if len(source)%2:
		source += b'\x00'
	sum=0
	for i in range(0,len(source),2):
		sum = sum+((source[i]<<8)+(source[i+1]))
	sum = sum + (sum>>16)
	return ~sum & 0xffff		

