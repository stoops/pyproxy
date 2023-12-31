#!/usr/bin/python3
import ciph, fcntl, threading, array
import os, sys, time, argparse
import select, socket, struct, subprocess

PROT = "tcp"

class ipvf:
	def __init__(self, data):
		try:
			head = struct.unpack("!BBHHHBBH4s4s", data[:20])
			(self.vers, self.ihlv, self.dscp, self.ecnv) = (head[0] >> 4, head[0] & 0xf, head[1] >> 2, head[1] & 0x3)
			(self.leng, self.iden, self.offs, self.frag) = (head[2], head[3], head[4] >> 13, head[4] & 0x1fff)
			(self.ttlv, self.prot, self.sums) = (head[5], head[6], head[7])
			self.sadr = socket.inet_ntoa(head[8])
			self.dadr = socket.inet_ntoa(head[9])
		except Exception as e:
			(self.vers, self.ihlv, self.dscp, self.ecnv) = (None, None, None, None)
			(self.leng, self.iden, self.offs, self.frag) = (None, None, None, None)
			(self.ttlv, self.prot, self.sums) = (None, None, None)
			self.sadr = None
			self.dadr = None
	def wich(self):
		if (self.prot == 17):
			return "udp"
		elif (self.prot == 6):
			return "tcp"
		return None

def intf(name, addr):
	(IFF_TUN, IFF_NO_PI, IFF_MULTI_QUEUE, TUNSETIFF) = (0x0001, 0x1000, 0x0100, 0x400454CA)
	sifs = struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI)
	tuns = open("/dev/net/tun", "r+b", buffering=0)
	fcntl.ioctl(tuns, TUNSETIFF, sifs)
	subprocess.Popen("ip link set %s up ; ip addr add %s/24 dev %s" % (name, addr, name, ), shell=True)
	return tuns

def stdo(line):
	secs = str(time.time()).split(".")[1].zfill(9)
	date = time.strftime("%b-%d-%Y/%H:%M:%S")
	sys.stdout.write("[%s.%s] %s\n" % (date, secs, line, ))
	sys.stdout.flush()

def ints(inpt):
	try:
		return int(inpt)
	except:
		return -1

def sels(socs, wait):
	try:
		return select.select(socs, [], [], wait)
	except:
		return ([], [], [])

def syns(objc, dest):
	try:
		objc.connect(dest)
	except:
		return False
	return True

def shut(objc):
	try:
		objc.shutdown(socket.SHUT_RDWR)
	except:
		pass
	try:
		objc.close()
	except:
		pass
	return None

def recs(objc, size, mode):
	try:
		if (mode == "d"):
			#return objc.read(size)
			return os.read(objc.fileno(), size)
		if (mode == "t"):
			return objc.recv(size)
		if (mode == "p"):
			return objc.recv(size)
		if (mode == "u"):
			return objc.recvfrom(size)
	except:
		pass
	if (PROT == "udp"):
		return (b"", None)
	return b""

def send(objc, data, mode, addr=None):
	try:
		if (mode == "d"):
			#objc.write(data)
			os.write(objc.fileno(), data)
		if (mode == "t"):
			objc.sendall(data)
		if (mode == "p"):
			objc.send(data)
		if (mode == "u"):
			objc.sendto(data, addr)
	except:
		return -1
	return 1

def sksa(objc, keys, init):
	kind = PROT
	try:
		objc.sksa(kind, keys, init)
	except:
		return False
	return True

def prga(objc, mode, skey, data):
	(outp, kind) = (data, PROT)
	if (data and objc):
		try:
			outp = objc.prga(kind, mode, skey, data)
		except:
			pass
	return outp

def lrme(indx, devs, ques, sepr, sock, arcs):
	last = [0, 0]
	while True:
		(rfds, wfds, efds) = sels([devs], 1)
		if (devs in rfds):
			data = recs(devs, 1900, "d")
			if (not data):
				continue
			leng = len(data)
			#head = ipvf(data)
			#kind = head.wich()
			kind = True
			secs = time.time()
			if (kind):
				#print(">",kind,head.sadr,head.dadr,leng)
				if ((secs - last[0]) >= 3):
					rate = int(((last[1] / (secs - last[0])) * 8) / 1000000)
					stdo("> lrme %s %s %s %s/mbps" % (indx, leng, data[:32], rate, ))
					last = [secs, 0]
				zero = b"0"
				ques.append(data)
				sent = send(sock, zero, "p")
				last[1] += leng

def lwme(indx, srvs, ques, sepr, sock, arcs):
	addr = None
	last = [0, 0]
	while True:
		if (not srvs["sock"]):
			if (type(srvs["dest"]) == tuple):
				if (PROT == "udp"):
					srvs["sock"] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
					if (not addr):
						addr = srvs["dest"]
						srvs["dest"] = (addr[0], addr[1] + indx)
				else:
					srvs["sock"] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					if (not syns(srvs["sock"], srvs["dest"])):
						stdo("! erro lwme syns")
						srvs["sock"] = shut(srvs["sock"])
		if (not srvs["sock"]):
			time.sleep(3)
			continue
		conn = srvs["sock"]
		(rfds, wfds, efds) = sels([sock], 1)
		if (sock in rfds):
			data = recs(sock, 1, "p")
			if (not data):
				continue
			buff = b""
			secs = time.time()
			while (ques):
				mesg = ques.pop(0)
				leng = len(mesg)
				if ((secs - last[0]) >= 3):
					rate = int(((last[1] / (secs - last[0])) * 8) / 1000000)
					stdo("> lwme %s %s %s %s/mbps" % (indx, len(mesg), mesg[:32], rate, ))
					last = [secs, 0]
				if (PROT == "tcp"):
					mesg = (str(leng).encode() + sepr + mesg)
					buff += mesg
				else:
					mesg = prga(arcs[0], "e", arcs[1][0], mesg)
					sent = send(conn, mesg, "u", addr=srvs["dest"])
				last[1] += leng
			if (buff):
				mesg = prga(arcs[0], "e", arcs[1][0], buff)
				sent = send(conn, mesg, "t")
				if (sent < 1):
					stdo("! erro lwme sent")
					srvs["sock"] = shut(conn)
					continue

def rrme(indx, srvs, ques, sepr, sock, arcs):
	addr = None
	buff = b""
	last = [0, 0]
	while True:
		if (not srvs["sock"]):
			time.sleep(3)
			continue
		conn = srvs["sock"]
		(rfds, wfds, efds) = sels([conn], 1)
		if (conn in rfds):
			data = recs(conn, 9500, "t")
			#(data, addr) = recs(conn, 1900, "u")
			data = prga(arcs[0], "d", arcs[1][1], data)
			if (not data):
				stdo("! erro rrme data")
				srvs["sock"] = shut(conn) # if prot == tcp
				continue
			if (addr):
				srvs["dest"] = addr
			if (PROT == "tcp"):
				zero = b""
				buff += data
				secs = time.time()
				while (sepr in buff):
					info = buff.split(sepr, 1)
					leng = ints(info[0])
					mesg = info[1][:leng]
					if (leng < 1):
						stdo("! warn rrme leng %s %s" %  (leng, buff, ))
						#srvs["sock"] = shut(conn)
						break
					if (len(mesg) != leng):
						#stdo("! warn rrme mesg %s %s" % (len(mesg), leng, ))
						#re-read?
						break
					if ((secs - last[0]) >= 3):
						rate = int(((last[1] / (secs - last[0])) * 8) / 1000000)
						stdo("< rrme %s %s %s %s/mbps" % (indx, leng, mesg[:32], rate, ))
						last = [secs, 0]
					zero = b"0"
					ques.append(mesg)
					buff = info[1][leng:]
					last[1] += leng
				if (zero):
					sent = send(sock, zero, "p")
			else:
				leng = len(data)
				if ((secs - last[0]) >= 3):
					rate = int(((last[1] / (secs - last[0])) * 8) / 1000000)
					stdo("< rrme %s %s %s %s/mbps" % (indx, leng, data[:32], rate, ))
					last = [secs, 0]
				zero = b"0"
				ques.append(data)
				sent = send(sock, zero, "p")

def rwme(indx, devs, ques, sepr, sock, arcs):
	last = [0, 0]
	while True:
		(rfds, wfds, efds) = sels([sock], 1)
		if (sock in rfds):
			data = recs(sock, 1, "p")
			if (not data):
				continue
			buff = b""
			while (ques):
				mesg = ques.pop(0)
				leng = len(mesg)
				buff += mesg
				secs = time.time()
				if ((secs - last[0]) >= 3):
					rate = int(((last[1] / (secs - last[0])) * 8) / 1000000)
					stdo("> rwme %s %s %s %s/mbps" % (indx, len(mesg), mesg[:32], rate, ))
					last = [secs, 0]
				sent = send(devs, mesg, "d")
				last[1] += leng
			#if (buff):
			#	sent = send(devs, buff, "d")

def main():
	argp = argparse.ArgumentParser(description="socks")
	argp.add_argument("-e", "--encr", action="store")
	argp.add_argument("-d", "--decr", action="store")
	argp.add_argument("-f", "--fork", action="store")
	argp.add_argument("-i", "--intf", action="store", default="tun0:10.0.0.1")
	argp.add_argument("-k", "--keys", action="store")
	args = argp.parse_args(sys.argv[1:])
	thrs = []

	if (args.decr):
		if (PROT == "tcp"):
			info = args.decr.split(":")
			addr = (info[0], int(info[1]))
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			sock.bind(addr)
			sock.listen(1)

	for indx in range(0, 1):
		info = args.intf.split(":")
		tuns = intf(info[0], info[1])
		(dest, conn) = (None, None)
		(sepr, buff) = (b"\n", b"")
		(lque, rque) = ([], [])
		(lrfd, lwfd) = socket.socketpair()
		(rrfd, rwfd) = socket.socketpair()
		arcs = (None, ["r", "s"])

		if (args.keys):
			arcs = (ciph.ArcfCiph(args.keys), arcs[1])
			init = str(time.time()) # if prot == tcp: attach key, assign object, send init, error handle
			sksa(arcs[0], arcs[1], args.keys)

		if (args.encr):
			info = args.encr.split(":")
			dest = (info[0], int(info[1]))
			conn = { "dest":dest, "sock":None }
		else:
			conn = { "dest":None, "sock":None }
			if (PROT == "udp"):
				info = args.decr.split(":")
				addr = (info[0], int(info[1]) + indx)
				sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
				sock.bind(addr)
				conn["sock"] = sock
			arcs = (arcs[0], ["s", "r"])

		lrth = threading.Thread(target=lrme, args=(indx, tuns, lque, sepr, lrfd, arcs))
		lrth.start()
		lwth = threading.Thread(target=lwme, args=(indx, conn, lque, sepr, lwfd, arcs))
		lwth.start()
		rrth = threading.Thread(target=rrme, args=(indx, conn, rque, sepr, rrfd, arcs))
		rrth.start()
		rwth = threading.Thread(target=rwme, args=(indx, tuns, rque, sepr, rwfd, arcs))
		rwth.start()
		thrs.append([[tuns, conn], [lrfd, lwfd, rrfd, rwfd], [lrth, lwth, rrth, rwth]])

	while True:
		if (args.decr):
			if (PROT == "tcp"):
				stat = False
				(conn, addr) = sock.accept()
				for x in range(0, len(thrs)):
					cons = thrs[x][0][1]
					if (not cons["sock"]):
						stdo("* main %s %s" % (x, addr, ))
						cons["sock"] = conn
						stat = True ; break
				if (not stat):
					stdo("! erro main stat")
					conn = shut(conn)
		time.sleep(1)
	tuns.close()

if (__name__ == "__main__"):
	main()
