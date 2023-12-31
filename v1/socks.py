#!/usr/bin/python3

import os, sys, time, argparse
import struct, select, socket, threading

from comm import *
import ciph

(SOCKVERS, SOCKAUTH, SOCKSTAT, SOCKNULL, SOCKIPVF) = (5, 0, 0, 0, 1)
SOCKSIZE = { "tcp":8192, "udp":1500 }
SOCKTIME = { "tcp":150000, "udp":150 }
SOCKCOMD = { "tcp":1, "bnd":2, "udp":3 }
SOCKTYPE = { "tcp":socket.SOCK_STREAM, "udp":socket.SOCK_DGRAM }
SOCKMAPS = {}
SOCKKEYS = None
SOCKEXEC = "/usr/bin/true"
SOCKNOTS = []
SOCKREMO = ("0.0.0.0", 0)

class BaseRequestHandler:
	def __init__(self, request, client_address, server):
		self.request = request
		self.client_address = client_address
		self.server = server
		self.handle()

class SockProx:
	sepr = b"\n"

	def __init__(self, host, prot):
		self.host = host
		self.prot = prot

	def numb(self, size):
		return str(size).encode()

	def ints(self, strs):
		try:
			return int(strs)
		except:
			return -1

	def recv(self, prot, sock, size):
		if (prot == "tcp"):
			return trea(sock, size=size)
		if (prot == "udp"):
			return recv(sock, size=size)

	def recs(self, sock, size, wait=3, trys=3):
		o = b""
		for x in range(0, trys):
			leng = (size - len(o))
			if (leng < 1):
				break
			(r, w, e) = sels([sock], wait=wait)
			if (sock in r):
				o += self.recv("tcp", sock, leng)
		return o

	def pack(self, form, data, size):
		try:
			outp = struct.unpack(form, data)
		except:
			outp = tuple([None for x in range(0, size)])
		return outp

	def wrap(self, arcs, mode, data, oper=True):
		if (data and arcs and oper):
			data = prga(arcs[0], "tcp", mode, arcs[1][mode], data)
		return data

	def conn(self, addr, dest, keys=None):
		outp = (None, None)
		(self.addr, self.dest, self.arcs) = (addr, dest, None)
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

		syns(self.sock, self.host)

		if (keys and (keys != "x")):
			self.arcs = (ciph.ArcfCiph(keys), { "e":"r", "d":"s" })
			ivec = str(time.time())
			sksa(self.arcs[0], "tcp", ["r", "s"], ivec)
			init = (ivec.encode() + SockProx.sepr)
			mesg = self.wrap(self.arcs, "e", b"1337")
			tsnd(self.sock, init + mesg)

		(vers, meth, kind) = (SOCKVERS, 1, SOCKAUTH)
		mesg = struct.pack("!BBB", vers, meth, kind)
		mesg = self.wrap(self.arcs, "e", mesg)
		tsnd(self.sock, mesg)

		resp = self.recs(self.sock, 2)
		resp = self.wrap(self.arcs, "d", resp)
		(vers, auth) = self.pack("!BB", resp, 2)
		if (auth != SOCKAUTH):
			stdo("erro conn auth")
			shut(self.sock)
			return outp

		(vers, comd, null, kind) = (SOCKVERS, SOCKCOMD[self.prot], SOCKNULL, SOCKIPVF)
		head = struct.pack("!BBBB", vers, comd, null, kind)
		(dadr, port) = (self.dest[0], self.dest[1])
		data = (socket.inet_pton(socket.AF_INET, dadr) + struct.pack("!H", port))
		mesg = (head + data)
		mesg = self.wrap(self.arcs, "e", mesg)
		tsnd(self.sock, mesg)

		resp = self.recs(self.sock, 10)
		resp = self.wrap(self.arcs, "d", resp)
		(vers, stat, null, kind) = self.pack("!BBBB", resp[:4], 4)
		if (stat != SOCKSTAT):
			stdo("erro conn stat")
			shut(self.sock)
			return outp

		if (self.prot == "udp"):
			(vers, comd, null, kind) = (SOCKVERS, SOCKCOMD[self.prot], SOCKNULL, SOCKIPVF)
			head = struct.pack("!BBBB", vers, comd, null, kind)
			(sadr, port) = (self.addr[0], self.addr[1])
			data = (socket.inet_pton(socket.AF_INET, sadr) + struct.pack("!H", port))
			mesg = (head + data)
			mesg = self.wrap(self.arcs, "e", mesg)
			tsnd(self.sock, mesg)

		return (self.sock, self.arcs)

	def serv(self, addr, sock, keys=None):
		outp = (None, None, None, None)
		(self.addr, self.dest, self.arcs) = (addr, None, None)
		self.sock = sock

		if (keys and (keys != "x")):
			self.arcs = (ciph.ArcfCiph(keys), { "e":"s", "d":"r" })
			(ivec, buff) = (b"", b"")
			while (not SockProx.sepr in ivec):
				temp = self.recs(self.sock, 1)
				if (not temp):
					break
				ivec += temp
			try:
				ivec = ivec.strip().decode()
			except:
				return outp
			temp = self.recs(self.sock, 4)
			sksa(self.arcs[0], "tcp", ["r", "s"], ivec)
			mesg = self.wrap(self.arcs, "d", temp)
			if (mesg != b"1337"):
				stdo("erro serv 1337 [%s] [%s]" % (mesg, len(mesg), ))
				return outp

		resp = self.recs(self.sock, 3)
		resp = self.wrap(self.arcs, "d", resp)
		(vers, meth, kind) = self.pack("!BBB", resp, 3)
		if (kind != SOCKAUTH):
			stdo("erro serv auth")
			return outp

		(vers, auth) = (SOCKVERS, SOCKAUTH)
		mesg = struct.pack("!BB", vers, auth)
		mesg = self.wrap(self.arcs, "e", mesg)
		tsnd(self.sock, mesg)

		resp = self.recs(self.sock, 10)
		resp = self.wrap(self.arcs, "d", resp)
		(vers, comd, null, kind) = self.pack("!BBBB", resp[:4], 4)
		try:
			self.prot = [k for k in SOCKCOMD.keys() if SOCKCOMD[k] == comd][0]
			dadr = socket.inet_ntop(socket.AF_INET, resp[4:8])
			port = int(self.pack("!H", resp[8:], 1)[0])
			self.dest = (dadr, port)
		except:
			stdo("erro serv dest")
			return outp

		(vers, comd, null, kind) = (SOCKVERS, SOCKSTAT, SOCKNULL, SOCKIPVF)
		head = struct.pack("!BBBB", vers, comd, null, kind)
		data = struct.pack("!BBBBH", 0, 0, 0, 0, 0)
		mesg = (head + data)
		mesg = self.wrap(self.arcs, "e", mesg)
		tsnd(self.sock, mesg)

		if (self.prot == "udp"):
			resp = self.recs(self.sock, 10)
			resp = self.wrap(self.arcs, "d", resp)
			try:
				sadr = socket.inet_ntop(socket.AF_INET, resp[4:8])
				port = int(self.pack("!H", resp[8:], 1)[0])
				self.addr = (sadr, port)
			except:
				stdo("erro serv addr")
				return outp

		return (self.prot, self.addr, self.dest, self.arcs)

	def loop(self, srcs, dsts, objc):
		(socs, arcs) = ([srcs, dsts], objc["arcs"])
		while (objc["stat"]):
			(r, w, e) = sels(socs, wait=1.1)
			if (None in r):
				objc["stat"] = False ; break
			secs = gets()
			if (srcs in r):
				data = self.recv("tcp", srcs, SOCKSIZE["tcp"])
				data = self.wrap(arcs, "e", data)
				if (not data):
					objc["stat"] = False ; break
				tsnd(dsts, data)
				objc["last"] = secs
			if (dsts in r):
				data = self.recv("tcp", dsts, SOCKSIZE["tcp"])
				data = self.wrap(arcs, "d", data)
				if (not data):
					objc["stat"] = False ; break
				tsnd(srcs, data)
				objc["last"] = secs

	def half(self, srcs, dsts, addr, dest, objc):
		(buff, socs, arcs) = (b"", [dsts], objc["arcs"])
		while (objc["stat"]):
			if (objc["main"]):
				socs = [srcs, dsts]
			(r, w, e) = sels(socs, wait=1.1)
			if (None in r):
				objc["stat"] = False ; break
			secs = gets()
			if (srcs in r):
				(data, xadr) = self.recv("udp", srcs, SOCKSIZE["udp"])
				if (not data):
					objc["stat"] = False ; break
				mesg = (self.numb(len(data)) + SockProx.sepr + data)
				mesg = self.wrap(arcs, "e", mesg)
				tsnd(dsts, mesg)
				objc["last"] = secs
			if (dsts in r):
				data = self.recv("tcp", dsts, SOCKSIZE["tcp"])
				data = self.wrap(arcs, "d", data)
				if (not data):
					objc["stat"] = False ; break
				buff += data
				while (SockProx.sepr in buff):
					info = buff.split(SockProx.sepr, 1)
					size = self.ints(info[0])
					if (size < 1):
						stdo("warn half size %s [%s] [%s]" % (addr, size, len(buff), ))
						objc["stat"] = False ; break
					mesg = info[1][:size]
					if (len(mesg) != size):
						break
					send(srcs, addr, mesg)
					buff = info[1][size:]
				objc["last"] = secs

	def xfer(self, srcs, dsts, addr, dest, objc):
		socs = [srcs, dsts]
		maps = [(srcs, dsts, dest), (dsts, srcs, addr)]
		while (objc["stat"]):
			(r, w, e) = sels(socs, wait=1.1)
			if (None in r):
				objc["stat"] = False ; break
			secs = gets()
			for (sobj, dobj, xadr) in maps:
				if (sobj in r):
					(data, zadr) = self.recv("udp", sobj, SOCKSIZE["udp"])
					if (not data):
						objc["stat"] = False ; break
					send(dobj, xadr, data)
					objc["last"] = secs

class SockPipe:
	def __init__(self, sock):
		(self.r, self.w) = socket.socketpair()
		(self.s, self.l) = (sock, [])
	def fileno(self):
		try:
			return self.r.fileno()
		except:
			return -1
	def close(self):
		for f in [self.w, self.r]:
			shut(f)
	def recvfrom(self, size):
		if (self.l):
			size = self.l.pop(0)
		try:
			return (self.r.recv(size), None)
		except:
			return (b"", None)
	def sendto(self, data, addr):
		try:
			return self.s.sendto(data, addr)
		except:
			return -1
	def pipe(self, data):
		try:
			self.l.append(len(data))
			self.w.send(data)
		except:
			if (self.l):
				self.l.pop(-1)

class ServProt(BaseRequestHandler):
	def handle(self):
		global SOCKMAPS

		prot = "tcp"
		addr = self.client_address
		reqs = self.request
		secs = gets()

		(dest, endp) = cmde(prot, addr)

		if (dest):
			excl = ipin(dest, SOCKNOTS)
			prox = SockProx(endp, prot)

			if (excl):
				(sock, arcs) = (socket.socket(socket.AF_INET, socket.SOCK_STREAM), None)
				syns(sock, dest)
			else:
				(sock, arcs) = prox.conn(addr, dest, keys=SOCKKEYS)

			if (sock):
				stdo("info conn init %s * %s:%s [%s:%s]" % (prot, addr, dest, reqs.fileno(), sock.fileno(), ))
				objc = { "stat":True, "main":True, "last":secs, "pipe":reqs, "sock":sock, "arcs":arcs, "proc":None, "pips":[] }
				objc["proc"] = threading.Thread(target=prox.loop, args=(reqs, sock, objc))
				objc["proc"].start()
				SOCKMAPS[addr] = objc

class ServProu(BaseRequestHandler):
	def handle(self):
		global SOCKMAPS

		prot = "udp"
		addr = self.client_address
		sock = None
		(data, conn) = self.request
		(secs, keyl) = (gets(), list(SOCKMAPS.keys()))

		if (not addr in keyl):
			pipe = SockPipe(conn)
			SOCKMAPS[addr] = { "stat":True, "main":True, "last":secs, "pipe":pipe, "sock":sock, "proc":None, "logs":0, "pips":[] }

			objc = SOCKMAPS[addr]
			pipe.pipe(data)

			(dest, endp) = cmde(prot, addr)
			if (dest):
				excl = ipin(dest, SOCKNOTS)
				prox = SockProx(endp, prot)

				if (excl):
					(sock, arcs) = (socket.socket(socket.AF_INET, socket.SOCK_DGRAM), None)
				else:
					(sock, arcs) = prox.conn(addr, dest, keys=SOCKKEYS)

				if (sock):
					objc["sock"] = sock
					objc.update({ "dest":dest, "prox":prox, "arcs":arcs, "excl":excl })
					stdo("info conn init %s * %s:%s [%s/%s] [%s/%s]" % (prot, addr, dest, objc["stat"], objc["last"], objc["sock"].fileno(), len(data), ))
					if (excl):
						objc["proc"] = threading.Thread(target=prox.xfer, args=(pipe, sock, addr, dest, objc, ))
					else:
						objc["proc"] = threading.Thread(target=prox.half, args=(pipe, sock, addr, dest, objc, ))
					objc["proc"].start()

		else:
			objc = SOCKMAPS[addr]
			(objc["stat"], objc["main"]) = (True, True)
			if ((secs - objc["logs"]) > 1):
				stdo("info conn pipe %s | %s [%s/%s]" % (prot, addr, objc["pipe"].fileno(), len(data), ))
				objc["logs"] = secs
			objc["pipe"].pipe(data)

class ServProx(BaseRequestHandler):
	def handle(self):
		global SOCKMAPS

		cadr = self.client_address
		reqs = self.request
		sock = None
		prox = SockProx(None, None)
		(secs, keyl) = (gets(), list(SOCKMAPS.keys()))

		(prot, addr, dest, arcs) = prox.serv(cadr, reqs, keys=SOCKKEYS)

		if (prot and addr and dest):
			objc = { "stat":True, "main":True, "last":secs, "pipe":reqs, "sock":sock, "arcs":arcs, "proc":None, "pips":[] }

			if (prot == "tcp"):
				sock = socket.socket(socket.AF_INET, SOCKTYPE[prot])
				objc["sock"] = sock
				stdo("info serv init %s * %s:%s [%s:%s]" % (prot, addr, dest, reqs.fileno(), sock.fileno(), ))
				syns(sock, dest)
				objc["proc"] = threading.Thread(target=prox.loop, args=(sock, reqs, objc))
				objc["proc"].start()
				SOCKMAPS[addr] = objc

			if (prot == "udp"):
				if (not addr in keyl):
					sock = socket.socket(socket.AF_INET, SOCKTYPE[prot])
					objc["sock"] = sock
					stdo("info serv init %s * %s:%s [%s:%s]" % (prot, addr, dest, reqs.fileno(), sock.fileno(), ))
					objc["proc"] = threading.Thread(target=prox.half, args=(sock, reqs, dest, addr, objc))
					objc["proc"].start()
					SOCKMAPS[addr] = objc
				else:
					objt = SOCKMAPS[addr]
					sock = objt["sock"]
					(objc["stat"], objc["main"], objc["sock"]) = (True, False, sock)
					stdo("info serv pipe %s | %s:%s [%s:%s]" % (prot, addr, dest, reqs.fileno(), sock.fileno(), ))
					objc["proc"] = threading.Thread(target=prox.half, args=(sock, reqs, dest, addr, objc))
					objc["proc"].start()
					objt["pips"].append(objc)

class UserverT:
	def __init__(self, addr, call):
		self.sock = socket.socket(socket.AF_INET, SOCKTYPE["tcp"])
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind(addr)
		self.sock.listen(16)
		self.call = call
	def serve_forever(self):
		while True:
			(conn, addr) = self.sock.accept()
			hand = self.call(conn, addr, None)

class UserverU:
	def __init__(self, addr, call):
		self.sock = socket.socket(socket.AF_INET, SOCKTYPE["udp"])
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind(addr)
		self.call = call
	def serve_forever(self):
		while True:
			(data, addr) = self.sock.recvfrom(SOCKSIZE["udp"])
			if (not data):
				continue
			reqs = (data, self.sock)
			hand = self.call(reqs, addr, None)

def cmde(prot, addr):
	cmds = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	(dest, port) = comd(SOCKEXEC, addr, prot, cmds, port=SOCKREMO[1])
	endp = (SOCKREMO[0], port)
	cmds.close()
	return (dest, endp)

def msto(addr, objc, indx, timo):
	global SOCKMAPS
	(secs, leng) = (gets(), len(objc["pips"]))
	if (not objc["stat"]):
		objc["main"] = False
		remo = True
		if (objc["proc"] and join(objc["proc"], 0.01)):
			remo = False
		stdo("info maps remo %s %s [%s/%s]" % (addr, remo, indx, leng, ))
		if (remo):
			if (indx < 0):
				if (leng < 1):
					shut(objc["sock"])
					shut(objc["pipe"])
					del SOCKMAPS[addr]
			else:
				objt = SOCKMAPS[addr]
				shut(objc["pipe"])
				objt["pips"].pop(indx)
	elif ((secs - objc["last"]) > timo):
		objc["stat"] = False

def mgmt(maps, timo):
	global SOCKMAPS
	while True:
		keyl = list(SOCKMAPS.keys())
		for addr in keyl:
			objc = SOCKMAPS[addr]
			objs = objc["pips"]
			(leng, sets, free) = (len(objs), 0, None)
			for indx in range(leng - 1, -1, -1):
				objt = objs[indx]
				msto(addr, objt, indx, timo)
				if (objt["stat"] and objt["main"]):
					sets += 1
				if ((not free) and objt["stat"]):
					free = objt
			indx = -1
			msto(addr, objc, indx, timo)
			if (objc["stat"] and objc["main"]):
				sets += 1
			if (sets > 1):
				stdo("warn main mult %s [%s]" % (addr, sets, ))
			elif ((sets < 1) and free):
				stdo("warn main free %s [%s]" % (addr, leng, ))
				free["main"] = True
		time.sleep(0.90)

def serv(mode, locl, remo, keys, comd, nots, timo):
	global SOCKKEYS, SOCKMAPS, SOCKEXEC
	global SOCKNOTS, SOCKTIME, SOCKREMO

	(SOCKKEYS, SOCKEXEC) = (keys, comd)
	SOCKREMO = (remo[1], int(remo[2]))
	(prot, bind) = (locl[0], (locl[1], int(locl[2])))

	if (nots):
		fobj = open(nots, "r")
		for line in fobj.readlines():
			line = line.strip()
			if ((not line) or line.startswith("#")):
				continue
			anet = ipaddress.ip_network(line)
			SOCKNOTS.append(anet)
		fobj.close()
	if (not timo):
		timo = SOCKTIME[prot]
	timo = int(timo)

	pidn = os.fork()
	if (pidn != 0):
		stdo("info fork %s:%s %s:%s" % (prot, bind, timo, pidn, ))
		sys.exit(0)

	thrm = threading.Thread(target=mgmt, args=(SOCKMAPS, timo, ))
	thrm.start()
	if (mode == "c"):
		if (prot == "tcp"):
			stcp = UserverT(bind, ServProt)
			stcp.serve_forever()
		elif (prot == "udp"):
			sudp = UserverU(bind, ServProu)
			sudp.serve_forever()
	elif (mode == "s"):
		if (prot == "tcp"):
			stcp = UserverT(bind, ServProx)
			stcp.serve_forever()

def main():
	argp = argparse.ArgumentParser(description="socks")
	argp.add_argument("-l", "--list", action="store", default="tcp:127.0.0.1:1337")
	argp.add_argument("-d", "--dest", action="store", default="tcp:127.0.0.1:7331")
	argp.add_argument("-m", "--mode", action="store", default="c")
	argp.add_argument("-k", "--keys", action="store", default="x")
	argp.add_argument("-e", "--exec", action="store")
	argp.add_argument("-n", "--nots", action="store")
	argp.add_argument("-t", "--timo", action="store")
	args = argp.parse_args(sys.argv[1:])

	locl = args.list.split(":")
	remo = args.dest.split(":")

	serv(args.mode, locl, remo, args.keys, args.exec, args.nots, args.timo)

if (__name__ == "__main__"):
	main()
