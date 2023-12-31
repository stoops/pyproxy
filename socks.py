#!/usr/bin/python3

import os, sys, time
import struct, select, socket
import socketserver, threading, argparse

from comm import *
import ciph

(SOCKVERS, SOCKAUTH, SOCKSTAT, SOCKNULL, SOCKIPVF) = (5, 0, 0, 0, 1)
SOCKSIZE = { "tcp":8192, "udp":1500 }
SOCKCOMD = { "tcp":1, "bnd":2, "udp":3 }
SOCKTYPE = { "tcp":socket.SOCK_STREAM, "udp":socket.SOCK_DGRAM }
SOCKMAPS = {}
SOCKKEYS = None
SOCKEXEC = "/usr/bin/true"
SOCKNOTS = []
SOCKTIME = 90
SOCKREMO = ("0.0.0.0", 0)

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

	def sels(self, socs, wait=3):
		try:
			return select.select(socs, [], [], wait)
		except:
			return ([None], [None], [None])

	def recv(self, prot, sock, size):
		if (prot == "tcp"):
			try:
				return sock.recv(size)
			except:
				return b""
		if (prot == "udp"):
			try:
				return sock.recvfrom(size)
			except:
				return (b"", None)

	def recs(self, sock, wait=3, size=1024):
		o = b""
		(r, w, e) = self.sels([sock], wait=wait)
		if (sock in r):
			o = self.recv("tcp", sock, size)
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

	def conn(self, dest, keys=None):
		outp = (None, None)
		self.arcs = None
		self.dest = dest
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

		resp = self.recs(self.sock, size=2)
		resp = self.wrap(self.arcs, "d", resp)
		(vers, auth) = self.pack("!BB", resp, 2)
		if (auth != SOCKAUTH):
			shut(self.sock)
			return outp

		(vers, comd, null, kind) = (SOCKVERS, SOCKCOMD[self.prot], SOCKNULL, SOCKIPVF)
		head = struct.pack("!BBBB", vers, comd, null, kind)
		(addr, port) = (self.dest[0], self.dest[1])
		data = (socket.inet_pton(socket.AF_INET, addr) + struct.pack("!H", port))
		mesg = (head + data)
		mesg = self.wrap(self.arcs, "e", mesg)
		tsnd(self.sock, mesg)

		resp = self.recs(self.sock, size=10)
		resp = self.wrap(self.arcs, "d", resp)
		(vers, stat, null, kind) = self.pack("!BBBB", resp[:4], 4)
		if (stat != SOCKSTAT):
			shut(self.sock)
			return outp

		outp = (self.sock, self.arcs)
		return outp

	def serv(self, sock, keys=None):
		outp = (None, None, None)
		self.arcs = None
		self.prot = None
		self.dest = None
		self.sock = sock

		if (keys and (keys != "x")):
			self.arcs = (ciph.ArcfCiph(keys), { "e":"s", "d":"r" })
			(ivec, buff) = (b"", b"")
			while (not SockProx.sepr in ivec):
				temp = self.recs(self.sock, size=1)
				if (not temp):
					break
				ivec += temp
			try:
				ivec = ivec.strip().decode()
			except:
				return outp
			temp = self.recs(self.sock, size=4)
			sksa(self.arcs[0], "tcp", ["r", "s"], ivec)
			mesg = self.wrap(self.arcs, "d", temp)
			if (mesg != b"1337"):
				stdo("warn serv 1337 [%s] [%s]" % (mesg, len(mesg), ))
				return outp

		resp = self.recs(self.sock, size=3)
		resp = self.wrap(self.arcs, "d", resp)
		(vers, meth, kind) = self.pack("!BBB", resp, 3)
		if (kind != SOCKAUTH):
			return outp

		(vers, auth) = (SOCKVERS, SOCKAUTH)
		mesg = struct.pack("!BB", vers, auth)
		mesg = self.wrap(self.arcs, "e", mesg)
		tsnd(self.sock, mesg)

		resp = self.recs(self.sock, size=10)
		resp = self.wrap(self.arcs, "d", resp)
		(vers, comd, null, kind) = self.pack("!BBBB", resp[:4], 4)
		try:
			self.prot = [k for k in SOCKCOMD.keys() if SOCKCOMD[k] == comd][0]
			addr = socket.inet_ntop(socket.AF_INET, resp[4:8])
			port = int(self.pack("!H", resp[8:], 1)[0])
			self.dest = (addr, port)
		except:
			self.prot = None
			self.dest = None
		if ((not self.prot) or (not self.dest)):
			return outp

		(vers, comd, null, kind) = (SOCKVERS, SOCKSTAT, SOCKNULL, SOCKIPVF)
		head = struct.pack("!BBBB", vers, comd, null, kind)
		data = struct.pack("!BBBBH", 0, 0, 0, 0, 0)
		mesg = (head + data)
		mesg = self.wrap(self.arcs, "e", mesg)
		tsnd(self.sock, mesg)

		outp = (self.prot, self.dest, self.arcs)
		return outp

	def loop(self, srcs, dsts, arcs):
		objc = { "stat":True, "last":0 }
		socs = [srcs, dsts]
		while (objc["stat"]):
			(r, w, e) = self.sels(socs, wait=3)
			if (None in r):
				objc["stat"] = False ; break
			if (srcs in r):
				data = self.recv("tcp", srcs, SOCKSIZE["tcp"])
				data = self.wrap(arcs, "e", data)
				if (not data):
					objc["stat"] = False ; break
				tsnd(dsts, data)
			if (dsts in r):
				data = self.recv("tcp", dsts, SOCKSIZE["tcp"])
				data = self.wrap(arcs, "d", data)
				if (not data):
					objc["stat"] = False ; break
				tsnd(srcs, data)
		shut(dsts)
		shut(srcs)

	def half(self, srcs, dsts, addr, objc, arcs):
		(socs, buff) = ([srcs, dsts], b"")
		while (objc["stat"]):
			(r, w, e) = self.sels(socs, wait=3)
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
					srcs.sendto(mesg, addr)
					buff = info[1][size:]
				objc["last"] = secs
			if ((secs - objc["last"]) > SOCKTIME):
				objc["stat"] = False ; break
		shut(dsts)
		shut(srcs)

	def xfer(self, srcs, dsts, addr, dest, objc):
		socs = [srcs, dsts]
		while (objc["stat"]):
			(r, w, e) = self.sels(socs, wait=3)
			if (None in r):
				objc["stat"] = False ; break
			secs = gets()
			if (srcs in r):
				(data, xadr) = self.recv("udp", srcs, SOCKSIZE["udp"])
				if (not data):
					objc["stat"] = False ; break
				send(dsts, dest, data)
				objc["last"] = secs
			if (dsts in r):
				(data, xadr) = self.recv("udp", dsts, SOCKSIZE["udp"])
				if (not data):
					objc["stat"] = False ; break
				srcs.sendto(data, addr)
				objc["last"] = secs
			if ((secs - objc["last"]) > SOCKTIME):
				objc["stat"] = False ; break
		shut(dsts)
		shut(srcs)

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
			self.s.sendto(data, addr)
		except:
			pass
	def pipe(self, data):
		try:
			self.l.append(len(data))
			self.w.send(data)
		except:
			if (self.l):
				self.l.pop(-1)

class ServProt(socketserver.BaseRequestHandler):
	def handle(self):
		prot = "tcp"
		addr = self.client_address
		reqs = self.request

		(dest, endp) = cmde(prot, addr)

		if (dest):
			excl = ipin(dest, SOCKNOTS)
			prox = SockProx(endp, prot)

			if (excl):
				(sock, arcs) = (socket.socket(socket.AF_INET, socket.SOCK_STREAM), None)
				syns(sock, dest)
			else:
				(sock, arcs) = prox.conn(dest, keys=SOCKKEYS)

			if (sock):
				stdo("info conn %s %s:%s [%s:%s]" % (prot, addr, dest, reqs.fileno(), sock.fileno(), ))
				prox.loop(reqs, sock, arcs)

class ServProu(socketserver.BaseRequestHandler):
	def handle(self):
		global SOCKMAPS

		prot = "udp"
		addr = self.client_address
		(data, conn) = self.request
		(keyl, secs) = (list(SOCKMAPS.keys()), gets())

		if (not addr in keyl):
			pipe = SockPipe(conn)
			SOCKMAPS[addr] = { "stat":True, "last":secs, "sock":None, "pipe":pipe, "proc":None, "logs":0 }

			objc = SOCKMAPS[addr]
			pipe.pipe(data)

			(dest, endp) = cmde(prot, addr)

			if (dest):
				excl = ipin(dest, SOCKNOTS)
				prox = SockProx(endp, prot)

				if (excl):
					(sock, arcs) = (socket.socket(socket.AF_INET, socket.SOCK_DGRAM), None)
				else:
					(sock, arcs) = prox.conn(dest, keys=SOCKKEYS)

				if (sock):
					objc["sock"] = sock
					SOCKMAPS[addr].update({ "dest":dest, "prox":prox, "arcs":arcs, "excl":excl })
					stdo("info conn init %s * %s:%s [%s/%s] [%s/%s]" % (prot, addr, dest, objc["stat"], objc["last"], objc["sock"].fileno(), len(data), ))
					if (excl):
						objc["proc"] = threading.Thread(target=prox.xfer, args=(pipe, sock, addr, dest, objc, ))
					else:
						objc["proc"] = threading.Thread(target=prox.half, args=(pipe, sock, addr, objc, arcs, ))
					objc["proc"].start()

		else:
			objc = SOCKMAPS[addr]
			if ((secs - objc["logs"]) >= 1):
				stdo("info conn pipe %s | %s [%s/%s]" % (prot, addr, objc["pipe"].fileno(), len(data), ))
				objc["logs"] = secs
			objc["pipe"].pipe(data)

class ServProx(socketserver.BaseRequestHandler):
	def handle(self):
		addr = self.client_address
		reqs = self.request
		prox = SockProx(None, None)
		(prot, dest, arcs) = prox.serv(reqs, keys=SOCKKEYS)

		if (prot and dest):
			sock = socket.socket(socket.AF_INET, SOCKTYPE[prot])

			if (prot == "tcp"):
				stdo("info serv tcps %s:%s [%s:%s]" % (addr, dest, reqs.fileno(), sock.fileno(), ))
				syns(sock, dest)
				prox.loop(sock, reqs, arcs)

			if (prot == "udp"):
				stdo("info serv udps %s:%s [%s:%s]" % (addr, dest, reqs.fileno(), sock.fileno(), ))
				objc = { "stat":True, "last":gets() }
				prox.half(sock, reqs, dest, objc, arcs)

class TserverT(socketserver.ThreadingMixIn, socketserver.TCPServer):
	pass

class TserverU(socketserver.ThreadingMixIn, socketserver.UDPServer):
	pass

class UserverU:
	def __init__(self, addr, objc):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind(addr)
	def serve_forever(self):
		while True:
			(data, addr) = self.sock.recvfrom(SOCKSIZE["udp"])
			if (not data):
				continue
			reqs = (data, self.sock)
			hand = ServProu(reqs, addr, None)

def cmde(prot, addr):
	cmds = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	(dest, port) = comd(SOCKEXEC, addr, prot, cmds, port=SOCKREMO[1])
	endp = (SOCKREMO[0], port)
	cmds.close()
	return (dest, endp)

def mgmt(maps):
	global SOCKMAPS
	while True:
		(keyl, secs) = (list(SOCKMAPS.keys()), gets())
		for addr in keyl:
			objc = SOCKMAPS[addr]
			if ((not objc["stat"]) or ((secs - objc["last"]) > SOCKTIME)):
				remo = True
				if (objc["proc"]):
					if (join(objc["proc"], 0.01)):
						remo = False
				stdo("info maps remo %s %s" % (addr, remo, ))
				if (remo):
					shut(objc["sock"])
					shut(objc["pipe"])
					del SOCKMAPS[addr]
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
	if (timo):
		SOCKTIME = int(timo)

	socketserver.TCPServer.allow_reuse_address = True
	socketserver.UDPServer.allow_reuse_address = True

	pidn = os.fork()
	if (pidn != 0):
		stdo("info fork %s" % (pidn, ))
		sys.exit(0)

	if (mode == "c"):
		if (prot == "tcp"):
			stcp = TserverT(bind, ServProt)
			stcp.serve_forever()

		if (prot == "udp"):
			thrm = threading.Thread(target=mgmt, args=(SOCKMAPS, ))
			thrm.start()

			sudp = UserverU(bind, ServProu)
			sudp.serve_forever()

	if (mode == "s"):
		if (prot == "tcp"):
			stcp = TserverT(bind, ServProx)
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
