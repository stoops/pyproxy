#!/usr/bin/python


import os, sys, time
import select, socket, subprocess
import argparse, ipaddress, threading
import ctypes, random, string


BONE = 1
BUDP = 1500
BTCP = 9500
BMAX = 9900
SEPR = ",".encode()
MUTX = [threading.Lock(), threading.Lock()]
NOTS = []


def stdo(line):
	secs = str(time.time()).split(".")[1].zfill(9)
	date = time.strftime("%Y-%m-%d_%H:%M:%S")
	sys.stdout.write("[%s.%s] %s\n" % (date, secs, line, ))
	#sys.stdout.flush()

def gets():
	return int(time.time())

def adru(addr):
	return ("%s:%d" % (addr[0], addr[1])).encode()

def uadr(adrs):
	info = adrs.split(":")
	return (info[0], int(info[1]))

def pcku(indx):
	return bytes([((indx >> 8) & 0xff), (indx & 0xff)])

def upck(data):
	return ((data[0] << 8) + data[1])

def hedu(addr, dest, data, finz=False):
	maps = { False:b"0", True:b"1" }
	mesg = (maps[finz] + SEPR + adru(addr) + SEPR + adru(dest) + SEPR + data)
	return (pcku(len(mesg)) + mesg)

def uhed(data):
	outp = (None, None, None, None)
	try:
		info = data.split(SEPR, 3)
		stat = info[0].decode()
		addr = info[1].decode()
		dest = info[2].decode()
		outp = (stat, uadr(addr), uadr(dest), info[3])
	except:
		pass
	return outp

def comd(path, addr, prot):
	outp = b""
	if (path):
		try:
			cmdl = [path, addr[0], str(addr[1]), prot]
			subp = subprocess.check_output(cmdl, shell=False, text=True)
			outp = uadr(subp.strip())
		except Exception as e:
			pass
	return outp

def sels(socs, wait=None):
	try:
		return select.select(socs, [], [], wait)
	except Exception as e:
		return ([], [], [None])

def join(objc, name, addr):
	stdo("join prep %s %s" % (name, addr, ))
	try:
		objc.join()
	except:
		stdo("join warn %s %s" % (name, addr, ))
	stdo("join post %s %s" % (name, addr, ))

def fino(sock):
	try:
		fnum = sock.fileno()
	except:
		fnum = -1
	if (fnum > 0):
		return True
	return False

def syns(sock, dest):
	try:
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
		sock.settimeout(5)
		sock.connect(dest)
		sock.settimeout(None)
	except Exception as e:
		return False
	return True

def fins(sock, whos):
	#if (whos and (not whos.startswith("#"))):
	#	stdo("info xxxx [%s] %s" % (whos, sock, ))
	if (not fino(sock)):
		return None
	try:
		sock.shutdown(socket.SHUT_RDWR)
	except:
		pass
	try:
		sock.close()
	except:
		pass
	return None

def recu(sock, size):
	try:
		return sock.recvfrom(size)
	except:
		return (None, None)

def senu(sock, buff, dest):
	try:
		sock.sendto(buff, dest)
		return True
	except:
		return False

def recw(sock):
	data = b""
	i = { "a":(0,2), "b":(-2,0) }
	while (i["b"][0] < i["b"][1]):
		k = "b"
		if (i["a"][0] < i["a"][1]):
			k = "a"
		elif (i["b"][0] < 0):
			size = upck(data)
			if ((size < BONE) or (BMAX < size)):
				stdo("warn recw size %s" % (size, ))
				return b""
			i["b"] = (0, size)
			data = b""
		try:
			(leng, size) = i[k]
			diff = (size - leng)
			temp = sock.recv(diff)
			if (not temp):
				#stdo("warn recw data [%s][%s] [%s]" % (len(temp), diff, fino(sock), ))
				return b""
			leng += len(temp)
			data += temp
			i[k] = (leng, size)
		except Exception as e:
			stdo("erro recw erro %s" % (e, ))
			return b""
	if (i["b"][0] != i["b"][1]):
		stdo("warn recw leng %s" % (i, ))
		return b""
	return data

def senz(sock, data, show):
	try:
		if (fino(sock)):
			sock.sendall(data)
	except Exception as e:
		if (show):
			stdo("erro senz erro %s" % (e, ))

def sent(sock, data, midx):
	MUTX[midx].acquire()
	senz(sock, data, True)
	MUTX[midx].release()

def ipin(addr, nots):
	try:
		iadr = ipaddress.ip_address(addr[0])
		for netw in nots:
			if (iadr in netw):
				return True
	except Exception as e:
		stdo("erro ipin %s" % (e, ))
	return False

def wrap(ciph, mode, skey, data):
	try:
		return ciph.prga(mode, skey, data)
	except:
		return b""


class arcf:
	def __init__(self, skey):
		self.h = 8
		self.m = 256
		self.s = {}
		self.k = skey.encode()
		self.c_f = ctypes.cdll.LoadLibrary("/etc/c.so")

	def sksa(self, keys, init, rnds):
		self.v = init
		(m, h, n, l) = (self.m, self.h, len(self.v), len(self.k))
		if ((n < 1) or (l < 1)):
			raise Exception("sksa [%d:%d]" % (n, l))
		for d in keys:
			if (not d in self.s.keys()):
				self.s[d] = {
					"c_i": ctypes.c_ubyte * 1, "c_j": ctypes.c_ubyte * 1, "c_c": ctypes.c_ubyte * 1, "p_z": [bytearray(1),bytearray(1),bytearray(1)],
					"c_v": ctypes.c_ubyte * n, "p_v": bytearray(self.v),
					"c_k": ctypes.c_ubyte * l, "p_k": bytearray(self.k),
					"c_s": ctypes.c_ubyte * m, "p_s": bytearray(self.m),
					"c_h": ctypes.c_ubyte * h, "p_h": bytearray(self.h)
				}
		for d in keys:
			s = self.s[d]
			s["p_v"] = bytearray(self.v) ; s["p_k"] = bytearray(self.k) ; s["p_z"] = [bytearray(1),bytearray(1),bytearray(1)]
			self.c_f.keys(s["c_s"].from_buffer(s["p_s"]), rnds, s["c_v"].from_buffer(s["p_v"]), n, s["c_k"].from_buffer(s["p_k"]), l)

	def prga(self, mode, keys, data):
		if (mode == "e"):
			init = bytes(random.sample(range(0, self.m), 16))
		else:
			(sums, init, data) = (data[0:8], data[8:24], data[24:])
		self.sksa([keys], init, 384)
		(m, h, s, l) = (self.m, self.h, self.s[keys], len(data))
		if (l < 1):
			raise Exception("prga [%d]" % (l))
		(a, z) = (ord(mode[0]), s["p_z"])
		(c_d, p_d) = (ctypes.c_ubyte * l, bytearray(data))
		(c_o, p_o) = (ctypes.c_ubyte * l, bytearray(l))
		self.c_f.ciph(c_o.from_buffer(p_o), c_d.from_buffer(p_d), l, s["c_i"].from_buffer(z[0]), s["c_j"].from_buffer(z[1]), s["c_c"].from_buffer(z[2]), s["c_s"].from_buffer(s["p_s"]), a)
		outp = bytes(p_o)
		self.c_f.sums(s["c_h"].from_buffer(s["p_h"]), h, z[0][0], z[1][0], z[2][0], s["c_s"].from_buffer(s["p_s"]))
		sumh = bytes(s["p_h"])
		if (mode == "e"):
			mesg = (sumh + init + outp)
			leng = len(mesg)
			outp = (pcku(leng) + mesg)
		else:
			if (sums != sumh):
				raise Exception("prga sums [%s] != [%s]" % (sums, sumh))
		return outp


class tcps:
	def __init__(self, args):
		self.name = "tcps"
		self.args = args
		self.stat = 1
		self.leng = args.cons
		self.cons = [None] * self.leng
		self.maps = {}
		self.smap = {}
		self.lsoc = None
		self.esoc = None
		self.rsoc = None

	def recv(self, argp):
		ciph = arcf(self.args.skey)
		midx = 0
		if (not syns(argp["sock"], argp["dest"])):
			stdo("erro %s recv conn %s->%s" % (self.name, argp["addr"], argp["dest"], ))
			argp["stat"] = 9
		while (self.stat == 1):
			stat = argp["stat"]
			rpip = argp["rpip"]
			sock = argp["sock"]
			if (stat != 1):
				break
			if ((not fino(rpip)) or (not fino(sock))):
				break
			socs = [rpip, sock]
			(rfds, wfds, efds) = sels(socs, 5)
			secs = gets()
			if (rpip in rfds):
				try:
					data = rpip.recv(BTCP)
				except:
					data = b""
				if (not data):
					break
				senz(sock, data, False)
			if (sock in rfds):
				try:
					data = sock.recv(BTCP)
				except:
					data = b""
				if (not data):
					break
				lock = argp["lock"]
				addr = argp["addr"]
				dest = argp["dest"]
				conn = argp["conn"]
				mesg = hedu(addr, dest, data)
				mesg = wrap(ciph, "e", "r", mesg)
				sent(conn, mesg, midx)
				if ((secs - lock[1]) > 1):
					stdo("info %s recv data %s->%s" % (self.name, addr, dest, ))
					lock[1] = secs
				argp["last"] = secs
			if ((secs - argp["last"]) >= self.args.timo):
				break
		argp["sock"] = fins(argp["sock"], "tcps recv ends sock")
		addr = argp["addr"]
		dest = argp["dest"]
		conn = argp["conn"]
		mesg = hedu(addr, dest, b"0", finz=True)
		mesg = wrap(ciph, "e", "r", mesg)
		sent(conn, mesg, midx)
		stdo("info %s recv fins %s->%s" % (self.name, addr, dest, ))
		argp["stat"] = -1

	def send(self, argp):
		ciph = arcf(self.args.skey)
		cadr = argp["addr"]
		conn = argp["conn"]
		while (self.stat == 1):
			data = recw(conn)
			if (not data):
				#stdo("warn %s send recw %s" % (self.name, addr, ))
				break
			try:
				data = ciph.prga("d", "s", data)
				data = data[2:]
			except Exception as e:
				stdo("warn %s send ciph [%s]" % (self.name, e, ))
				continue
			(finz, addr, dest, data) = uhed(data)
			if (not data):
				stdo("warn %s send head" % (self.name, ))
				continue
			if (addr in self.smap.keys()):
				sobj = self.smap[addr]
				if (sobj["stat"] != 1):
					continue
				if (finz == "1"):
					sobj["stat"] = 9
					continue
			secs = gets()
			if (not addr in self.smap.keys()):
				sobj = { "stat":1, "last":secs }
				sobj["lock"] = [0, 0]
				sobj["link"] = cadr
				sobj["addr"] = addr
				sobj["dest"] = dest
				sobj["conn"] = conn
				sobj["sock"] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				(sobj["rpip"], sobj["wpip"]) = socket.socketpair()
				sobj["thro"] = threading.Thread(target=self.recv, args=(sobj, ))
				sobj["thro"].start()
				self.smap[addr] = sobj
			sobj = self.smap[addr]
			dest = sobj["dest"]
			sock = sobj["sock"]
			wpip = sobj["wpip"]
			if (fino(sock)):
				try:
					wpip.send(data)
					lock = sobj["lock"]
					if ((secs - lock[0]) > 1):
						stdo("info %s send data %s->%s" % (self.name, addr, dest, ))
						lock[0] = secs
					sobj["last"] = secs
				except:
					stdo("warn %s send send" % (self.name, ))
		for addr in self.smap.keys():
			sobj = self.smap[addr]
			if (sobj["link"] != cadr):
				continue
			if (sobj["stat"] == 1):
				sobj["stat"] = 9
		argp["conn"] = fins(argp["conn"], "tcps send ends conn")
		argp["stat"] = -1

	def serv(self):
		indx = 0
		locl = uadr(self.args.locl)
		self.lsoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.lsoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.lsoc.bind(locl)
		self.lsoc.listen(96)
		while (self.stat == 1):
			secs = gets()
			keys = list(self.smap.keys())
			for addr in keys:
				sobj = self.smap[addr]
				if (sobj["stat"] == 1):
					if ((secs - sobj["last"]) >= self.args.timo):
						sobj["stat"] = 9
				elif (sobj["stat"] < 0):
					fins(sobj["wpip"], "tcps serv ends wpip")
					fins(sobj["rpip"], "tcps serv ends rpip")
					fins(sobj["sock"], "tcps serv ends sock")
					join(sobj["thro"], "tcps serv smap proc", sobj["addr"])
					sobj["stat"] = 0
					del self.smap[addr]
			indx = ((indx + 1) % self.leng)
			self.maps[indx] = True
			keys = list(self.maps.keys())
			for idxk in keys:
				cobj = self.cons[idxk]
				if (not cobj):
					indx = idxk
					del self.maps[idxk]
				elif (cobj["stat"] < 0):
					fins(cobj["conn"], "tcps serv stat conn")
					join(cobj["thro"], "tcps serv maps proc", cobj["addr"])
					cobj["stat"] = 0
					self.cons[idxk] = None
			(rfds, wfds, efds) = sels([self.lsoc], 5)
			if (efds):
				break
			if (self.lsoc in rfds):
				if (self.cons[indx]):
					stdo("warn %s serv indx" % (self.name, ))
					time.sleep(0.5)
					continue
				try:
					cobj = { "stat":1 }
					(cobj["conn"], cobj["addr"]) = self.lsoc.accept()
					cobj["thro"] = threading.Thread(target=self.send, args=(cobj, ))
					cobj["thro"].start()
					self.cons[indx] = cobj
					self.maps[indx] = True
				except:
					break
		stdo("info %s serv fins" % (self.name, ))
		self.stat = 0


class tcpc:
	def __init__(self, args):
		self.name = "tcpc"
		self.args = args
		self.stat = 1
		self.leng = args.cons
		self.cons = [None] * self.leng
		self.maps = {}
		self.smap = {}
		self.lsoc = None
		self.esoc = None
		self.rsoc = None

	def recv(self, argp):
		ciph = arcf(self.args.skey)
		while (self.stat == 1):
			socs = []
			if (self.args.nots):
				if (fino(self.esoc)):
					socs.append(self.esoc)
			if (fino(self.rsoc)):
				socs.append(self.rsoc)
			if (not socs):
				stdo("warn %s recv conn socs" % (self.name, ))
				time.sleep(0.5)
				continue
			(rfds, wfds, efds) = sels(socs, 5)
			secs = gets()
			for sock in rfds:
				data = recw(sock)
				if (not data):
					stdo("warn %s recv data %s" % (self.name, len(data), ))
					fins(sock, "tcpc recv recw sock")
					continue
				try:
					data = ciph.prga("d", "r", data)
					data = data[2:]
				except Exception as e:
					stdo("warn %s recv ciph [%s]" % (self.name, e, ))
					continue
				(finz, addr, dest, data) = uhed(data)
				if (not data):
					stdo("warn %s recv head" % (self.name, ))
					continue
				if (not addr in self.smap.keys()):
					stdo("warn %s recv maps %s" % (self.name, addr, ))
					continue
				sobj = self.smap[addr]
				lock = sobj["lock"]
				conn = sobj["conn"]
				if (finz == "1"):
					sobj["stat"] = 9
					continue
				senz(conn, data, False)
				if ((secs - lock[1]) > 1):
					stdo("info %s recv data %s->%s" % (self.name, addr, dest, ))
					lock[1] = secs
				sobj["last"] = secs

	def send(self, argp):
		prot = "tcp"
		ciph = arcf(self.args.skey)
		secs = gets()
		addr = argp["addr"]
		conn = argp["conn"]
		if (self.args.dest):
			dest = uadr(self.args.dest)
		else:
			dest = comd(self.args.exec, addr, prot)
		if (dest):
			midx = 1
			if (self.args.nots):
				excl = ipin(dest, NOTS)
				if (excl):
					midx = 0
			sobj = { "stat":1, "addr":addr, "dest":dest, "conn":conn, "midx":midx, "last":secs, "lock":[0,0] }
			self.smap[addr] = sobj
		else:
			stdo("warn %s send dest %s" % (self.name, addr, ))
			argp["stat"] = -1
		while (self.stat == 1):
			if ((argp["stat"] != 1) or (sobj["stat"] != 1)):
				break
			(rfds, wfds, efds) = sels([conn], 5)
			secs = gets()
			if (conn in rfds):
				try:
					data = conn.recv(BTCP)
				except:
					data = b""
				if (not data):
					break
				mesg = hedu(addr, dest, data)
				mesg = wrap(ciph, "e", "s", mesg)
				sock = self.esoc if (midx == 0) else self.rsoc
				sent(sock, mesg, midx)
				lock = sobj["lock"]
				if ((secs - lock[0]) > 1):
					stdo("info %s send data %s->%s" % (self.name, addr, dest, ))
					lock[0] = secs
				sobj["last"] = secs
			if ((secs - sobj["last"]) >= self.args.timo):
				break
		argp["conn"] = fins(argp["conn"], "tcpc send ends conn")
		if (dest):
			mesg = hedu(addr, dest, b"0", finz=True)
			mesg = wrap(ciph, "e", "s", mesg)
			sock = self.esoc if (midx == 0) else self.rsoc
			sent(sock, mesg, midx)
			sobj["stat"] = -1
		stdo("info %s send fins %s->%s" % (self.name, addr, dest, ))
		argp["stat"] = -1

	def serv(self):
		indx = 0
		last = 0
		locl = uadr(self.args.locl)
		remo = uadr(self.args.remo)
		reml = ("127.0.0.1", remo[1])
		self.lsoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.lsoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.lsoc.bind(locl)
		self.lsoc.listen(96)
		self.thrr = threading.Thread(target=self.recv, args=(self, ))
		self.thrr.start()
		while (self.stat == 1):
			secs = gets()
			indx = ((indx + 1) % self.leng)
			if ((secs - last) >= 5):
				if (self.args.nots):
					if (not fino(self.esoc)):
						self.esoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
						if (not syns(self.esoc, reml)):
							stdo("warn %s recv conn esoc" % (self.name, ))
							self.esoc = fins(self.esoc, "tcpc serv conn esoc")
				if (not fino(self.rsoc)):
					self.rsoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					if (not syns(self.rsoc, remo)):
						stdo("warn %s recv conn rsoc" % (self.name, ))
						self.rsoc = fins(self.rsoc, "tcpc serv conn rsoc")
				last = secs
			keys = list(self.smap.keys())
			for adrk in keys:
				sobj = self.smap[adrk]
				if ((secs - sobj["last"]) >= self.args.timo):
					fins(sobj["conn"], "tcpc serv last conn")
					sobj["stat"] = -1
					del self.smap[adrk]
			self.maps[indx] = True
			keys = list(self.maps.keys())
			for idxk in keys:
				cobj = self.cons[idxk]
				if (not cobj):
					indx = idxk
					del self.maps[idxk]
				elif (cobj["stat"] < 0):
					fins(cobj["conn"], "tcpc serv stat conn")
					join(cobj["thro"], "tcpc serv maps proc", cobj["addr"])
					cobj["stat"] = 0
					self.cons[idxk] = None
					del self.maps[idxk]
			(rfds, wfds, efds) = sels([self.lsoc], 5)
			secs = gets()
			if (efds):
				break
			if (self.lsoc in rfds):
				if (self.cons[indx]):
					for x in range(0, self.leng):
						if (not self.cons[x]):
							indx = x
							break
				if (self.cons[indx]):
					stdo("warn %s serv indx" % (self.name, ))
					time.sleep(0.5)
					continue
				try:
					cobj = { "stat":1 }
					(cobj["conn"], cobj["addr"]) = self.lsoc.accept()
					cobj["thro"] = threading.Thread(target=self.send, args=(cobj, ))
					cobj["thro"].start()
					self.cons[indx] = cobj
					self.maps[indx] = True
				except:
					break
		stdo("info %s serv fins" % (self.name, ))
		self.stat = 0


class udps:
	def __init__(self, args):
		self.name = "udps"
		self.args = args
		self.leng = args.cons
		self.stat = 1
		self.cons = [None] * self.leng
		self.maps = {}
		self.smap = {}
		self.lsoc = None
		self.rsoc = None

	def recv(self, argp):
		ciph = arcf(self.args.skey)
		while (self.stat == 1):
			stat = argp["stat"]
			conn = argp["conn"]
			sock = argp["sock"]
			if ((stat != 1) or (not fino(conn))):
				stdo("warn %s recv conn" % (self.name, ))
				break
			(rfds, wfds, efds) = sels([sock], 5)
			secs = gets()
			if (sock in rfds):
				(data, addr) = recu(sock, BUDP)
				if (not data):
					stdo("warn %s recv sock" % (self.name, ))
					break
				midx = 0
				addr = argp["addr"]
				dest = argp["dest"]
				mesg = hedu(addr, dest, data)
				mesg = wrap(ciph, "e", "r", mesg)
				lock = argp["lock"]
				if ((secs - lock[1]) > 1):
					stdo("info %s recv data %s->%s" % (self.name, addr, dest, ))
					lock[1] = secs
				sent(conn, mesg, midx)
				argp["last"] = secs
			if ((secs - argp["last"]) >= self.args.timo):
				break
		stdo("info %s recv fins %s->%s" % (self.name, argp["addr"], argp["dest"], ))
		argp["stat"] = -1

	def send(self, argp):
		ciph = arcf(self.args.skey)
		cadr = argp["addr"]
		conn = argp["conn"]
		while (self.stat == 1):
			data = recw(conn)
			if (not data):
				#stdo("warn %s send recw %s" % (self.name, addr, ))
				break
			try:
				data = ciph.prga("d", "s", data)
				data = data[2:]
			except Exception as e:
				stdo("warn %s send ciph [%s]" % (self.name, e, ))
				continue
			(finz, addr, dest, data) = uhed(data)
			if (not data):
				stdo("warn %s send head" % (self.name, ))
				continue
			secs = gets()
			keys = list(self.smap.keys())
			if (not addr in keys):
				sobj = { "stat":1, "last":secs }
				sobj["lock"] = [0, 0]
				sobj["link"] = cadr
				sobj["addr"] = addr
				sobj["dest"] = dest
				sobj["conn"] = conn
				sobj["sock"] = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				sobj["thro"] = threading.Thread(target=self.recv, args=(sobj, ))
				sobj["thro"].start()
				self.smap[addr] = sobj
			sobj = self.smap[addr]
			dest = sobj["dest"]
			sock = sobj["sock"]
			lock = sobj["lock"]
			stat = senu(sock, data, dest)
			if (not stat):
				stdo("warn %s send send" % (self.name, ))
				break
			sobj["last"] = secs
			if ((secs - lock[0]) > 1):
				stdo("info %s send data %s->%s" % (self.name, addr, dest, ))
				lock[0] = secs
		for addr in self.smap.keys():
			sobj = self.smap[addr]
			if (sobj["link"] != cadr):
				continue
			if (sobj["stat"] == 1):
				sobj["stat"] = 9
		argp["conn"] = fins(argp["conn"], "udps send ends conn")
		argp["stat"] = -1

	def serv(self):
		indx = 0
		locl = uadr(self.args.locl)
		self.lsoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.lsoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.lsoc.bind(locl)
		self.lsoc.listen(96)
		while (self.stat == 1):
			secs = gets()
			keys = list(self.smap.keys())
			for addr in keys:
				sobj = self.smap[addr]
				if (sobj["stat"] == 1):
					if ((secs - sobj["last"]) >= self.args.timo):
						sobj["stat"] = 9
				elif (sobj["stat"] < 0):
					fins(sobj["sock"], "#udps serv ends sock")
					join(sobj["thro"], "udps serv smap proc", sobj["addr"])
					sobj["stat"] = 0
					del self.smap[addr]
			indx = ((indx + 1) % self.leng)
			self.maps[indx] = True
			keys = list(self.maps.keys())
			for x in keys:
				cobj = self.cons[x]
				if (not cobj):
					indx = x
					del self.maps[x]
				elif (cobj["stat"] < 0):
					fins(cobj["conn"], "udps serv stat conn")
					join(cobj["thro"], "udps serv maps proc", cobj["addr"])
					cobj["stat"] = 0
					self.cons[x] = None
					del self.maps[x]
			(rfds, wfds, efds) = sels([self.lsoc], 5)
			if (efds):
				break
			if (self.lsoc in rfds):
				if (self.cons[indx]):
					stdo("warn %s serv indx" % (self.name, ))
					time.sleep(0.5)
					continue
				try:
					cobj = { "stat":1 }
					(cobj["conn"], cobj["addr"]) = self.lsoc.accept()
					cobj["thro"] = threading.Thread(target=self.send, args=(cobj, ))
					cobj["thro"].start()
					self.cons[indx] = cobj
					self.maps[indx] = True
				except:
					break
		stdo("info %s serv fins" % (self.name, ))
		self.stat = 0


class udpc:
	def __init__(self, args):
		self.name = "udpc"
		self.args = args
		self.leng = args.cons
		self.stat = 1
		self.cons = [None] * self.leng
		self.maps = {}
		self.lsoc = None
		self.esoc = None
		self.rsoc = None
		(self.rpip, self.wpip) = socket.socketpair()

	def recv(self, argp):
		ciph = arcf(self.args.skey)
		while (self.stat == 1):
			socs = []
			if (self.args.nots):
				if (fino(self.esoc)):
					socs.append(self.esoc)
			if (fino(self.rsoc)):
				socs.append(self.rsoc)
			if (not socs):
				stdo("warn %s recv conn socs" % (self.name, ))
				time.sleep(0.5)
				continue
			(rfds, wfds, efds) = sels(socs, 5)
			secs = gets()
			for sock in rfds:
				data = recw(sock)
				if (not data):
					stdo("warn %s recv data %s" % (self.name, len(data), ))
					fins(sock, "udpc recv data sock")
					continue
				try:
					data = ciph.prga("d", "r", data)
					data = data[2:]
				except Exception as e:
					stdo("warn %s recv ciph [%s]" % (self.name, e, ))
					continue
				(finz, addr, dest, data) = uhed(data)
				if (not data):
					stdo("warn %s recv head" % (self.name, ))
					continue
				senu(self.lsoc, data, addr)
				if (addr in self.maps.keys()):
					mobj = self.maps[addr]
					lock = mobj["lock"]
					if ((secs - lock[1]) > 1):
						stdo("info %s recv data %s->%s" % (self.name, addr, dest, ))
						lock[1] = secs

	def send(self, argp):
		last = 0
		prot = "udp"
		ciph = arcf(self.args.skey)
		while (self.stat == 1):
			data = self.rpip.recv(2)
			if (len(data) != 2):
				stdo("warn %s send pipe" % (self.name, ))
				break
			secs = gets()
			if ((secs - last) >= 5):
				keys = list(self.maps.keys())
				for addr in keys:
					mobj = self.maps[addr]
					if ((secs - mobj["last"]) >= 15):
						del self.maps[addr]
			indx = (upck(data) % self.leng)
			cobj = self.cons[indx]
			if ((not cobj) or (cobj["stat"] != 1)):
				stdo("warn %s send indx" % (self.name, ))
				if (cobj):
					cobj["stat"] = -1
				continue
			addr = cobj["addr"]
			data = cobj["data"]
			if (not addr in self.maps.keys()):
				if (self.args.dest):
					dest = uadr(self.args.dest)
				else:
					dest = comd(self.args.exec, addr, prot)
				if (not dest):
					stdo("warn %s send dest %s" % (self.name, addr, ))
					cobj["stat"] = -1
					continue
				midx = 1
				sock = self.rsoc
				if (self.args.nots):
					excl = ipin(dest, NOTS)
					if (excl):
						midx = 0
						sock = self.esoc
				self.maps[addr] = { "addr":addr, "dest":dest, "sock":sock, "midx":midx, "last":secs, "lock":[0,0] }
			mobj = self.maps[addr]
			midx = mobj["midx"]
			dest = mobj["dest"]
			sock = mobj["sock"]
			lock = mobj["lock"]
			mesg = hedu(addr, dest, data)
			mesg = wrap(ciph, "e", "s", mesg)
			if ((secs - lock[0]) > 1):
				stdo("info %s send data %s->%s" % (self.name, addr, dest, ))
				lock[0] = secs
			sent(sock, mesg, midx)
			mobj["last"] = secs
			cobj["stat"] = -1

	def serv(self):
		indx = 0
		last = 0
		locl = uadr(self.args.locl)
		remo = uadr(self.args.remo)
		reml = ("127.0.0.1", remo[1])
		self.lsoc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.lsoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.lsoc.bind(locl)
		self.thrr = threading.Thread(target=self.recv, args=(self, ))
		self.thrr.start()
		self.thrs = threading.Thread(target=self.send, args=(self, ))
		self.thrs.start()
		while (self.stat == 1):
			secs = gets()
			indx = ((indx + 1) % self.leng)
			if ((secs - last) >= 5):
				if (self.args.nots):
					if (not fino(self.esoc)):
						self.esoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
						if (not syns(self.esoc, reml)):
							stdo("warn %s recv conn esoc" % (self.name, ))
							self.esoc = fins(self.esoc, "udpc serv conn esoc")
				if (not fino(self.rsoc)):
					self.rsoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					if (not syns(self.rsoc, remo)):
						stdo("warn %s recv conn rsoc" % (self.name, ))
						self.rsoc = fins(self.rsoc, "udpc serv conn rsoc")
				last = secs
			(rfds, wfds, efds) = sels([self.lsoc], 5)
			if (efds):
				break
			if (self.lsoc in rfds):
				cobj = self.cons[indx]
				if (cobj and (cobj["stat"] == 1)):
					stdo("warn %s serv stat" % (self.name, ))
					time.sleep(0.5)
					continue
				try:
					cobj = { "stat":1 }
					(cobj["data"], cobj["addr"]) = recu(self.lsoc, BUDP)
					self.cons[indx] = cobj
					mesg = pcku(indx)
					self.wpip.send(mesg)
				except:
					break
		stdo("info %s serv fins" % (self.name, ))
		self.stat = 0


def main():
	argp = argparse.ArgumentParser(description="soc")
	argp.add_argument("-m", "--mode", action="store")
	argp.add_argument("-e", "--exec", action="store")
	argp.add_argument("-d", "--dest", action="store")
	argp.add_argument("-n", "--nots", action="store")
	argp.add_argument("-f", "--fork", action="store_true")
	argp.add_argument("-l", "--locl", action="store", default="127.0.0.1:31337")
	argp.add_argument("-r", "--remo", action="store", default="127.0.0.1:37331")
	argp.add_argument("-k", "--skey", action="store", default="null")
	argp.add_argument("-c", "--cons", action="store", default="64")
	argp.add_argument("-t", "--timo", action="store", default="15")

	args = argp.parse_args(sys.argv[1:])
	ekey = os.environ.get("SKEY", None)
	objc = None

	if (ekey):
		args.skey = ekey

	if (args.nots):
		fobj = open(args.nots, "r")
		for line in fobj.readlines():
			line = line.strip()
			if ((not line) or line.startswith("#")):
				continue
			anet = ipaddress.ip_network(line)
			NOTS.append(anet)
		fobj.close()

	if (args.fork):
		pidn = os.fork()
		if (pidn != 0):
			stdo("info fork [%s][%s]" % (pidn, args.skey, ))
			sys.exit(0)

	args.cons = int(args.cons)
	args.timo = int(args.timo)

	if (args.mode == "uc"):
		objc = udpc(args)
	if (args.mode == "us"):
		objc = udps(args)
	if (args.mode == "tc"):
		objc = tcpc(args)
	if (args.mode == "ts"):
		objc = tcps(args)

	if (objc):
		objc.serv()


if (__name__ == "__main__"):
	main()
