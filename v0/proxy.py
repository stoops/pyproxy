#!/usr/bin/python3

import os, sys, time
import ctypes, random, string
import select, socket, subprocess
import resource, threading, sqlite3
import argparse, ipaddress, multiprocessing
import multiprocessing.sharedctypes as sharedtypes
import ciph

(MAXT, MINT) = (2 ** 11, 2 ** 5)
(MAXC, MINC) = (2 **  7, 2 ** 5)
(EXTR, MULT) = (2 **  7, 2 ** 2)
(THRL, THRM, THRS, THRZ) = (0.003, 0.030, 0.300, 0.900)
(SEPR, NICE, DPRO, VERS) = ("\n", "0x31337", "0.0.0.0:0:null", "1.0.7")
ADJT = { "udp":{ -9:[0, 53], 3:[80, 443], 5:[500, 4500] }, "tcp":{  } }
SOCS = { "udp":{ "s":socket.SOCK_DGRAM, "t":MINT }, "tcp":{ "s":socket.SOCK_STREAM, "t":MAXT } }
BUFF = { "udp":(0x539 + EXTR), "tcp":0x2000, "max":(0x7A69 + EXTR) }

def gets():
	return int(time.time())

def getl(o):
	try:
		return list(o)
	except:
		return []

def getv(o, k):
	try:
		return o[k]
	except:
		return None

def clos(o, m):
	try:
		if (o and (o.fileno() > 0)):
			o.close()
	except Exception as e:
		fout("! erro close %s [%s] [%s]" % (m, o, e))

def defa(argv, vmap, defv):
	return vmap.get(argv, vmap.get(defv, argv))

def fout(line):
	msec = str(time.time()).split(".")[1].zfill(11)
	date = time.strftime("%b-%d-%Y/%H:%M:%S")
	sys.stdout.write("[%s.%s] %s\n" % (date, msec, line))
	sys.stdout.flush()

def make(adrs):
	info = adrs.split(":")
	return (info[0], int(info[1]))

def nets(adrs, netw):
	try:
		if (not netw):
			return ipaddress.ip_address(adrs)
		else:
			return ipaddress.ip_network(adrs)
	except:
		return ipaddress.ip_address("0.0.0.0")

def netp(addr, prox, nats, nots):
	try:
		iadr = nets(addr[0], False)
		for netw in nats.keys():
			if (iadr in netw):
				addr = (nats[netw], addr[1])
		iadr = nets(addr[0], False)
		for netw in nots.keys():
			if (iadr in netw):
				prox = nots[netw]
	except:
		pass
	return (addr, prox)

def sels(rinp, wait, mesg):
	try:
		return select.select(rinp, [], rinp, wait)
	except KeyboardInterrupt:
		sys.exit(0)
	except Exception as e:
		fout("! erro sels %s %s %s" % (mesg, rinp, e, ))
		return ([None], [None], [None])

def join(proc, wait):
	try:
		proc.join(timeout=wait)
	except Exception as e:
		pass
	try:
		return proc.is_alive()
	except Exception as e:
		return False

def core(rfds, last, xfer=True, skip=False, inpt=[], keys=("r", "s")):
	(outp, held, secs) = ([], [], gets())
	for robj in rfds:
		while (robj.q and robj.q["h"]):
			data = robj.q["h"].pop(0)
			held.append(data)
		held.extend(inpt)
		if (not skip):
			(bulk, addr) = robj.recs(keys=keys[0])
			held.extend(bulk)
		for data in held:
			if (xfer and (not data)):
				return (False, outp)
			if (xfer and (robj.l.send(data, keys=keys[1]) < 1)):
				return (False, outp)
			outp.append(data) ; last.set(secs)
		(held, inpt, bulk) = ([], [], [])
	return (True, outp)

class SharedNum:
	def __init__(self, nval):
		self.n = sharedtypes.Value("i", nval, lock=True)
	def get(self):
		with self.n.get_lock():
			return self.n.value
	def set(self, nval):
		with self.n.get_lock():
			self.n.value = nval

class SharedBool:
	def __init__(self, bval):
		self.m = { False:0, True:1 }
		self.n = SharedNum(self.m[bval])
	def get(self):
		return bool(self.n.get())
	def set(self, bval):
		self.n.set(self.m[bval])

class SharedSocket:
	NULL = socket.socket(socket.AF_INET, SOCS["udp"]["s"])
	def __init__(self):
		self.f = SharedSocket.NULL
	def fileno(self):
		if (self.f):
			return self.f.fileno()
		return -1
	def close(self):
		self.f = None

class SockObjc:
	def __init__(self, prot, dest, sock):
		self.c = SharedBool(False)
		self.p = prot
		self.d = dest
		self.s = sock
		self.f = -1
		self.t = defa(prot, BUFF, "udp")
		self.q = {}
		self.r = None
		self.l = None

	def init(self, dest, sock, prxy, setr=False, qden=None):
		self.d = dest
		self.s = sock
		self.q = { "p":None, "k":None, "c":None, "s":False, "d":qden, "h":[] }
		self.r = None
		if ((self.p != "tcp") and sock and setr):
			self.r = self.s
			self.s = SharedSocket()
		if (prxy and (prxy["p"][1] != 0)):
			for k in ["p", "k"]:
				self.q[k] = prxy[k]
			self.q["c"] = ciph.ArcfCiph(self.q["k"])
		self.f = -1
		self.c.set(False)

	def link(self, sock):
		self.l = sock

	def sock(self):
		if (self.r):
			return self.r
		return self.s

	def fileno(self, stop=True):
		r = -1
		if (stop and self.c.get()):
			return r
		try:
			if (self.s):
				r = self.s.fileno()
		except Exception as e:
			fout("! %s erro fino [%s] (%s)" % (self.p, self.d, e, ))
		if (stop and (r < 0)):
			self.c.set(True)
		return r

	def loop(self):
		retn = (None, None)
		try:
			(size, sock) = (self.t, self.sock())
			if (self.p == "udp"):
				retn = sock.recvfrom(size)
			elif (self.p == "tcp"):
				retn = sock.accept()
		except Exception as e:
			fout("! %s erro loop [%s] (%s)" % (self.p, self.d, e, ))
		return retn

	def conf(self, retn):
		self.q["s"] = True
		self.t = (defa(self.p, BUFF, "udp") + EXTR)
		return retn

	def ciph(self):
		if (self.p != "tcp"):
			return self.conf(1)
		self.q["s"] = False
		(secs, prox) = (str(gets()), self.q["d"])
		self.q["c"].sksa(self.p, ["r", "s"], secs)
		innr = ("%s:%d:%s%s" % (prox[0], prox[1], NICE, SEPR)).encode()
		outr = self.q["c"].prga(self.p, "e", "s", innr)
		data = ("%s:%s%s" % (secs, outr.hex(), SEPR)).encode()
		leng = self.send(data)
		return self.conf(leng)

	def conn(self):
		try:
			self.c.set(False)
			if (self.q and self.q["p"] and (self.q["p"][1] > 0)):
				if (not self.q["d"]):
					self.q["d"] = (self.d[0], self.d[1])
					self.d = (self.q["p"][0], self.q["p"][1])
			if (self.p == "tcp"):
				self.fins(stop=False)
			if (not self.s):
				self.s = socket.socket(socket.AF_INET, SOCS[self.p]["s"])
			if (self.p == "tcp"):
				self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
				self.s.connect(self.d)
			if (self.q and self.q["p"] and (self.q["p"][1] > 0)):
				if (self.ciph() < 1):
					raise Exception("ciph")
			self.f = self.fileno()
			self.l.f = self.l.fileno()
			if ((self.f < 0) or (self.l.f < 0)):
				raise Exception("fileno (%s:%s)" % (self.f, self.l.f, ))
			return True
		except Exception as e:
			fout("! %s erro conn [%s:%s] {%s:%s} %s" % (self.p, self.d, self.l.d, self.q["d"], self.l.q["d"], e, ))
		return False

	def fins(self, stop=True, stcp=True):
		if (stop):
			self.c.set(True)
		if (stcp):
			try:
				self.s.shutdown(socket.SHUT_RDWR)
			except:
				pass
		clos(self.s, "%s fins (%s)" % (self.p, self.d, ))
		self.s = None

	def encr(self, data, keys="s"):
		(outp, head) = (data, b"")
		if (self.q and self.q["s"] and data):
			try:
				if (self.p != "tcp"):
					head = ("%s:%d%s%s:%d%s%s%s" % (self.l.d[0], self.l.d[1], SEPR, self.q["d"][0], self.q["d"][1], SEPR, NICE, SEPR, )).encode()
				outp = self.q["c"].prga(self.p, "e", keys, head + data)
			except Exception as e:
				fout("! %s erro encr ciph [%s:%s] (%s)" % (self.p, self.l.d, self.q["d"], e, ))
				outp = b""
		return outp

	def decr(self, data, keys="r", rewr=False):
		outp = data
		if (self.q and self.q["s"] and outp):
			try:
				outp = self.q["c"].prga(self.p, "d", keys, outp)
				if (self.p != "tcp"):
					head = outp.split(SEPR.encode(), 3)
					if (head[2] != NICE.encode()):
						raise Exception(NICE)
					if ((self.q["p"][1] < 0) or rewr):
						self.q["d"] = make(head[0].decode())
						self.l.d = make(head[1].decode())
					outp = head[3]
			except Exception as e:
				fout("! %s erro decr ciph [%s:%s] (%s)" % (self.p, self.d, self.q["d"], e, ))
				outp = b""
		return outp

	def recs(self, keys="r"):
		(retn, dest, size) = ([None], self.d, self.t)
		if (self.fileno() < 0):
			return (retn, dest)
		try:
			(r, d) = (retn, dest)
			if (self.p == "udp"):
				(r, d) = self.s.recvfrom(size)
			elif (self.p == "tcp"):
				r = self.s.recv(size)
			elif (self.p == "pip"):
				raise Exception("pip")
			if (not type(r) is list):
				r = [r]
			for i in range(0, len(r)):
				r[i] = self.decr(r[i], keys=keys)
			(retn, dest) = (r, d)
		except Exception as e:
			fout("! %s erro recs [%s] (%s)" % (self.p, self.d, e, ))
		return (retn, dest)

	def sendudp(self, data, sock, dest, size=BUFF["tcp"]):
		while (data):
			sent = sock.sendto(data[:size], dest)
			if (sent < 1):
				raise Exception("sendudp")
			data = data[sent:]

	def send(self, data, dest=None, keys="s"):
		(leng, sock) = (-1, self.sock())
		if (self.fileno() < 0):
			return leng
		if (not dest):
			dest = self.d
		try:
			data = self.encr(data, keys=keys)
			if (self.p == "udp"):
				self.sendudp(data, sock, dest)
			elif (self.p == "tcp"):
				sock.sendall(data)
			elif (self.p == "pip"):
				self.sendudp(data, sock, dest)
			leng = len(data)
		except Exception as e:
			fout("! %s erro send [%s] (%s)" % (self.p, self.d, e, ))
		return leng

	def prep(self, last, stat):
		conn = self.l
		if (conn.q and conn.q["p"] and (conn.q["p"][1] < 0)):
			if (conn.p != "tcp"):
				return conn.conf(self.d)
			(data, outp) = (b"", [])
			if (stat.get() and (conn.fileno() > -1)):
				(rfds, wfds, efds) = sels([conn], THRZ, "prep")
				(good, outp) = core(rfds, last, xfer=False)
			while (len(outp) > 0):
				data = outp.pop(0)
				if (SEPR.encode() in data):
					break
			try:
				conn.q["s"] = False
				hold = data.split(SEPR.encode(), 1)
				temp = hold[0].strip().decode().split(":")
				conn.q["c"].sksa(conn.p, ["r", "s"], temp[0])
				outr = bytes.fromhex(temp[1])
				innr = conn.q["c"].prga(conn.p, "d", "r", outr)
				info = innr.strip().decode()
				if (not info.endswith(":" + NICE)):
					raise Exception(NICE)
				if (hold[1]):
					outp = ([hold[1]] + outp)
				for item in outp:
					data = conn.q["c"].prga(conn.p, "d", "r", item)
					conn.q["h"].append(data)
				self.d = make(info)
				return conn.conf(self.d)
			except Exception as e:
				fout("! %s erro prep ciph [%s] (%s)" % (conn.p, conn.d, e, ))
				return None
		return self.d

def shut(sock, conn, stat, stop=True, mesg="x"):
	stat.set(False)
	if (stop):
		conn.c.set(True) ; sock.c.set(True)

def down(sock, conn, stat, stop=True, mesg="x"):
	shut(sock, conn, stat, stop=stop, mesg=mesg)
	conn.fins(stop=stop) ; sock.fins(stop=stop)

def mini(mins, klen, coma, comi, lkey, lval):
	limi = int((coma - (comi / 2)) + 1)
	maxl = int(max(0, klen - limi) + (comi / 2))
	if (klen >= limi):
		(x, i) = (0, len(mins["d"]))
		while (x < i):
			(ikey, ival) = mins["d"][x]
			if (lval < ival):
				i = x ; break
			x += 1
		mins["d"].insert(i, (lkey, lval))
		mins["d"] = mins["d"][:maxl+maxl]
		mins["l"] = maxl

def mgmt(prot, maps, dels, xfer):
	keyl = getl(maps.keys())
	klen = len(keyl)
	mapx = {}
	for addr in keyl:
		if (addr in dels):
			continue
		objc = maps[addr]
		(conn, sock, last, stat) = (objc["conn"], objc["sock"], objc["last"], objc["stat"])
		if ((not xfer) and (not stat.get())):
			for sobj in [conn, sock]:
				if (sobj.c.get() or (sobj.fileno() < 0) or (sobj.f < 0)):
					objc["mesg"].add("stat") ; dels.add(addr)
				else:
					mapx[sobj] = (addr, sobj, last)
	return (keyl, klen, mapx)

def tcon(prot, objc, addr, dest, klen, mode, init):
	(conn, sock, last, timo, stat) = (objc["conn"], objc["sock"], objc["last"], objc["timo"], objc["stat"])
	if (prot != "tcp"):
		conn.q["h"].append(init)
	if (not sock.prep(last, stat)):
		down(sock, conn, stat, mesg="prep")
		return -1
	if (not sock.conn()):
		down(sock, conn, stat, mesg="conn")
		return -2
	offs = (MULT * 3)
	if (sock.q and sock.q["p"] and (sock.q["p"][1] < 0)):
		dest = sock.d ; offs = (MULT * 3)
		objc["link"] = ("%s-%s:%s-%s" % (conn.p, addr, dest, sock.p)).encode()
	info = objc["link"].decode()
	for k in ADJT[prot].keys():
		if (dest[1] in ADJT[prot][k]):
			t = (SOCS[prot]["t"] << abs(k))
			if (k < 0):
				t = (SOCS[prot]["t"] >> abs(k))
			timo.set(t + offs)
	fout("~ %s [%s] <%s> (%s:%s|%s:%s) {%d}" % (prot, info, klen, conn.fileno(), conn.f, sock.f, sock.fileno(), timo.get(), ))
	if (mode != "loop"):
		pidn = 0
		if (mode == "process"):
			pidn = os.fork()
		while (stat.get() and (pidn == 0)):
			if (conn.q["h"]):
				core([conn], last, skip=True)
			(rfds, wfds, efds) = sels([conn, sock], THRZ * MULT, "thre")
			if ((None in rfds) or efds):
				break
			(good, null) = core(rfds, last)
			if (not good):
				break
		if (mode == "process"):
			if (pidn == 0):
				sys.exit(0)
			os.waitpid(pidn)
		down(sock, conn, stat, mesg="xfer")
		return 1
	shut(sock, conn, stat, stop=False)
	return 0

def tchk(prot, maps, dels, cons, xfer):
	while True:
		(secs, chks) = (gets(), [])
		mins = { "l":0, "d":[] }
		for addr in getl(maps.keys()):
			if (addr in dels):
				continue
			objc = getv(maps, addr)
			if (not objc):
				continue
			(last, timo, stat, proc) = (objc["last"], objc["timo"], objc["stat"], objc["proc"])
			if (not proc):
				objc["mesg"].add("proc") ; dels.add(addr)
			if ((secs - last.get()) >= timo.get()):
				objc["mesg"].add("time") ; dels.add(addr)
			notp = ((not join(proc, THRL)) or (not stat.get()))
			if (xfer and notp):
				objc["mesg"].add("xfer") ; dels.add(addr)
			if ((not xfer) and (not notp)):
				continue
			if (not addr in dels):
				chks.append((addr, last.get()))
		leng = len(chks)
		for (addr, last) in chks:
			mini(mins, leng, cons[0], cons[1], addr, last)
		leng = mins["l"]
		for item in mins["d"][:leng]:
			addr = item[0]
			objc = getv(maps, addr)
			if (objc):
				objc["mesg"].add("limi") ; dels.add(addr)
		time.sleep(THRZ)

def comd(path, addr, prot, cmdc):
	outp = None
	(maxs, secs, curs, sadr) = (MINT << MULT, gets(), cmdc.cursor(), "%s:%s:%s" % (prot, addr[0], addr[1]))
	try:
		if (os.stat("/tmp/cons.db").st_size == 0):
			curs.execute("CREATE TABLE cons(secs INTEGER, sadr TEXT, dadr TEXT)")
		curs.execute("DELETE FROM cons WHERE secs <= '%s'" % (secs-maxs))
	except Exception as e:
		fout("! %s erro comd sql new [%s] %s" % (prot, addr, e, ))
	try:
		rows = curs.execute("SELECT * FROM cons WHERE sadr = '%s'" % (sadr))
		rowv = rows.fetchone()
		if (rowv):
			outp = make(rowv[2].strip())
			fout("i %s info cached [%s] %s %s" % (prot, secs, addr, rowv, ))
			curs.execute("UPDATE cons SET secs = '%s' WHERE sadr = '%s'" % (secs, sadr))
			cmdc.commit() ; curs.close()
			return outp
	except Exception as e:
		fout("! %s erro comd sql [%s] %s" % (prot, addr, e, ))
	try:
		cmdl = [path, addr[0], str(addr[1]), prot]
		subp = subprocess.check_output(cmdl, shell=False, text=True)
		outp = make(subp.strip())
		curs.execute("INSERT INTO cons VALUES (%s, '%s', '%s:0')" % (secs, sadr, subp.strip()))
	except Exception as e:
		fout("! %s erro comd [%s] %s" % (prot, addr, e, ))
	cmdc.commit() ; curs.close()
	return outp

def serv(adrs, prot, mode, path, byte, cons, prxy, nats, nots):
	ssec = 0
	mudp = "pip"
	objs = []
	maps = {}
	srvs = { "s":{}, "r":{} }
	xfer = { "loop":False, "thread":True, "process":True }
	pmap = { "udp":{ "p":mudp, "s":None, "d":None }, "tcp":{ "p":prot, "s":None, "d":None } }
	dels = set()
	xpro = pmap[prot]["p"]
	cmdc = sqlite3.connect("/tmp/cons.db")
	for addr in adrs:
		sock = socket.socket(socket.AF_INET, SOCS[prot]["s"])
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.bind(addr)
		if (prot == "tcp"):
			sock.listen(MINC)
		sobj = SockObjc(prot, addr, sock)
		sobj.init(addr, sock, prxy, setr=True)
		srvs["s"][sock.fileno()] = (sock, sobj)
		if ((prot == "udp") and (prxy["p"][1] != 0)):
			sock = socket.socket(socket.AF_INET, SOCS[prot]["s"])
			robj = SockObjc(prot, prxy["p"], sock)
			robj.init(prxy["p"], sock, prxy, setr=True)
			sobj.link(robj) ; robj.link(sobj)
			robj.prep(None, None) ; robj.conn()
			srvs["r"][sock.fileno()] = (sock, robj)
	for x in range(0, (cons[0] + cons[1]) + 1):
		conn = SockObjc(xpro, None, None)
		sock = SockObjc(prot, None, None)
		stat = SharedBool(False) ; last = SharedNum(0) ; timo = SharedNum(0)
		link = b""
		conn.link(sock) ; sock.link(conn)
		objs.append({ "conn":conn, "sock":sock, "last":last, "timo":timo, "stat":stat, "link":link, "proc":None, "mesg":set() })
	lsts = [srvs["s"][k][0] for k in srvs["s"].keys()]
	lstr = [srvs["r"][k][0] for k in srvs["r"].keys()]
	chks = threading.Thread(target=tchk, args=(prot, maps, dels, cons, xfer[mode], ))
	chks.start()
	while True:
		secs = gets()
		if ((secs - ssec) >= 3):
			(keyl, klen, mapx) = mgmt(prot, maps, dels, xfer[mode])
			ssec = secs
		clis = [mapx[k][1] for k in mapx.keys()]
		rinp = (lsts + lstr + clis)
		(rfds, wfds, efds) = sels(rinp, THRZ, "loop")
		for fdes in rfds:
			if (fdes in lsts):
				fobj = srvs["s"][fdes.fileno()][1]
				(data, addr) = fobj.loop()
				(sorc, dest, qden) = (addr, None, None)
				(pmap["udp"]["s"], pmap["tcp"]["s"]) = (fobj.r, data)
				(pmap["udp"]["d"], pmap["tcp"]["d"]) = (None, None)
				if ((prot == "udp") and (prxy["p"][1] < 0)):
					data = fobj.decr(data, keys="w", rewr=True)
					(addr, dest, qden) = (fobj.q["d"], fobj.l.d, fobj.q["d"])
				if (data and (not addr in keyl)):
					if (not dest):
						dest = comd(path, sorc, prot, cmdc)
					if (not dest):
						continue
					(dest, prox) = netp(dest, prxy, nats, nots)
					if ((byte == 1) and (prox["p"][1] > 0)):
						pmap["udp"]["d"] = fobj.l.r
					for objc in objs:
						if (objc["proc"]):
							continue
						(conn, sock, last, timo, stat) = (objc["conn"], objc["sock"], objc["last"], objc["timo"], objc["stat"])
						conn.init(sorc, pmap[prot]["s"], prox, setr=True, qden=qden)
						sock.init(dest, pmap[prot]["d"], prox, setr=True, qden=None)
						stat.set(True) ; last.set(secs) ; timo.set(SOCS[prot]["t"])
						objc["link"] = ("%s-%s:%s-%s" % (conn.p, addr, dest, sock.p)).encode()
						proc = threading.Thread(target=tcon, args=(prot, objc, addr, dest, klen+1, mode, data, ))
						proc.start() ; objc["proc"] = proc
						maps[addr] = objc ; keyl.append(addr)
						ssec = 0 ; break
				elif (data and (addr in keyl)):
					objc = maps[addr]
					(conn, sock, last) = (objc["conn"], objc["sock"], objc["last"])
					if (conn.p == mudp):
						if ((sock.f < 0) or conn.q["h"]):
							conn.q["h"].append(data)
						else:
							(good, null) = core([conn], last, skip=True, inpt=[data], keys=("u", "v"))
							if (not good):
								maps[addr]["mesg"].add("pipe") ; dels.add(addr)
				if (not addr in keyl):
					fout("! %s warn addr [%s] (%d:%d:%d)" % (prot, addr, klen, len(objs), cons[0] + cons[1], ))
			elif (fdes in lstr):
				fobj = srvs["r"][fdes.fileno()][1]
				(data, addr) = fobj.loop()
				data = fobj.decr(data, keys="w", rewr=True)
				dest = fobj.l.d
				if (dest in keyl):
					last = maps[dest]["last"]
					(good, null) = core([fobj], last, skip=True, inpt=[data], keys=("u", "v"))
					if (not good):
						maps[dest]["mesg"].add("byte") ; dels.add(dest)
			elif (fdes):
				if (fdes in mapx.keys()):
					(radr, robj, last) = mapx[fdes]
					(good, null) = core([fdes], last)
					if (not good):
						maps[radr]["mesg"].add("core") ; dels.add(radr)
		for dadr in getl(dels):
			objc = getv(maps, dadr)
			if (not objc):
				continue
			(conn, sock, stat, link, proc) = (objc["conn"], objc["sock"], objc["stat"], objc["link"], objc["proc"])
			shut(sock, conn, stat)
			(info, mesg) = (link.decode(), "-".join(list(objc["mesg"])))
			fout("x %s [%s] <%s> (%d:%d|%d:%d)" % (prot, info, mesg, conn.fileno(), conn.f, sock.f, sock.fileno(), ))
			if (join(proc, THRL)):
				continue
			down(sock, conn, stat)
			objc["mesg"].clear() ; objc["proc"] = None
			del maps[dadr] ; keyl = getl(maps.keys())
			ssec = 0
		dels.clear()

def main():
	(b, s) = ("store_true", "store")
	args = { "byte":b, "cons":s, "exec":s, "fork":b, "listen":s, "mode":s, "anat":s, "onot":s, "protocol":s, "socks":s }
	opts = argparse.ArgumentParser(description="proxy")
	for k in args.keys():
		opts.add_argument("-%s"%(k[0]), "--%s"%(k), action=args[k])
	args = opts.parse_args()
	adrs = [make(i) for i in args.listen.split(",")]
	nats = {} ; nots = {}
	argl = [(args.anat, nats), (args.onot, nots)]
	for argi in argl:
		(a, o) = argi
		if (not a):
			continue
		f = open(a, "r")
		for l in f.readlines():
			if (l.startswith("#")):
				continue
			i = l.strip().split(":")
			k = nets(i[0], True)
			if (len(i) > 1):
				v = i[1]
			else:
				v = { "p":make(DPRO), "k":DPRO.split(":").pop(-1) }
			o[k] = v
		f.close()
	argv = defa(args.socks, { None:DPRO }, "*")
	prxy = { "p":make(argv), "k":argv.split(":").pop(-1) }
	prot = defa(args.protocol, { "udp":"udp", "tcp":"tcp" }, "udp")
	mode = defa(args.mode, { "loop":"loop", "thread":"thread", "process":"process" }, "loop")
	path = defa(args.exec, { None:"/usr/bin/true" }, "*")
	cons = defa(args.cons, { "lo":(MAXC << 0, MINC << 0), "me":(MAXC << 1, MINC << 1), "hi":(MAXC << 2, MINC << 2) }, "me")
	byte = defa(args.byte and (prot == "udp"), { True:1, "byte":-1 }, "byte")
	fout("s %s <%s:%s> %s {%s:%s} [%s]" % (adrs, prot, mode, prxy, byte, cons, VERS, ))
	for r in [resource.RLIMIT_NOFILE, resource.RLIMIT_NPROC]:
		resource.setrlimit(r, (8192, 8192))
	if (args.fork):
		cpid = os.fork()
		if (cpid != 0):
			sys.exit(0)
	serv(adrs, prot, mode, path, byte, cons, prxy, nats, nots)

if (__name__ == "__main__"):
	main()
