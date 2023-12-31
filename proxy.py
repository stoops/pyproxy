#!/usr/bin/python3

import os, sys, time
import select, socket, subprocess
import argparse, resource, threading, traceback
import multiprocessing
import multiprocessing.sharedctypes as sharedtypes

BUFF = (2 ** 14)
MAXT = (2 ** 13)
MAXC = (2 ** 6)
MINC = (2 ** 3)
NOFI = (2 ** 4)
MULT = (2 ** 2)
THRL = 0.003
THRT = 0.030
THRS = 0.300
THRZ = 0.900
COMD = "/usr/bin/true"
SOCS = { "udp":socket.SOCK_DGRAM, "tcp":socket.SOCK_STREAM }
BLEN = BUFF

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

def fout(line):
	date = time.strftime("%b-%d-%Y/%H:%M:%S")
	sys.stdout.write("[%s] %s\n" % (date, line))
	sys.stdout.flush()

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

class SharedBytes:
	def __init__(self, size):
		self.l = sharedtypes.Value("i", 0, lock=True)
		self.d = sharedtypes.Array("c", bytearray(size), lock=True)
	def get(self, size=None):
		r = b""
		with self.l.get_lock():
			e = self.l.value
			d = size
			if ((not d) or (d < 1) or (d > e)):
				d = e
			r = self.d.raw[:d]
			self.d.value = self.d.raw[d:]
			self.l.value = (e - d)
		return r
	def set(self, data):
		with self.l.get_lock():
			e = self.l.value
			d = len(data)
			if ((e + d) < len(self.d)):
				self.d.value = (self.d.raw[:e] + data)
				self.l.value = (e + d)
	def len(self):
		return self.l.value

class PipeObjc:
	def __init__(self):
		(self.r, self.w) = multiprocessing.Pipe(duplex=False)
	def fileno(self):
		return self.r.fileno()
	def close(self):
		for f in [self.r, self.w]:
			try:
				f.close()
			except:
				pass
	def recvpipe(self, size):
		return self.r.recv_bytes(maxlength=size)
	def sendpipe(self, data):
		self.w.send_bytes(data)

class SockObjc:
	def __init__(self, prot, dest, sock=None):
		self.c = SharedBool(False)
		self.p = prot
		self.d = dest
		self.s = sock
		if (not self.s):
			self.s = socket.socket(socket.AF_INET, SOCS[self.p])
		else:
			if (self.p == "pip"):
				self.r = self.s.s
				self.s = PipeObjc()
				self.x = b""
				self.z = SharedBytes(MULT * BUFF)

	def fileno(self):
		if (self.c.get()):
			return -1
		try:
			return self.s.fileno()
		except Exception as e:
			fout("! %s error fino [%s] (%s)" % (self.p, self.d, e, ))
		return -1

	def loop(self):
		if (self.p == "udp"):
			return self.recv()
		if (self.p == "tcp"):
			return self.s.accept()

	def conn(self):
		try:
			dest = (self.d[0], self.d[1])
			if (self.p == "tcp"):
				self.s.connect(dest)
			return True
		except Exception as e:
			fout("! %s error conn [%s] (%s)" % (self.p, self.d, e, ))
		return False

	def fins(self):
		try:
			self.s.shutdown(socket.SHUT_RDWR)
		except:
			pass
		try:
			self.s.close()
		except:
			fout("! %s error fins (%s)" % (self.p, self.d, ))
		self.c.set(True)

	def buff(self):
		r = b""
		x = self.x.split(b"\n")
		self.x = x.pop(-1)
		while (x):
			try:
				l = int(x.pop(0))
				r += self.z.get(l)
			except:
				pass
		return r

	def recv(self):
		(r, d) = (b"", self.d)
		if (self.c.get()):
			return (r, d)
		try:
			if (self.p == "udp"):
				(r, d) = self.s.recvfrom(BUFF)
			if (self.p == "tcp"):
				r = self.s.recv(BUFF)
			if (self.p == "pip"):
				r = self.s.recvpipe(BUFF)
				if (BLEN != BUFF):
					self.x += r
					r = self.buff()
		except Exception as e:
			fout("! %s error recv [%s] (%s)" % (self.p, self.d, e, ))
		return (r, d)

	def sendudp(self, data, sock, dest):
		size = (2 ** 13)
		while (data):
			sent = sock.sendto(data[:size], dest)
			if (sent < 1):
				raise Exception("sendudp")
			data = data[sent:]

	def send(self, data, dest=None):
		if (self.c.get()):
			return -1
		if (not dest):
			dest = self.d
		try:
			if (self.p == "udp"):
				self.sendudp(data, self.s, dest)
			if (self.p == "tcp"):
				self.s.sendall(data)
			if (self.p == "pip"):
				self.sendudp(data, self.r, dest)
			return 1
		except Exception as e:
			fout("! %s error send [%s] (%s)" % (self.p, self.d, e, ))
		return -1

	def pipe(self, data):
		if (self.c.get()):
			return -1
		try:
			if (self.p == "pip"):
				if (BLEN == BUFF):
					self.s.sendpipe(data)
				else:
					size = (b"%d\n" % (len(data)))
					self.z.set(data)
					self.s.sendpipe(size)
			return 1
		except:
			fout("! %s error pipe (%s)" % (self.p, self.d, ))
		return -1

def sels(rinp):
	try:
		return select.select(rinp, [], [], THRZ)
	except KeyboardInterrupt:
		sys.exit(0)
	except:
		return ([], [], [])

def join(proc, wait):
	try:
		proc.join(timeout=wait)
	except:
		pass

def mini(mins, klen, lkey, lval):
	maxl = ((klen - MAXC) + (MINC + MINC))
	limi = ((MAXC - MINC) + 1)
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
	secs = gets()
	mapx = { "sadr":{}, "dadr":{}, "srcs":[], "dsts":[] }
	keyl = getl(maps.keys())
	klen = len(keyl)
	mins = { "l":0, "d":[] }
	for addr in keyl:
		conn = maps[addr]["conn"]
		sock = maps[addr]["sock"]
		proc = maps[addr]["proc"]
		stat = maps[addr]["stat"].get()
		lval = maps[addr]["last"].get()
		if (lval < (secs - MAXT)):
			dels.add(addr)
		if (xfer):
			if (not proc.is_alive()):
				dels.add(addr)
			elif (not stat):
				dels.add(addr)
		else:
			mini(mins, klen, addr, lval)
			if (not stat):
				for keys in [(conn, "sadr", "srcs"), (sock, "dadr", "dsts")]:
					(fdes, adrs, objs) = keys
					fnum = fdes.fileno()
					if (fdes.c.get()):
						dels.add(addr)
					elif (fnum < 0):
						dels.add(addr)
					else:
						mapx[adrs][fnum] = addr
						mapx[objs].append(fdes)
	l = mins["l"]
	for i in mins["d"][:l]:
		dels.add(i[0])
	return (mapx, keyl, klen)

def tchk(p, o, r, x):
	while True:
		keyl = getl(o.keys())
		klen = len(keyl)
		mins = { "l":0, "d":[] }
		for addr in keyl:
			objc = getv(o, addr)
			if (objc):
				lval = objc["last"].get()
				join(objc["proc"], THRL)
				if (x):
					mini(mins, klen, addr, lval)
		l = mins["l"]
		for i in mins["d"][:l]:
			r.add(i[0])
		time.sleep(THRS)

def tcon(p, o, k, x):
	conn = o["conn"]
	sock = o["sock"]
	stat = o["stat"]
	last = o["last"]
	if (not sock.conn()):
		stat.set(False)
		conn.fins()
		sock.fins()
		return -1
	if (x):
		while (stat.get() and (not conn.c.get()) and (not sock.c.get())):
			rinp = [conn, sock]
			(rfds, wfds, efds) = sels(rinp)
			secs = gets()
			for s in [0, 1]:
				d = ((s + 1) % 2)
				if (rinp[s] in rfds):
					(data, addr) = rinp[s].recv()
					if (not data):
						stat.set(False)
					elif (rinp[d].send(data) < 0):
						stat.set(False)
					last.set(secs)
		stat.set(False)
		conn.fins()
		sock.fins()
		return 2
	stat.set(False)
	return 1

def comd(addr):
	try:
		cmdl = [COMD, addr[0], str(addr[1])]
		subp = subprocess.check_output(cmdl, shell=False, text=True)
		outp = subp.strip().split(":")
		return (outp[0], int(outp[1]))
	except Exception as e:
		fout("! error comd (%s)" % (e, ))
		return None

def serv(adrs, prot, mode):
	mudp = "pip"
	srvs = []
	maps = {}
	xfer = { "loop":False, "thread":True, "process":True }
	dels = set()
	for addr in adrs:
		sock = socket.socket(socket.AF_INET, SOCS[prot])
		sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		sock.bind(addr)
		if (prot == "tcp"):
			sock.listen(MAXC)
		sobj = SockObjc(prot, addr, sock=sock)
		srvs.append(sobj)
	chks = threading.Thread(target=tchk, args=(prot, maps, dels, xfer[mode], ))
	chks.start()
	while True:
		(mapx, keyl, klen) = mgmt(prot, maps, dels, xfer[mode])
		rinp = (srvs + mapx["srcs"] + mapx["dsts"])
		(rfds, wfds, efds) = sels(rinp)
		secs = gets()
		for fdes in rfds:
			if (fdes in srvs):
				(data, addr) = fdes.loop()
				tcpc = data
				if (not data):
					continue
				if (not addr in keyl):
					if (prot == "udp"):
						conn = SockObjc(mudp, addr, sock=fdes)
					if (prot == "tcp"):
						conn = SockObjc(prot, addr, sock=tcpc)
					dest = comd(addr)
					stat = SharedBool(True)
					last = SharedNum(secs)
					sock = SockObjc(prot, dest)
					fout("~ %s [%s:%s] <%s> (%s:%s)" % (prot, addr, dest, klen, conn.fileno(), sock.fileno(), ))
					objc = { "conn":conn, "sock":sock, "dest":dest, "last":last, "stat":stat, "proc":None }
					if ((mode == "loop") or (mode == "thread")):
						objc["proc"] = threading.Thread(target=tcon, args=(prot, objc, addr, xfer[mode], ))
					elif (mode == "process"):
						objc["proc"] = multiprocessing.Process(target=tcon, args=(prot, objc, addr, xfer[mode], ))
					objc["proc"].start()
					join(objc["proc"], THRT)
					maps[addr] = objc
					keyl.append(addr)
				if (addr in keyl):
					conn = maps[addr]["conn"]
					if (conn.pipe(data) < 0):
						dels.add(addr)
			for keys in [("srcs", "sadr", "sock"), ("dsts", "dadr", "conn")]:
				(objs, adrs, okey) = keys
				if (fdes in mapx[objs]):
					skey = getv(mapx[adrs], fdes.fileno())
					if (skey):
						sdes = maps[skey][okey]
						last = maps[skey]["last"]
						(data, addr) = fdes.recv()
						if (not data):
							dels.add(skey)
						elif (sdes.send(data) < 0):
							dels.add(skey)
						last.set(secs)
		keyd = getl(dels)
		if (keyd):
			for skey in keyd:
				objc = getv(maps, skey)
				if (objc):
					dest = objc["dest"]
					fout("x %s [%s:%s]" % (prot, skey, dest, ))
					objc["stat"].set(False)
					objc["conn"].fins()
					objc["sock"].fins()
					join(objc["proc"], THRL)
					if (objc["proc"].is_alive()):
						continue
					del maps[skey]
			dels.clear()

def main():
	global COMD, BLEN
	resource.setrlimit(resource.RLIMIT_NOFILE, (NOFI * MAXC, -1))
	args = { "byte":"store_true", "exec":"store", "fork":"store_true", "listen":"store", "mode":"store", "protocol":"store" }
	opts = argparse.ArgumentParser(description="proxy")
	for k in args.keys():
		opts.add_argument("-%s"%(k[0]), "--%s"%(k), action=args[k])
	args = opts.parse_args()
	if (args.byte):
		BLEN = 1
	if (args.exec):
		COMD = args.exec
	adrs = []
	for item in args.listen.split(","):
		info = item.split(":")
		adrs.append((info[0], int(info[1])))
	mmap = { "loop":"loop", "thread":"thread", "process":"process" }
	mode = mmap.get(args.mode, "loop")
	pmap = { "udp":"udp", "tcp":"tcp" }
	prot = pmap[args.protocol]
	fout("s %s [%s] (%s:%s)" % (adrs, prot, mode, BLEN, ))
	if (args.fork):
		cpid = os.fork()
		if (cpid != 0):
			sys.exit(0)
	serv(adrs, prot, mode)

if (__name__ == "__main__"):
	main()
