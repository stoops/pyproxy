#!/usr/bin/python

import time, threading
from comm import *
import ciph

def stop(thrs, indx, mesg):
	objc = thrs[indx]
	(thid, addr) = (objc["thid"], objc["socs"][0])
	stdo("info mgmt %s:%s %s %s" % (thid, indx, addr, mesg, ))
	objc["stat"] = False
	thrs.pop(indx)

def mgmt(maxs, thrs):
	while True:
		(leng, dels) = (len(thrs), [])
		for indx in range(0, leng):
			if (not join(thrs[indx]["thre"], 0.01)):
				dels.append(indx)
		dels.sort()
		dels.reverse()
		for remo in dels:
			stop(thrs, remo, "stat")
		while (len(thrs) > maxs):
			(leng, remo) = (len(thrs), 1)
			for indx in range(0, leng):
				if (thrs[indx]["last"] < thrs[remo]["last"]):
					remo = indx
			stop(thrs, remo, "limi")
		time.sleep(0.90)

def xfer(prot, mode, skey, sepr, nots, objc):
	(thid, leng) = (objc["thid"], objc["leng"])
	(addr, dest, dadr, conn, clis) = objc["socs"]

	secs = gets()
	lock = [0, 0]
	arcs = None
	if (mode):
		arcs = ciph.ArcfCiph(skey)

	data = trea(conn)
	if (not data):
		shut(clis)
		shut(conn)
		return -1
	(eadr, dmsg) = (dest, data)
	excl = ipin(dadr, nots)
	if (excl):
		eadr = dadr
	if ((mode == "e") and (not excl)):
		ivec = str(time.time())
		sksa(arcs, prot, ["r", "s"], ivec)
		info = ("%s:%d" % (dadr[0], dadr[1])).encode()
		inpt = (info + sepr + data)
		outp = prga(arcs, prot, "e", "r", inpt)
		data = (ivec.encode() + sepr + outp)
	if ((mode == "d") and (not excl)):
		while (not sepr in data):
			temp = trea(conn)
			if (not temp):
				break
			data += temp
		inpt = prep(arcs, prot, ["r", "s"], sepr, data)
		outp = prga(arcs, prot, "d", "r", inpt)
		(dadr, data) = decr(sepr, outp)
		eadr = dadr
	if ((secs - lock[0]) > 1):
		stdo("info serv %s:i %s %s:%s [%s:%s] (%s)" % (thid, addr, eadr, dadr, conn.fileno(), clis.fileno(), leng, ))
		lock[0] = secs
	syns(clis, eadr)
	if (tsnd(clis, data) < 1):
		shut(clis)
		shut(conn)
		return -2

	socs = [conn, clis]
	lock = [secs, secs]
	pair = [(conn, clis, {"e":"e", "d":"d"}, "r", 0), (clis, conn, {"d":"e", "e":"d"}, "s", 1)]
	while objc["stat"]:
		try:
			(rfds, wfds, efds) = select.select(socs, [], [], 3)
		except Exception as e:
			stdo("erro xfer %s" % (e, ))
			objc["stat"] = False
			break
		secs = gets()
		for fdes in rfds:
			for item in pair:
				(ssoc, dsoc, oper, keys, indx) = item
				if (ssoc != fdes):
					continue
				data = trea(ssoc)
				dmsg = data
				if (not data):
					objc["stat"] = False
					break
				if (((mode == "e") or (mode == "d")) and (not excl)):
					data = prga(arcs, prot, oper[mode], keys, data)
				if ((secs - lock[indx]) > 1):
					stdo("info xfer %s:%s %s [%s:%s]" % (thid, keys, addr, ssoc.fileno(), dsoc.fileno(), ))
					lock[indx] = secs
				if (tsnd(dsoc, data) < 1):
					objc["stat"] = False
					break
				objc["last"] = secs

	shut(clis)
	shut(conn)
	return 0

def loop(prot, mode, lsrc, lprt, ddst, dprt, skey, cmds, cmdf, nofi):
	maxs = 96
	sepr = b"\n"
	dest = (ddst, int(dprt))
	serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	cmdc = [cmdf, sqlite3.connect(cmdf)]
	nots = []
	thrs = []

	serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	serv.bind((lsrc, int(lprt)))
	serv.listen(16)
	if (nofi):
		fobj = open(nofi, "r")
		for line in fobj.readlines():
			line = line.strip()
			if ((not line) or line.startswith("#")):
				continue
			anet = ipaddress.ip_network(line)
			nots.append(anet)
		fobj.close()

	stdo("%s %s %s %s %s %s %s %s %s" % (prot, mode, lsrc, lprt, ddst, dprt, cmds, cmdf, nofi))

	thid = 0
	thrm = threading.Thread(target=mgmt, args=(maxs, thrs, ))
	thrm.start()
	while True:
		(conn, addr) = accp(serv)
		if ((not conn) or (not addr)):
			close(conn)
			continue
		dadr = comd(cmds, addr, prot, cmdc)
		if (not dadr):
			close(conn)
			continue
		clis = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		secs = gets()
		leng = len(thrs)
		thid = max(secs, thid + 1)
		socs = (addr, dest, dadr, conn, clis)
		objc = {"stat":True, "last":secs, "thid":thid, "leng":leng, "socs":socs, "thre":None}
		thre = threading.Thread(target=xfer, args=(prot, mode, skey, sepr, nots, objc, ))
		thre.start()
		objc["thre"] = thre
		thrs.append(objc)

def main():
	argp = argparse.ArgumentParser(description="tcp")
	argp.add_argument("-l", "--lsrc", action="store", default="127.0.0.1")
	argp.add_argument("-p", "--lprt", action="store", default="31337")
	argp.add_argument("-d", "--dest", action="store")
	argp.add_argument("-q", "--dprt", action="store")
	argp.add_argument("-e", "--exec", action="store", default="/usr/bin/true")
	argp.add_argument("-f", "--dbfi", action="store", default="/tmp/tcps.db")
	argp.add_argument("-m", "--mode", action="store")
	argp.add_argument("-n", "--nots", action="store")
	argp.add_argument("-k", "--skey", action="store", default="null")
	args = argp.parse_args(sys.argv[1:])

	pidn = os.fork()
	if (pidn != 0):
		stdo("info fork %s" % (pidn, ))
		sys.exit(0)

	prot = "tcp"
	loop(prot, args.mode, args.lsrc, args.lprt, args.dest, args.dprt, args.skey, args.exec, args.dbfi, args.nots)

if (__name__ == "__main__"):
	main()
