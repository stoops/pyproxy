#!/usr/bin/python

import threading
from comm import *
import ciph

GOOD = b"\xff\x13\x37\xff"
TERM = b"\xff\x00\x00\xff"
ZADR = ("0.0.0.0", 0)

def stop(maxs, socs, maps, thrs, mult, dels):
	temp = list(dels)
	temp.sort() ; temp.reverse()
	while (temp):
		indx = temp.pop(0)
		item = maps[indx]
		(clis, adrs, last) = (item[0], item[1], item[3])
		if ((last[5] == -1) or (last[5] == -2)):
			fins = True
			if (mult and join(thrs[indx], 0.10)):
				fins = False
			if (fins):
				last[5] = -3
		if (last[5] == -3):
			clis.close()
			maps.pop(indx)
			if (not mult):
				socs.pop(indx)
			else:
				thrs.pop(indx)
			stdo("info stop %s %s [%s]" % (adrs[:2], last, indx, ))
	dels.clear()

def mgmt(maxs, socs, maps, thrs, mult, dels):
	(maxc, maxt) = maxs
	while True:
		(secs, leng, wait) = (gets(), len(maps), False)
		if (dels):
			wait = True
		if (not wait):
			for i in range(1, leng):
				try:
					item = maps[i]
				except Exception as e:
					wait = True ; break
				if (item[3][5] < 0):
					wait = True ; break
		if (not wait):
			(mini, remo) = (1, [])
			for indx in range(1, leng):
				(last, lout) = (maps[indx][3], maps[mini][3])
				if ((secs - last[0]) > maxt):
					remo.append(indx)
				if (last[0] < lout[0]):
					mini = indx
			if (leng > maxc):
				remo.append(mini)
			for indx in remo:
				(adrs, last) = (maps[indx][1], maps[indx][3])
				stdo("info remo %s %s [%s/%s]" % (adrs[:2], last, leng, indx, ))
				last[5] = -1
		time.sleep(0.90)

def xfer(mode, prot, serv, clis, adrs, excl, last, arcf, init):
	(sadr, dadr, eadr) = (adrs[1], adrs[2], adrs[3])
	(rfds, wfds, efds) = ([clis], [], [])
	mapx = { TERM:["term", None], GOOD:["good", ZADR] }
	while (last[5] == 0):
		if (not init):
			try:
				(rfds, wfds, efds) = select.select([clis], [], [], 3)
			except Exception as e:
				stdo("erro xfer %s" % (e, ))
				(rfds, wfds, efds) = ([], [], [])
				last[5] = -2 ; break
		if (clis in rfds):
			(secs, addr, data) = (gets(), adrs[0], init)
			if (not init):
				(data, radr) = recv(clis)
			if (not data):
				last[5] = -2 ; break
			if ((mode == "e") and (data in mapx.keys())):
				stdo("warn %s %s" % (mapx[data][0], adrs, ))
				adrs[4] = mapx[data][1]
			else:
				if ((mode == "d") and (not excl)):
					data = prga(arcf, prot, "e", "x", data)
				if ((mode == "e") and (not excl)):
					data = prga(arcf, prot, "d", "x", data)
				if (data):
					if ((secs - last[2]) >= 1):
						stdo("info clis %s:%s %s:%s [%s]" % (addr, sadr, dadr, eadr, clis.fileno() ))
						last[2] = secs
					send(serv, addr, data)
			last[0] = secs
		if (init):
			return 0
	if (not init):
		last[5] = -2
		stdo("info ends %s %s [%s]" % (adrs[:2], last, clis.fileno() ))

def loop(prot, lsrc, ddst, mode, skey, cmds, cmdf, nofi):
	sepr = b"\n"
	(lstn, dest) = (make(lsrc), make(ddst))
	serv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	socs = [serv]
	maps = [None]
	arcf = None
	cmdc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	nots = []
	thrs = [None]
	dels = set()

	serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	serv.bind(lstn)
	if (mode):
		arcf = ciph.ArcfCiph(skey)
	if (nofi):
		fobj = open(nofi, "r")
		for line in fobj.readlines():
			line = line.strip()
			if ((not line) or line.startswith("#")):
				continue
			anet = ipaddress.ip_network(line)
			nots.append(anet)
		fobj.close()
	cmdo = { x:bool(x & int(cmdf)) for x in [1, 2, 4] }
	hold = { "*":[] }

	stdo("%s %s %s %s %s %s %s" % (prot, lstn, dest, mode, cmds, cmdo, nofi))

	(maxc, maxt) = ((2 ** 7) + (2 ** 5), (2 ** 9) + (2 ** 7))
	(maxs, reus, resu, mult) = ((maxc, maxt), cmdo[4], cmdo[2], cmdo[1])
	thrm = threading.Thread(target=mgmt, args=(maxs, socs, maps, thrs, mult, dels, ))
	thrm.start()
	while True:
		try:
			(rfds, wfds, efds) = select.select(socs, [], [])
		except Exception as e:
			stdo("erro sels %s" % (e, ))
			(rfds, wfds, efds) = ([], [], [])
			break
		secs = gets()
		for fdes in rfds:
			(data, addr) = recv(fdes)
			if (not data):
				continue
			if (fdes == serv):
				(indx, leng, last) = (-1, len(maps), [0, 0, 0, 0, 0, 0])
				(dadr, clis, excl, rest) = (None, None, False, False)
				(sadr, eadr, port) = (addr, None, dest[1])
				for i in range(1, leng):
					item = maps[i]
					(cobj, adrs, cexc, lout) = (item[0], item[1], item[2], item[3])
					if (lout[5] < 0):
						dels.add(i)
					elif (adrs[0] == addr):
						(sadr, dadr, eadr) = (adrs[1], adrs[2], adrs[3])
						(indx, clis, last, excl, port) = (i, cobj, lout, cexc, eadr[1])
						if ((secs - last[3]) >= 1):
							stdo("info conn %s:%s [%s/%s]" % (addr, dadr, port, indx, ))
							last[3] = secs
						if (adrs[4] == ZADR):
							rest = True
				if (not dadr):
					(dadr, port) = comd(cmds, addr, prot, cmdc, port=port)
					if (dadr):
						excl = ipin(dadr, nots)
						if (excl):
							eadr = dadr
				if (not dadr):
					continue
				if ((mode == "e") and (not excl)):
					if (not eadr):
						eadr = dest
					eadr = (eadr[0], port)
					if ((not resu) or (not rest)):
						init = ("%s:%d" % (sadr[0], sadr[1])).encode()
						info = ("%s:%d" % (dadr[0], dadr[1])).encode()
						data = (init + sepr + info + sepr + data)
					else:
						data = (GOOD + sepr + data)
					data = prga(arcf, prot, "e", "x", data)
				if ((mode == "d") and (not excl)):
					data = prga(arcf, prot, "d", "x", data)
					if (not data.startswith(GOOD + sepr)):
						(sadr, dadr, data) = decr(sepr, data)
						eadr = dadr
						if (eadr):
							if ((last[4] < 1) and (indx > 0)):
								send(serv, addr, GOOD)
								last[4] = secs
					else:
						data = data[5:]
					if (data and (not eadr)):
						stdo("warn decr %s:%s %s:%s %s [%s]" % (addr, sadr, dadr, eadr, lstn, indx, ))
						send(serv, addr, TERM)
						last[4] = 0
						if (not addr in hold.keys()):
							hold[addr] = []
							hold["*"].append(addr)
							if (len(hold["*"]) > maxc):
								keyn = hold["*"].pop(0)
								del hold[keyn]
						if (len(hold[addr]) < maxc):
							hold[addr].append(data)
				if (reus):
					for i in range(1, leng):
						item = maps[i]
						(cobj, adrs, cexc, lout) = (item[0], item[1], item[2], item[3])
						if (lout[5] < 0):
							dels.add(i)
						elif ((adrs[1] == sadr) and (adrs[2] == dadr)):
							(sadr, dadr, eadr) = (adrs[1], adrs[2], adrs[3])
							(indx, clis, last) = (i, cobj, lout)
							if (addr != adrs[0]):
								stdo("info redr %s:%s -> %s:%s" % (sadr, dadr, adrs[0], addr, ))
								(adrs[0], lout[0]) = (addr, secs)
				if (data and eadr):
					if (not clis):
						clis = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
					if ((secs - last[1]) >= 1):
						stdo("info serv %s:%s %s:%s %s [%s:%s]" % (addr, sadr, dadr, eadr, lstn, clis.fileno(), indx, ))
						last[1] = secs
					if (addr in hold.keys()):
						while (len(hold[addr]) > 0):
							stdo("warn hold %s:%s %s:%s %s [%s]" % (addr, sadr, dadr, eadr, lstn, indx, ))
							buff = hold[addr].pop(0)
							send(clis, eadr, buff)
						del hold[addr]
						hold["*"].remove(addr)
					send(clis, eadr, data)
					last[0] = secs
					if (indx < 0):
						(null, arct, xadr) = (b"", ciph.ArcfCiph(skey), None)
						adrs = [addr, sadr, dadr, eadr, xadr]
						objc = [clis, adrs, excl, last]
						maps.append(objc)
						if (not mult):
							socs.append(clis)
						else:
							thre = threading.Thread(target=xfer, args=(mode, prot, serv, clis, adrs, excl, last, arct, null, ))
							thre.start()
							thrs.append(thre)
			else:
				for i in range(1, leng):
					item = maps[i]
					(clis, adrs, excl, last) = (item[0], item[1], item[2], item[3])
					if ((clis == fdes) and (last[5] == 0)):
						xfer(mode, prot, serv, clis, adrs, excl, last, arcf, data)
		stop(maxs, socs, maps, thrs, mult, dels)

def main():
	argp = argparse.ArgumentParser(description="udp")
	argp.add_argument("-l", "--list", action="store", default="127.0.0.1:31337")
	argp.add_argument("-d", "--dest", action="store", default="127.0.0.1:37331")
	argp.add_argument("-e", "--exec", action="store", default="/usr/bin/true")
	argp.add_argument("-c", "--cons", action="store", default="7")
	argp.add_argument("-m", "--mode", action="store")
	argp.add_argument("-n", "--nots", action="store")
	argp.add_argument("-k", "--skey", action="store", default="null")
	args = argp.parse_args(sys.argv[1:])

	pidn = os.fork()
	if (pidn != 0):
		stdo("info fork %s" % (pidn, ))
		sys.exit(0)

	prot = "udp"
	loop(prot, args.list, args.dest, args.mode, args.skey, args.exec, args.cons, args.nots)

if (__name__ == "__main__"):
	main()
