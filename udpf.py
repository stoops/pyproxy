#!/usr/bin/python

from comm import *
import ciph

def loop(prot, mode, lsrc, lprt, ddst, dprt, skey, cmds, cmdf, nofi):
	sepr = b"\n"
	dest = (ddst, int(dprt))
	serv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	socs = [serv]
	maps = [None]
	arcf = None
	cmdc = [cmdf, sqlite3.connect(cmdf)]
	nots = []

	serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	serv.bind((lsrc, int(lprt)))
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

	stdo("%s %s %s %s %s %s %s %s %s" % (prot, mode, lsrc, lprt, ddst, dprt, cmds, cmdf, nofi))

	while True:
		try:
			(rfds, wfds, efds) = select.select(socs, [], [])
		except Exception as e:
			stdo("erro sels %s" % (e, ))
			(rfds, wfds, efds) = ([], [], [])
			break
		try:
			secs = gets()
			for fdes in rfds:
				(data, addr) = recv(fdes)
				if (not data):
					continue
				(eadr, dmsg) = (dest, data)
				if (fdes == serv):
					(indx, remo, leng, clis, lock) = (-1, 1, len(maps), None, [0, 0])
					for i in range(1, leng):
						(cobj, cadr, cexc, lsec, lout) = (maps[i][0], maps[i][1], maps[i][2], maps[i][3], maps[i][4])
						if (cadr == addr):
							(indx, clis, lock) = (i, cobj, lout)
							maps[i][3] = secs
						elif (lsec < maps[remo][3]):
							remo = i
					dadr = comd(cmds, addr, prot, cmdc)
					if (not dadr):
						continue
					excl = ipin(dadr, nots)
					if (excl):
						eadr = dadr
					if (not clis):
						clis = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
					if ((mode == "e") and (not excl)):
						info = ("%s:%d" % (dadr[0], dadr[1])).encode()
						data = (info + sepr + data)
						data = prga(arcf, prot, "e", "x", data)
					if ((mode == "d") and (not excl)):
						data = prga(arcf, prot, "d", "x", data)
						(dadr, data) = decr(sepr, data)
						eadr = dadr
					if ((secs - lock[0]) > 1):
						stdo("info serv %s %s:%s [%s] %s:%s" % (addr, eadr, dadr, clis.fileno(), len(dmsg), len(data), ))
						lock[0] = secs
					send(clis, eadr, data)
					if (indx < 0):
						lock = [secs, secs]
						socs.append(clis)
						maps.append([clis, addr, excl, secs, lock])
						leng += 1
					if (leng > 96):
						if (indx < 0):
							socs[remo].close()
							maps.pop(remo)
							socs.pop(remo)
				else:
					for item in maps:
						if (not item):
							continue
						(clis, addr, excl, last, lock) = (item[0], item[1], item[2], item[3], item[4])
						if (clis == fdes):
							if ((mode == "d") and (not excl)):
								data = prga(arcf, prot, "e", "x", data)
							if ((mode == "e") and (not excl)):
								data = prga(arcf, prot, "d", "x", data)
							if ((secs - lock[1]) > 1):
								stdo("info clis %s [%s] %s:%s" % (addr, clis.fileno(), len(dmsg), len(data), ))
								lock[1] = secs
							send(serv, addr, data)
							item[3] = secs
		except Exception as e:
			stdo("erro loop %s" % (e, ))

def main():
	argp = argparse.ArgumentParser(description="udp")
	argp.add_argument("-l", "--lsrc", action="store", default="127.0.0.1")
	argp.add_argument("-p", "--lprt", action="store", default="31337")
	argp.add_argument("-d", "--dest", action="store")
	argp.add_argument("-q", "--dprt", action="store")
	argp.add_argument("-e", "--exec", action="store", default="/usr/bin/true")
	argp.add_argument("-f", "--dbfi", action="store", default="/tmp/udps.db")
	argp.add_argument("-m", "--mode", action="store")
	argp.add_argument("-n", "--nots", action="store")
	argp.add_argument("-k", "--skey", action="store", default="null")
	args = argp.parse_args(sys.argv[1:])

	pidn = os.fork()
	if (pidn != 0):
		stdo("info fork %s" % (pidn, ))
		sys.exit(0)

	prot = "udp"
	loop(prot, args.mode, args.lsrc, args.lprt, args.dest, args.dprt, args.skey, args.exec, args.dbfi, args.nots)

if (__name__ == "__main__"):
	main()
