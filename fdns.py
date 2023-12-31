#!/usr/bin/python

from comm import *
import ciph

def loop(prot, lsrc, ddst, mode, skey):
	(lstn, dest) = (make(lsrc), make(ddst))
	serv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	socs = [serv]
	maps = [None]
	arcf = None

	serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	serv.bind(lstn)
	if (mode):
		arcf = ciph.ArcfCiph(skey)

	maxc = (2 ** 6)
	while True:
		try:
			(rfds, wfds, efds) = select.select(socs, [], [])
		except Exception as e:
			stdo("erro sels %s" % (e, ))
			(rfds, wfds, efds) = ([], [], [])
			break
		try:
			for fdes in rfds:
				(data, addr) = recv(fdes)
				if (not data):
					continue
				if (fdes == serv):
					if (mode == "e"):
						data = prga(arcf, prot, "e", "x", data)
					if (mode == "d"):
						data = prga(arcf, prot, "d", "x", data)
					if (data):
						clis = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
						stdo("info serv %s [%s] %s" % (addr, clis.fileno(), len(data), ))
						send(clis, dest, data)
						socs.append(clis)
						maps.append((clis, addr))
					while (len(maps) > maxc):
						remo = 1
						maps[remo][0].close()
						maps.pop(remo)
						socs.pop(remo)
				else:
					for item in maps:
						if (not item):
							continue
						(clis, addr) = item
						if (clis == fdes):
							if (mode == "d"):
								data = prga(arcf, prot, "e", "x", data)
							stdo("info clis %s [%s] %s" % (addr, clis.fileno(), len(data), ))
							if (mode == "e"):
								data = prga(arcf, prot, "d", "x", data)
							send(serv, addr, data)
		except Exception as e:
			stdo("erro loop %s" % (e, ))

def main():
	argp = argparse.ArgumentParser(description="dns")
	argp.add_argument("-l", "--list", action="store", default="127.0.0.1:53")
	argp.add_argument("-d", "--dest", action="store", default="127.0.0.1:35")
	argp.add_argument("-m", "--mode", action="store")
	argp.add_argument("-k", "--skey", action="store", default="null")
	args = argp.parse_args(sys.argv[1:])

	pidn = os.fork()
	if (pidn != 0):
		stdo("info fork %s" % (pidn, ))
		sys.exit(0)

	prot = "udp"
	loop(prot, args.list, args.dest, args.mode, args.skey)

if (__name__ == "__main__"):
	main()
