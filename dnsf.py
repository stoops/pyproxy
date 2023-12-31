#!/usr/bin/python

from comm import *
import ciph

def loop(prot, mode, lsrc, lprt, ddst, dprt, skey):
	dest = (ddst, int(dprt))
	serv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	socs = [serv]
	maps = [None]
	arcf = None

	serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	serv.bind((lsrc, int(lprt)))
	if (mode):
		arcf = ciph.ArcfCiph(skey)

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
					clis = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
					if (mode == "e"):
						data = prga(arcf, prot, "e", "x", data)
					stdo("info serv %s [%s] %s" % (addr, clis.fileno(), len(data), ))
					if (mode == "d"):
						data = prga(arcf, prot, "d", "x", data)
					if (data):
						send(clis, dest, data)
						socs.append(clis)
						maps.append((clis, addr))
					while (len(socs) > 96):
						socs[1].close()
						maps.pop(1)
						socs.pop(1)
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
	argp.add_argument("-l", "--lsrc", action="store", default="127.0.0.1")
	argp.add_argument("-p", "--lprt", action="store", default="53")
	argp.add_argument("-d", "--dest", action="store")
	argp.add_argument("-q", "--dprt", action="store")
	argp.add_argument("-m", "--mode", action="store")
	argp.add_argument("-k", "--skey", action="store", default="null")
	args = argp.parse_args(sys.argv[1:])

	pidn = os.fork()
	if (pidn != 0):
		stdo("info fork %s" % (pidn, ))
		sys.exit(0)

	prot = "udp"
	loop(prot, args.mode, args.lsrc, args.lprt, args.dest, args.dprt, args.skey)

if (__name__ == "__main__"):
	main()
