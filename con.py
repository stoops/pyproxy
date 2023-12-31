#!/usr/bin/python

import os, sys, socket, subprocess, time

def stdo(line):
	secs = str(time.time()).split(".")[1].zfill(9)
	date = time.strftime("%Y-%m-%d_%H:%M:%S")
	sys.stdout.write("[%s.%s] %s\n" % (date, secs, line, ))
	sys.stdout.flush()

def caps(intf, ladr):
	last = 0
	maxt = 666
	cons = {}
	(mark, pudp, ptcp, null) = (b"flags", b"udp", b"tcp", b"")
	(sepr, colo, dots, dirs) = (b" ", b":", b".", b">")
	proc = subprocess.Popen(["tcpdump", "-nni", intf, "src", "net", ladr, "and", "not", "dst", "net", ladr], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	while True:
		line = proc.stdout.readline().lower().replace(mark, ptcp)
		secs = int(time.time())
		prot = b""
		if (ptcp in line):
			prot = ptcp
		else:
			prot = pudp
		if (prot):
			info = line.replace(colo, null).split(sepr)
			if ((len(info) > 4) and (info[2].count(dots) == 4) and (info[3] == dirs)):
				sadr = colo.join(info[2].rsplit(dots, 1))
				dadr = colo.join(info[4].rsplit(dots, 1))
				sadr = (prot + colo + sadr).decode()
				dadr = dadr.decode()
				keys = list(cons.keys())
				if ((not sadr in keys) or (cons[sadr][0] != dadr)):
					stdo("conn (%s)->(%s) [%s]" % (sadr, dadr, len(keys), ))
				cons[sadr] = [dadr, secs]
		if ((secs - last) >= 5):
			keys = list(cons.keys())
			for addr in keys:
				if ((secs - cons[addr][1]) >= maxt):
					stdo("dels (%s)->%s" % (addr, cons[addr], ))
					del cons[addr]
			last = secs

def main():
	pidn = os.fork()
	if (pidn != 0):
		stdo("info fork [%s]" % (pidn, ))
		sys.exit(0)
	caps(sys.argv[1], sys.argv[2])

if (__name__ == "__main__"):
	main()
