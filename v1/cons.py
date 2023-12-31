#!/usr/bin/python

import os, sys, socket, subprocess, time, threading

def stdo(line):
	secs = int(time.time())
	sys.stdout.write("[%s] %s\n" % (secs, line, ))
	sys.stdout.flush()

def send(sock, data, addr):
	try:
		sock.sendto(data, addr)
	except:
		pass

def mons(maxt, intf, ladr, cons):
	last = 0
	(mark, pudp, ptcp, null) = (b"flags", b"udp", b"tcp", b"")
	(sepr, colo, dots, dirs) = (b" ", b":", b".", b">")
	proc = subprocess.Popen(["tcpdump", "-nni", intf, "src", "net", ladr, "and", "not", "dst", "net", ladr], shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	while True:
		line = proc.stdout.readline().lower().replace(mark, ptcp)
		secs = int(time.time())
		prot = b""
		if (pudp in line):
			prot = pudp
		elif (ptcp in line):
			prot = ptcp
		if (prot):
			info = line.replace(colo, null).split(sepr)
			if ((len(info) > 4) and (info[3] == dirs)):
				srca = colo.join(info[2].rsplit(dots, 1))
				dstb = colo.join(info[4].rsplit(dots, 1))
				srca = (prot + colo + srca)
				keys = list(cons.keys())
				if (not srca in keys):
					stdo("info mons add %s %s %s %s" % (srca, dstb, secs, len(keys), ))
				cons[srca] = [dstb, secs]
		if ((secs - last) > 3):
			keys = list(cons.keys())
			for k in keys:
				if ((secs - cons[k][1]) > maxt):
					stdo("info mons del %s %s" % (k, cons[k], ))
					del cons[k]
			last = secs

def loop():
	sepr = b"\n"
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.bind(("127.0.0.1", 31337))
	maps = {}
	cons = {}

	(maxc, maxt) = ((2 ** 7) + (2 ** 5), (2 ** 9) + (2 ** 7))
	(gets, trys, sets) = (b"get", b"try", b"set")
	if (sys.argv[1:]):
		args = sys.argv[1].split(",")
		(intf, ladr) = (args[0], args[1])
		thrm = threading.Thread(target=mons, args=(maxt, intf, ladr, cons, ))
		thrm.start()
	while True:
		try:
			(data, addr) = sock.recvfrom(1024)
		except KeyboardInterrupt:
			break
		except:
			(data, addr) = (None, None)
		if ((not data) or (not addr)):
			continue
		secs = int(time.time())
		keyl = list(maps.keys())
		(leng, keyu, resp, repl) = (len(keyl), [], None, False)
		try:
			info = data.split(sepr)
			(acts, keys, vals) = (info[0], info[1], info[2])
			if (acts == gets):
				keyu.append(keys)
				repl = True
			elif (acts == trys):
				for keyn in keyl:
					valu = maps[keyn][0]
					if (keyn.startswith(keys) and valu.startswith(vals)):
						keyu.append(keyn)
				repl = True
			elif (acts == sets):
				maps[keys] = [vals, secs]
				for keyn in keyl:
					last = maps[keyn][1]
					if ((secs - last) >= maxt):
						stdo("info dels [%s] -> %s (%s)" % (keyn, maps[keyn], leng, ))
						del maps[keyn]
				keyl = list(maps.keys())
		except:
			pass
		for keyn in keyu:
			if (not keyn in keyl):
				if (keyn in cons.keys()):
					vals = cons[keyn][0]
					maps[keyn] = [vals, secs]
					keyl = list(maps.keys())
					stdo("info cons [%s] -> [%s]" % (keyn, vals, ))
			if (keyn in keyl):
				if (not resp):
					resp = maps[keyn][0]
				maps[keyn][1] = secs
		if ((not resp) and repl):
			resp = b" "
		stdo("info serv %s -> [%s] (%s)" % (info, resp, leng, ))
		if (resp):
			send(sock, resp, addr)

def main():
	pidn = os.fork()
	if (pidn != 0):
		stdo("info fork %s" % (pidn, ))
		sys.exit(0)
	loop()

if (__name__ == "__main__"):
	main()
