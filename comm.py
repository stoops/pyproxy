import os, sys, socket, select, subprocess, time
import argparse, ipaddress, sqlite3

def stdo(line):
	secs = str(time.time()).split(".")[1].zfill(9)
	date = time.strftime("%b-%d-%Y/%H:%M:%S")
	sys.stdout.write("[%s.%s] %s\n" % (date, secs, line, ))
	sys.stdout.flush()

def gets():
	return int(time.time())

def make(adrs):
	info = adrs.split(":")
	return (info[0], int(info[1]))

def sels(socs, wait=None):
	try:
		return select.select(socs, [], [], wait)
	except:
		return ([None], [None], [None])

def recv(objc, size=1500):
	(data, addr) = (b"", None)
	try:
		(data, addr) = objc.recvfrom(size)
	except Exception as e:
		stdo("erro recv %s" % (e, ))
	return (data, addr)

def send(objc, addr, data):
	size = -1
	try:
		while (data):
			size = objc.sendto(data, addr)
			if (size < 1):
				raise Exception("size")
			data = data[size:]
	except Exception as e:
		stdo("erro send [%s] [%s] [%s] %s" % (objc, addr, len(data), e, ))
	return size

def accp(objc):
	outp = (None, None)
	try:
		outp = objc.accept()
	except Exception as e:
		stdo("erro accp %s" % (e, ))
	return outp

def syns(objc, dest):
	try:
		objc.connect(dest)
	except Exception as e:
		stdo("erro syns %s" % (e, ))

def trea(objc, size=8192):
	outp = b""
	try:
		outp = objc.recv(size)
	except Exception as e:
		stdo("erro trea %s" % (e, ))
	return outp

def tsnd(objc, data):
	size = -1
	try:
		objc.sendall(data)
		size = len(data)
	except Exception as e:
		stdo("erro tsnd %s" % (e, ))
	return size

def shut(objc):
	try:
		objc.shutdown(socket.SHUT_RDWR)
	except:
		pass
	try:
		objc.close()
	except:
		pass

def prga(objc, prot, mode, skey, data):
	outp = b""
	try:
		outp = objc.prga(prot, mode, skey, data)
	except Exception as e:
		stdo("erro prga %s" % (e, ))
	return outp

def sksa(objc, prot, keys, init):
	try:
		objc.sksa(prot, keys, init)
	except Exception as e:
		stdo("erro sksa %s" % (e, ))
		return False
	return True

def decr(sepr, data):
	(sadr, dadr, outp) = (None, None, b"")
	try:
		info = data.split(sepr, 2)
		sadr = make(info[0].decode())
		dadr = make(info[1].decode())
		outp = info[2]
	except Exception as e:
		stdo("erro decr %s" % (e, ))
	return (sadr, dadr, outp)

def prep(objc, prot, keys, sepr, data):
	outp = b""
	try:
		info = data.split(sepr, 1)
		ivec = info[0].decode()
		sksa(objc, prot, keys, ivec)
		outp = info[1]
	except Exception as e:
		stdo("erro prep %s" % (e, ))
	return outp

def ipin(addr, nots):
	try:
		iadr = ipaddress.ip_address(addr[0])
		for netw in nots:
			if (iadr in netw):
				return True
	except Exception as e:
		stdo("erro ipin %s" % (e, ))
	return False

def join(thre, wait):
	stat = True
	try:
		thre.join(timeout=wait)
	except Exception as e:
		stdo("erro join %s" % (e, ))
		stat = False
	try:
		stat = thre.is_alive()
	except Exception as e:
		stdo("erro stat %s" % (e, ))
		stat = False
	return stat

def comd(path, addr, prot, sock, mesg=False, port=0):
	sadr = ("%s:%s:%s" % (prot, addr[0], addr[1]))
	(secs, outp) = (gets(), None)
	ladr = ("127.0.0.1", 31337)
	try:
		if (not sock.gettimeout()):
			sock.settimeout(3)
		while True:
			(rfds, wfds, efds) = select.select([sock], [], [], 0)
			if (not sock in rfds):
				break
			(xmsg, xadr) = recv(sock)
	except Exception as e:
		pass
	try:
		rowq = ("get\n%s\nnull" % (sadr, )).encode()
		send(sock, ladr, rowq)
		(rowl, xadr) = recv(sock)
		if (rowl):
			rowl = rowl.decode().strip()
		if (rowl):
			if (mesg):
				stdo("info cached [%s] %s" % (secs, rowl, ))
			outp = make(rowl.strip())
	except Exception as e:
		stdo("erro comd get [%s] %s" % (addr, e, ))
		rowl = ""
	if (not outp):
		try:
			cmdl = [path, addr[0], str(addr[1]), prot]
			subp = subprocess.check_output(cmdl, shell=False, text=True)
			outp = make(subp.strip())
		except Exception as e:
			stdo("warn comd exe [%s] %s" % (addr, e, ))
	if (not outp):
		return (outp, port)
	try:
		sqrr = ("%s:%s:" % (prot, addr[0]))
		dqrr = ("%s:%s:" % (outp[0], outp[1]))
		rowq = ("try\n%s\n%s" % (sqrr, dqrr, )).encode()
		send(sock, ladr, rowq)
		(rows, xadr) = recv(sock)
		if (rows):
			rows = rows.decode().strip()
		if (rows):
			if (mesg):
				stdo("info cached [%s] %s" % (secs, rows, ))
			info = rows.strip().split(":")
			if (len(info) > 2):
				port = int(info[2])
		dadr = ("%s:%s:%s" % (outp[0], outp[1], port))
		rowq = ("set\n%s\n%s" % (sadr, dadr, )).encode()
		send(sock, ladr, rowq)
	except Exception as e:
		stdo("erro comd try [%s] %s" % (addr, e, ))
	return (outp, port)
