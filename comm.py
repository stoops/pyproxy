import os, sys, socket, select, subprocess, time
import argparse, ipaddress, sqlite3

def stdo(line):
	secs = str(time.time()).split(".")
	sys.stdout.write("[%s.%s] %s\n" % (secs[0], secs[1].zfill(9), line, ))
	sys.stdout.flush()

def gets():
	return int(time.time())

def make(adrs):
	info = adrs.split(":")
	return (info[0], int(info[1]))

def recv(objc, size=1500):
	(data, addr) = (None, None)
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
		stdo("erro send %s" % (e, ))
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
	(addr, outp) = (None, b"")
	try:
		info = data.split(sepr, 1)
		addr = make(info[0].decode())
		outp = info[1]
	except Exception as e:
		stdo("erro decr %s" % (e, ))
	return (addr, outp)

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

def comd(path, addr, prot, cmdc, mesg=False):
	outp = None
	(maxs, secs, curs, sadr) = (300, gets(), cmdc[1].cursor(), "%s:%s:%s" % (addr[0], addr[1], prot))
	try:
		if (os.stat(cmdc[0]).st_size == 0):
			curs.execute("CREATE TABLE cons(secs INTEGER, sadr TEXT, dadr TEXT)")
		curs.execute("DELETE FROM cons WHERE secs <= '%s'" % (secs-maxs))
	except Exception as e:
		stdo("erro comd sql new [%s] %s" % (addr, e, ))
	try:
		rows = curs.execute("SELECT * FROM cons WHERE sadr = '%s'" % (sadr))
		rowv = rows.fetchone()
		if (rowv):
			outp = make(rowv[2].strip())
			if (mesg):
				stdo("info cached [%s] %s" % (secs, rowv, ))
			curs.execute("UPDATE cons SET secs = '%s' WHERE sadr = '%s'" % (secs, sadr))
			cmdc[1].commit() ; curs.close()
			return outp
	except Exception as e:
		stdo("erro comd sql [%s] %s" % (addr, e, ))
	try:
		cmdl = [path, addr[0], str(addr[1]), prot]
		subp = subprocess.check_output(cmdl, shell=False, text=True)
		outp = make(subp.strip())
		curs.execute("INSERT INTO cons VALUES (%s, '%s', '%s')" % (secs, sadr, subp.strip()))
	except Exception as e:
		stdo("erro comd [%s] %s" % (addr, e, ))
	cmdc[1].commit() ; curs.close()
	return outp
