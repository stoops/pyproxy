
import ctypes, random, string

SEPR = "\n"

class ArcfCiph:
	def __init__(self, skey):
		self.s = {}
		self.m = 256
		self.k = skey.encode()
		self.h = (string.digits + string.ascii_uppercase + string.ascii_lowercase)
		self.c_f = ctypes.cdll.LoadLibrary("/etc/c.so")
	def sksa(self, prot, keys, init, rnds=1024):
		self.v = str(init).encode()
		(n, l) = (len(self.v), len(self.k))
		for d in keys:
			self.s[d] = [ctypes.c_int(0), ctypes.c_int(0), ctypes.c_int(0), bytearray(range(0, self.m)), ctypes.c_char * self.m]
		if ((n < 1) or (l < 1)):
			raise Exception("sksa [%d:%d]" % (n, l))
		if ((prot != "tcp") and (rnds == 1024)):
			return None
		p_v = bytearray(self.v)
		p_k = bytearray(self.k)
		c_v = (ctypes.c_char * n)
		c_k = (ctypes.c_char * l)
		for d in keys:
			p_s = self.s[d][3]
			c_s = self.s[d][4]
			self.c_f.keys(c_s.from_buffer(p_s), rnds, c_v.from_buffer(p_v), n, c_k.from_buffer(p_k), l)
	def prga(self, prot, mode, keys, data):
		if (prot != "tcp"):
			if (mode == "e"):
				init = ("".join([random.choice(self.h) for x in range(0, 11)]) + "/" + str(len(data)))
			else:
				info = data.split(SEPR.encode(), 2)
				try:
					(init, sums, data) = (info[0].decode(), int(info[1]), info[2])
				except:
					raise Exception("prga split")
			self.sksa(prot, [keys], init, rnds=256)
		(m, r, l) = (self.m, self.s[keys], len(data))
		(c_i, c_j, c_c, p_s, c_s) = (r[0], r[1], r[2], r[3], r[4])
		if (l < 1):
			raise Exception("prga [%d]" % (l))
		p_d = bytearray(data)
		p_o = bytearray(l)
		c_d = (ctypes.c_char * l)
		c_o = (ctypes.c_char * l)
		self.c_f.ciph(c_o.from_buffer(p_o), c_d.from_buffer(p_d), l, ctypes.pointer(c_i), ctypes.pointer(c_j), ctypes.pointer(c_c), c_s.from_buffer(p_s), ord(mode[0]))
		o = bytes(p_o)
		if (prot != "tcp"):
			c_u = ctypes.c_uint(0)
			self.c_f.sums(ctypes.pointer(c_u), c_s.from_buffer(p_s), c_i.value, c_j.value, c_c.value)
			if (mode == "e"):
				o = (init.encode() + SEPR.encode() + str(c_u.value).encode() + SEPR.encode() + o)
			else:
				if (sums != c_u.value):
					raise Exception("prga sums [%d] != [%d] {%s:%d}" % (sums, c_u.value, init, l, ))
		return o
