# Copyright 2012-2016 Luke Dashjr
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the standard MIT license.  See COPYING for more details.

from binascii import a2b_hex as __a2b_hex
from . import blkmaker as _blkmaker
from time import time as _time

try:
	__a2b_hex('aa')
	_a2b_hex = __a2b_hex
except TypeError:
	def _a2b_hex(a):
		return __a2b_hex(a.encode('ascii'))

def request(jcaps, lpid = None):
	params = {
		'capabilities': jcaps,
		'maxversion': _blkmaker.MAX_BLOCK_VERSION,
	}
	if lpid:
		params['longpollid'] = lpid
	req = {
		'id':0,
		'method': 'getblocktemplate',
		'params': [params],
	}
	return req

class _Transaction:
	def __init__(self, txnj = {}):
		if txnj is None:
			return
		if 'data' not in txnj:
			raise ValueError("Missing or invalid type for transaction data")
		self.data = _a2b_hex(txnj['data'])

class _LPInfo:
	pass

class Template:
	def __init__(self):
		self.auxs = {}
		self.sigoplimit = 0xffff
		self.sizelimit = 0xffffffff
		self.maxtime = 0xffffffff
		self.maxtimeoff = 0x7fff
		self.mintime = 0
		self.mintimeoff = -0x7fff
		self.maxnonce = 0xffffffff
		self.expires = 0x7fff
		self.cbtxn = None
		self.next_dataid = 0
		self.version = None
	
	def addcaps(self):
		# TODO: make this a lot more flexible for merging
		# For now, it's a simple "filled" vs "not filled"
		if self.version:
			return 0
		return ('coinbasetxn', 'workid', 'time/increment', 'coinbase/append', 'version/force', 'version/reduce', 'submit/coinbase', 'submit/truncate')
	
	def get_longpoll(self):
		return self.lp
	
	def get_submitold(self):
		return self.submitold
	
	# Wrappers around blkmaker, for OO friendliness
	def init_generation3(self, script, override_cb=False):
		return _blkmaker.init_generation3(self, script, override_cb)
	def init_generation2(self, script, override_cb=False):
		return _blkmaker.init_generation2(self, script, override_cb)
	def init_generation(self, script, override_cb=False):
		return _blkmaker.init_generation(self, script, override_cb)
	def append_coinbase_safe2(self, append, extranoncesz = 0, merkle_only = False):
		return _blkmaker.append_coinbase_safe2(self, append, extranoncesz, merkle_only)
	def append_coinbase_safe(self, append, extranoncesz = 0, merkle_only = False):
		return _blkmaker.append_coinbase_safe(self, append, extranoncesz, merkle_only)
	def get_data(self, usetime = None):
		return _blkmaker.get_data(self, usetime)
	def get_mdata(self, usetime = None, out_expire = None, extranoncesz = _blkmaker.sizeof_workid):
		return _blkmaker.get_mdata(self, usetime, out_expire, extranoncesz)
	def time_left(self, nowtime = None):
		return _blkmaker.time_left(self, nowtime)
	def work_left(self):
		return _blkmaker.work_left(self)
	def propose(self, caps, foreign):
		return _blkmaker.propose(self, caps, foreign)
	def submit(self, data, dataid, nonce, multiplier, foreign=False):
		return _blkmaker.submit(self, data, dataid, nonce, multiplier, foreign)
	def submit_foreign(self, data, dataid, nonce, multiplier):
		return _blkmaker.submit_foreign(self, data, dataid, nonce, multiplier)
	
	# JSON-specific stuff
	def request(self, lpid = None):
		return request(self.addcaps(), lpid)
	
	def add(self, json, time_rcvd = None):
		if time_rcvd is None: time_rcvd = _time()
		if self.version:
			raise ValueError("Template already populated (combining not supported)")
		
		if 'result' in json:
			if json.get('error', None):
				raise ValueError('JSON result is error')
			json = json['result']
		
		self.diffbits = _a2b_hex(json['bits'])[::-1]
		self.curtime = json['curtime']
		self.height = json['height']
		self.prevblk = _a2b_hex(json['previousblockhash'])[::-1]
		self.sigoplimit = json.get('sigoplimit', self.sigoplimit)
		self.sizelimit = json.get('sizelimit', self.sizelimit)
		self.version = json['version']
		
		self.cbvalue = json.get('coinbasevalue', None)
		self.workid = json.get('workid', None)
		
		self.expires = json.get('expires', self.expires)
		self.maxtime = json.get('maxtime', self.maxtime)
		self.maxtimeoff = json.get('maxtimeoff', self.maxtimeoff)
		self.mintime = json.get('mintime', self.mintime)
		self.mintimeoff = json.get('mintimeoff', self.mintimeoff)
		
		self.lp = _LPInfo()
		if 'longpollid' in json:
			self.lp.lpid = json['longpollid']
			self.lp.uri = json.get('longpolluri', None)
		self.submitold = json.get('submitold', True)
		
		self.txns = []
		self.txns_datasz = 0
		for t in json['transactions']:
			tobj = _Transaction(t)
			self.txns.append(tobj)
			self.txns_datasz += len(tobj.data)
		
		if 'coinbasetxn' in json:
			self.cbtxn = _Transaction(json['coinbasetxn'])
		
		if 'coinbaseaux' in json:
			for aux in json['coinbaseaux']:
				self.auxs[aux] = _a2b_hex(json['coinbaseaux'][aux])
		
		if 'target' in json:
			self.target = _a2b_hex(json['target'])
		
		self.mutations = set(json.get('mutable', ()))
		
		if (self.version > _blkmaker.MAX_BLOCK_VERSION or (self.version >= 2 and not self.height)):
			if 'version/reduce' in self.mutations:
				self.version = _blkmaker.MAX_BLOCK_VERSION if self.height else 1
			elif 'version/force' not in self.mutations:
				raise ValueError("Unrecognized block version, and not allowed to reduce or force it")
		
		self._time_rcvd = time_rcvd;
		
		return True
