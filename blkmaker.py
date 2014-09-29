# Copyright 2012-2014 Luke Dashjr
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the standard MIT license.  See COPYING for more details.

import base58 as _base58
from binascii import b2a_hex as _b2a_hex
from hashlib import sha256 as _sha256
from struct import pack as _pack
from time import time as _time

from blktemplate import _Transaction

MAX_BLOCK_VERSION = 2

def _dblsha256(data):
	return _sha256(_sha256(data).digest()).digest()

def init_generation2(tmpl, script):
	if not tmpl.cbtxn is None:
		return (0, False)
	
	if len(script) >= 0xfd:
		return (0, True)
	
	sh = b''
	h = tmpl.height
	while h > 127:
		sh += _pack('<B', h & 0xff)
		h >>= 8
	sh += _pack('<B', h)
	sh = _pack('<B', len(sh)) + sh
	
	data = b''
	data += b"\x01\0\0\0"  # txn ver
	data += b"\x01"        # input count
	data +=   b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"  # prevout
	data +=   b"\xff\xff\xff\xff"   # index (-1)
	data +=   _pack('<B', len(sh))  # scriptSig length
	data +=   sh
	data +=   b"\xff\xff\xff\xff"   # sequence
	data += b"\x01"        # output count
	data +=   _pack('<Q', tmpl.cbvalue)
	data +=   _pack('<B', len(script))
	data +=   script
	data += b'\0\0\0\0'  # lock time
	
	txn = _Transaction(None)
	
	txn.data = data
	
	tmpl.cbtxn = txn
	
	tmpl.mutations.add('coinbase/append')
	tmpl.mutations.add('coinbase')
	tmpl.mutations.add('generate')
	
	return (tmpl.cbvalue, True)

def init_generation(tmpl, script):
	return init_generation2(tmpl, script)[0]

def _build_merkle_root(tmpl, coinbase):
	txnlist = [coinbase] + [t.data for t in tmpl.txns]
	merklehashes = [_dblsha256(t) for t in txnlist]
	while len(merklehashes) > 1:
		if len(merklehashes) % 2:
			merklehashes.append(merklehashes[-1])
		merklehashes = [_dblsha256(merklehashes[i] + merklehashes[i + 1]) for i in range(0, len(merklehashes), 2)]
	return merklehashes[0]

_cbScriptSigLen = 4 + 1 + 36
sizeof_workid = 8

def _append_cb(tmpl, append):
	coinbase = tmpl.cbtxn.data
	# The following can be done better in both Python 2 and Python 3, but this way works with both
	origLen = ord(coinbase[_cbScriptSigLen:_cbScriptSigLen+1])
	appendsz = len(append)
	
	if origLen > 100 - appendsz:
		return None
	
	cbExtraNonce = _cbScriptSigLen + 1 + origLen
	
	newLen = origLen + appendsz
	coinbase = coinbase[:_cbScriptSigLen] + chr(newLen).encode('ascii') + coinbase[_cbScriptSigLen+1:cbExtraNonce] + append + coinbase[cbExtraNonce:]
	
	return coinbase

def append_coinbase_safe(tmpl, append):
	if 'coinbase/append' not in tmpl.mutations and 'coinbase' not in tmpl.mutations:
		raise RuntimeError('Coinbase appending not allowed by template')
	
	datasz = len(tmpl.cbtxn.data)
	availsz = 100 - sizeof_workid - ord(tmpl.cbtxn.data[_cbScriptSigLen:_cbScriptSigLen+1])
	if len(append) > availsz:
		return availsz
	
	newcb = _append_cb(tmpl, append)
	if newcb is None:
		raise RuntimeError('Append failed')
	
	return availsz

def _extranonce(tmpl, workid):
	coinbase = tmpl.cbtxn.data
	if not workid:
		return coinbase
	extradata = _pack('<Q', workid)
	coinbase = _append_cb(tmpl, extradata)
	return coinbase

def get_data(tmpl, usetime = None, out_expire = None):
	if usetime is None: usetime = _time()
	if (not (time_left(tmpl, usetime) and work_left(tmpl))):
		return (None, None)
	
	cbuf = _pack('<I', tmpl.version)
	cbuf += tmpl.prevblk
	
	dataid = tmpl.next_dataid
	tmpl.next_dataid += 1
	cbtxndata = _extranonce(tmpl, dataid)
	if (not cbtxndata):
		return (None, None)
	merkleroot = _build_merkle_root(tmpl, cbtxndata)
	if (not merkleroot):
		return (None, None)
	cbuf += merkleroot
	
	time_passed = int(usetime - tmpl._time_rcvd)
	timehdr = tmpl.curtime + time_passed
	if (timehdr > tmpl.maxtime):
		timehdr = tmpl.maxtime
	
	cbuf += _pack('<I', timehdr)
	cbuf += tmpl.diffbits
	if not out_expire is None:
		out_expire[0] = tmpl.expires - time_passed - 1
	
	return (cbuf, dataid)

def time_left(tmpl, nowtime = None):
	if nowtime is None: nowtime = _time()
	age = (nowtime - tmpl._time_rcvd)
	if age >= tmpl.expires:
		return 0
	return tmpl.expires - age

def work_left(tmpl):
	if not tmpl.version:
		return 0
	if 'coinbase/append' not in tmpl.mutations and 'coinbase' not in tmpl.mutations:
		return 1
	return 0xffffffffffffffff - tmpl.next_dataid

def _varintEncode(n):
	if n < 0xfd:
		return _pack('<B', n)
	# NOTE: Technically, there are more encodings for numbers bigger than
	# 16-bit, but transaction counts can't be that high with version 2 Bitcoin
	# blocks
	return b'\xfd' + _pack('<H', n)

def submit(tmpl, data, dataid, nonce, foreign=False):
	data = data[:76]
	data += _pack('!I', nonce)
	
	if foreign or ('submit/truncate' not in tmpl.mutations or dataid):
		data += _varintEncode(1 + len(tmpl.txns))
		
		data += _extranonce(tmpl, dataid)
		
		if foreign or ('submit/coinbase' not in tmpl.mutations):
			for i in range(len(tmpl.txns)):
				data += tmpl.txns[i].data
	
	info = {}
	if (not getattr(tmpl, 'workid', None) is None) and not foreign:
		info['workid'] = tmpl.workid
	
	return {
		'id': 0,
		'method': 'submitblock',
		'params': [
			_b2a_hex(data).decode('ascii'),
			info
		]
	}

def submit_foreign(tmpl, data, dataid, nonce):
	return submit(tmpl, data, dataid, nonce, True)

def address_to_script(addr):
	addrbin = _base58.b58decode(addr, 25)
	if addrbin is None:
		raise RuntimeError('Invalid address')
	addrver = _base58.get_bcaddress_version(addr)
	if addrver == 0 or addrver == 111:
		# Bitcoin pubkey hash or Testnet pubkey hash
		return b''
		+ b'\x76'  # OP_DUP
		+ b'\xa9'  # OP_HASH160
		+ b'\x14'  # push 20 bytes
		+ addrbin
		+ b'\x88'  # OP_EQUALVERIFY
		+ b'\xac'  # OP_CHECKSIG
	if addrver == 5 or addrver == 196:
		# Bitcoin script hash or Testnet script hash
		return b''
		+ b'\xa9'  # OP_HASH160
		+ b'\x14'  # push 20 bytes
		+ addrbin
		+ b'\x87'  # OP_EQUAL
	raise RuntimeError('Invalid address version')
