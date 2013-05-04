from binascii import b2a_hex as _b2a_hex
from hashlib import sha256 as _sha256
from struct import pack as _pack
from time import time as _time

MAX_BLOCK_VERSION = 2

def _dblsha256(data):
	return _sha256(_sha256(data).digest()).digest()

def _build_merkle_root(tmpl, coinbase):
	txnlist = [coinbase] + list(tmpl.txns)
	merklehashes = [_dblsha256(t) for t in txnlist]
	while len(merklehashes) > 1:
		if len(merklehashes) % 2:
			merklehashes.append(merklehashes[-1])
		merklehashes = [_dblsha256(merklehashes[i] + merklehashes[i + 1]) for i in range(0, len(merklehashes), 2)]
	return merklehashes[0]

_cbScriptSigLen = 4 + 1 + 36

def _extranonce(tmpl, workid):
	coinbase = tmpl.cbtxn.data
	if not workid:
		return coinbase
	extradata = _pack('<Q', workid)
	# The following can be done better in both Python 2 and Python 3, but this way works with both
	origLen = ord(coinbase[41:42])
	newLen = origLen + len(extradata)
	coinbase = coinbase[0:41] + chr(newLen).encode('ascii') + coinbase[42:42 + origLen] + extradata + coinbase[42 + origLen:]
	return coinbase

def get_data(tmpl, usetime = _time()):
	if (not (time_left(tmpl, usetime) and work_left(tmpl))):
		return
	
	cbuf = _pack('<I', tmpl.version)
	cbuf += tmpl.prevblk
	
	dataid = tmpl.next_dataid
	tmpl.next_dataid += 1
	cbtxndata = _extranonce(tmpl, dataid)
	if (not cbtxndata):
		return 0
	merkleroot = _build_merkle_root(tmpl, cbtxndata)
	if (not merkleroot):
		return 0
	cbuf += merkleroot
	
	timehdr = tmpl.curtime + int(usetime - tmpl._time_rcvd)
	if (timehdr > tmpl.maxtime):
		timehdr = tmpl.maxtime
	
	cbuf += _pack('<I', timehdr)
	cbuf += tmpl.diffbits
	
	return (cbuf, dataid)

def time_left(tmpl, nowtime = _time()):
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

def submit(tmpl, data, dataid, nonce):
	data = data[:76]
	data += _pack('!I', nonce)
	
	if 'submit/truncate' not in tmpl.mutations and dataid:
		data += _varintEncode(1 + len(tmpl.txns))
		
		data += _extranonce(tmpl, dataid)
		
		if 'submit/coinbase' not in tmpl.mutations:
			for i in range(len(tmpl.txns)):
				data += tmpl.txns[i]
	
	return {
		'id': 0,
		'method': 'submitblock',
		'params': [
			_b2a_hex(data).decode('ascii'),
			{}
		]
	}
