#!/usr/bin/python
# Copyright 2012-2014 Luke Dashjr
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the standard MIT license.  See COPYING for more details.

from blkmaker import _dblsha256
import blktemplate
import json
import struct
import sys

# This test_input data is released under the terms of the Creative Commons "CC0 1.0 Universal" license and/or copyright waiver.
test_input = '''
{
	"result": {
		"previousblockhash": "000000004d424dec1c660a68456b8271d09628a80cc62583e5904f5894a2483c",
		"target": "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"noncerange": "00000000ffffffff",
		"transactions": [],
		"sigoplimit": 20000,
		"expires": 120,
		"longpoll": "/LP",
		"height": 23957,
		"coinbasetxn": {
			"data": "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1302955d0f00456c6967697573005047dc66085fffffffff02fff1052a010000001976a9144ebeb1cd26d6227635828d60d3e0ed7d0da248fb88ac01000000000000001976a9147c866aee1fa2f3b3d5effad576df3dbf1f07475588ac00000000"
		},
		"version": 2,
		"curtime": 1346886758,
		"mutable": ["coinbase/append"],
		"sizelimit": 1000000,
		"bits": "ffff001d"
	},
	"id": 0,
	"error": null
}
'''

def send_json(req):
	print(json.dumps(req, indent=4))

tmpl = blktemplate.Template()
req = tmpl.request()

# send req to server and parse response into req
send_json(req)
if (len(sys.argv) == 2):
	req = json.load(sys.stdin)
else:
	req = json.loads(test_input)
	send_json(req)

try:
	# Bypass Python 3 idiocy
	range = xrange
except:
	pass

tmpl.add(req)
while (tmpl.time_left() and tmpl.work_left()):
	(data, dataid) = tmpl.get_data()
	assert(len(data) >= 76)
	
	# mine the right nonce
	for nonce in range(0x7fffffff):
		data = data[:76] + struct.pack('!I', nonce)
		blkhash = _dblsha256(data)
		if blkhash[28:] == b'\0\0\0\0':
			break
		if (not (nonce % 0x1000)):
			sys.stdout.write("0x%8x hashes done...\r" % nonce)
			sys.stdout.flush()
	print("Found nonce: 0x%8x \n" % nonce)
	
	req = tmpl.submit(data, dataid, nonce)
	# send req to server
	send_json(req)
