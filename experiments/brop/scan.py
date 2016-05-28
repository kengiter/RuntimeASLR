#!/usr/bin/python

import socket
import string
import threading

_f = None
_lock = threading.Lock()

def scan_host(ip):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

	try:
		s.settimeout(5)

		s.connect((ip, 80))
		s.send("HEAD / HTTP/1.0\n\n")
		data = s.recv(4096)
		s.close()

		x = string.find(data, "Server: ")
		if x == -1:
			return

		data = data[(x + 8):]

		x = string.find(data, "\r")
		if x != -1:
			data = data[0:x]

		found_banner(ip, data)
	except:
		s.close()

def found_banner(ip, data):
	global _lock

	with _lock:
		print("%s %s" % (ip, data))


def scanner():
	while True:
		ip = get_ip()
		if ip == None:
			break

		scan_host(ip)

def get_ip():
	global _f, _lock

	with _lock:
		ip = _f.readline()

	if ip == "":
		return None

	ip = ip[0:-1]

	return ip

def main():
	global _f

	_f = open("ips.txt")

	threadno = 5
	threads = []

	for i in range(threadno):
		t = threading.Thread(target=scanner)
		t.start()
		threads.append(t)

	for t in threads:
		t.join()

main()
