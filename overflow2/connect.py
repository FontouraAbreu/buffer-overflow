## I have a service running in a  random port an Id like to connect to it via a tcp socket

import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# id like de port to be the first argument of the program

port = int(sys.argv[1])
command = sys.argv[2]
s.connect(("localhost", port))
s.send(bytes(command, "utf-8"))
data = s.recv(1024)
print("Received")
print(repr(data))
