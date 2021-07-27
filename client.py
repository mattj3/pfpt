import socket

clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#host = input("")
host = socket.gethostname()

port = 444

clientSocket.connect((host, port))

# amount of data to receive 
message = clientSocket.recv(1024)

clientSocket.close()

print(message.decode('ascii'))
