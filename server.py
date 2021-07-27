# sockets init connections and allow sending and reciving of data 
# internal endpoint for sending and receiving data

import socket

# AF_INET used to specifiy protocol (IPV4, IPV6)
# Using IPV4
# SOCK_STREAM -> TCP (connection bases protocol)
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#host = '192.168.1.?'
#???
host = socket.gethostname()

# port = input("")
port = 444

# bind values 
serverSocket.bind((host, port))

# TCP listener 
# Can specifiy number of connections
serverSocket.listen(3)

while True:
    #establish connection 
    clientSocket, address = serverSocket.accept()

    # Notify server about connection
    # % used for data type conversion
    print("Received connection from " % str(address))

    #create message 
    message = "Thank you for connecting to the server." + '\n'

    #send message
    clientSocket.send(message.encode('ascii'))

    #close socket 
    clientSocket.close()