import socket
import sys

serverPort = 10070

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print('{0} [BindIP] [Server IP] [Message]'.format(sys.argv[0]))
        sys.exit()

    bindIP = sys.argv[1]
    serverIP = sys.argv[2]
    message = sys.argv[3]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((bindIP, 0))

    try:
        sock.connect((serverIP, serverPort))

        buffer = bytes(message, encoding='utf-8')
        sock.send(buffer)
        print('Sended message : {0}'.format(message))

        buffer = sock.recv(1024)
        received_message = str(buffer, encoding='utf-8')
        print('Received message : {0}'.format(received_message))

    finally:
        sock.close()
