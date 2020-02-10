import socketserver
import sys

class TcpEchoServerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        print('Client is connected : {0}'.format(self.client_address[0]))
        sock = self.request

        buffer = sock.recv(1024)
        received_message = str(buffer, encoding='utf-8')
        print('Received : {0}'.format(received_message))
        sock.send(buffer)
        sock.close()

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('{0} [Bind IP]'.format(sys.argv[0]))
        sys.exit()

    bindIP = sys.argv[1]
    bindPort = 10070

    server = socketserver.TCPServer((bindIP, bindPort), TcpEchoServerHandler)

    print("Start Echo-Server")
    server.serve_forever()
