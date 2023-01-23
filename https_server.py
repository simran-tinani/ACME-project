from http.server import BaseHTTPRequestHandler, HTTPServer
import time
import json
import sys
import argparse
import os, fileinput
import ssl

parser = argparse.ArgumentParser(description='Start a DNS implemented in Python.')
parser.add_argument('--domain', nargs='+')

args = parser.parse_args()

serverPort=5001
domain_names=args.domain
hostName=domain_names[0]

embed_text=""

with open('final-certificate.pem','r') as fh:
    embed_text=fh.read()

class MyServer(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/jose+json') #text/html #application/octet-stream
        self.end_headers()
    def do_GET(self):
        global embed_text
        self.send_response(200)
        self.send_header('Content-type', 'text/octet-stream') #text/html #application/octet-stream
        self.end_headers()
        self.wfile.write(bytes(embed_text, "utf-8"))
    def do_POST(self):
        global embed_text
        self.send_response(200)
        self.send_header('Content-type', 'application/jose+json') #text/html #application/octet-stream
        self.end_headers()
        self.wfile.write(bytes(embed_text, "utf-8"))


if __name__ == "__main__":        
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started http://%s:%s" % (hostName, serverPort))
    webServer.socket = ssl.wrap_socket (webServer.socket, 
        keyfile="domain_private_key.pem", 
        certfile='final-certificate.pem', server_side=True)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
        
webServer.server_close()
print("Server stopped.")

