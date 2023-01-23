from http.server import BaseHTTPRequestHandler, HTTPServer
import time
import json
import sys
import argparse
import os, fileinput



parser = argparse.ArgumentParser(description='Start a DNS implemented in Python.')
parser.add_argument('--port', default=5053, type=int, help='The port to listen on.')
parser.add_argument('--record', type=str, help='Record address.')
parser.add_argument('--dir', type=str, help='ACME Directory.')
parser.add_argument('--domain', nargs='+')

args = parser.parse_args()

domain_names=args.domain
hostName=domain_names[0]
serverPort=5002


embed_text=""


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
        self.data_string = self.rfile.read(int(self.headers['Content-Length']))
        post_data = json.loads(json.loads(self.data_string))
        if post_data['password']=="post-pw":
            embed_text=post_data['post-value']


if __name__ == "__main__":        
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started http://%s:%s" % (hostName, serverPort))
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
        
webServer.server_close()
print("Server stopped.")