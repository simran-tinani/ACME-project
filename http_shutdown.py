from http.server import BaseHTTPRequestHandler, HTTPServer
import time
import json
import sys
import argparse
import os, fileinput


serverPort=5001
hostName="shutdown.com"


class MyServer(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/jose+json') #text/html #application/octet-stream
        self.end_headers()
    def do_GET(self):
        sys.exit()
    def do_POST(self):
        sys.exit()


if __name__ == "__main__":        
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started http://%s:%s" % (hostName, serverPort))
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass
        
webServer.server_close()
print("Server stopped.")