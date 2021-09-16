from http.server import HTTPServer, BaseHTTPRequestHandler

recived_requests = []

class RequestHandler(BaseHTTPRequestHandler):
    
    def do_GET(self):
        request_path = self.path
        id = request_path.split("#")[1]
        recived_requests.append(id)
        print("Recived packet with ID ", id)
        with open('http_server.log', 'a') as fout:
            fout.write(id + '\n')
        self.send_response(200)
        
def main():
    port = 8080
    print('Listening on localhost:%s' % port)
    server = HTTPServer(('', port), RequestHandler)
    server.serve_forever()

        
if __name__ == "__main__":
    main()
