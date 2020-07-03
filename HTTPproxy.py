import socket
import sys
import thread
import hashlib
import requests
import re
from urlparse import urlparse, parse_qs


headerregex = r'.{3,}: .{3,}'
httpregex = r'(?i)HTTP/[0-2].[0-9]'


#Thread function for starting a new connection.
def new_connection(conid, caddr, apikey):
	
	url = 'https://www.virustotal.com/vtapi/v2/file/report'

	#Receive Data from Client loop
	while 1:
		#LEFT SMALL, only accepting 1024 bytes because we ONLY will look at get requests. everything else gets error response
		data = conid.recv(1024)
		if not data:
			break
		
		reqf = data.split("\r\n") 
		fields = reqf[0].split(" ")	

		if len(fields) < 3:
			response = 'HTTP/1.0 400 Bad Request'		
			conid.sendall(response)
			continue

		
		if fields[0] == 'GET' and re.match(httpregex, fields[2]) is not None:
		

			urlp = urlparse(fields[1])
			#print 'URL stuff:', urlp		

			urip = urlp.path

	
			hostp = urlp.netloc
	

			if urip == '':
				urip = '/'
			
			#Set up Host Port
			if urlp.port == '' or urlp.port is None:
				hostport = int(80)
			else:
				hostp = urlp.netloc
				tidx = hostp.find(':')
				porttest = hostp[tidx+1:]
				hostp = hostp[:tidx]			
				hostport = int(porttest)
				
			sendstring = 'GET ' + urip  +  ' HTTP/1.0\r\n'		
			sendstring = sendstring + 'Host: ' + hostp + '\r\n'


			#Set up and send client headers.
			for i in range(1, len(reqf)):
				if re.match(headerregex, reqf[i]) is not None:
					sendstring = sendstring + reqf[i] + '\r\n'
				else:
					continue

			sendstring = sendstring + 'Connection: close\r\n\r\n'
			newhost = hostp
			serversock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			
			rawdata = []
		
			#Try to connect to the server with the client information.	
			try:
				serversock.settimeout(5)
				serversock.connect((newhost, hostport))
				serversock.sendall(sendstring)


				
				#Loop to make sure we get ALL data back from server
				while True:
					tempdata  = serversock.recv(2048)
					
					if not tempdata:
						break
					rawdata.append(tempdata)
					
				response = b''.join(rawdata)
				respcopy = response

				
				#parse response now so we can send the objects md5 to virustotal
				idxnl = response.find('\r\n\r\n')
				fileobject = response[idxnl+4:]


				params = {'apikey': apikey, 'resource': hashlib.md5(fileobject).hexdigest(), 'allinfo':True} 				

				vtresponse = requests.get(url, params=params)


					
				if vtresponse.status_code == 0 or vtresponse.status_code == 200:
					print "GOOD RESPONSE FROM VT..."
					jsonres = vtresponse.json()	
					#print "RESPONSE:", jsonres				
					
					if 'positives' in jsonres:
						#print jsonres['positives']
						if jsonres['positives'] > 0:
							print "VIRUS POSITIVES:", jsonres['positives']
							
							htmlresponse = '<html>\n<head>\n<title>ERROR</title>\n</head>\n<body>\n<h1>CONTENT BLOCKED</h1>\n<p>The requested file is suspected malware and has been blocked.</p>\n</body>\n</html>'

							#Set up HTML page response
							response = 'HTTP/1.0 200 OK\r\nContent-type: text/html\r\nContent-Length: ' + str(len(htmlresponse)) + '\r\n\r\n' + htmlresponse 
							
						else:
							#Send the file/object on through with an OK status. 
							response = respcopy 
					

				elif vtresponse.status_code == 204:
					print "TOO MANY REQUESTS TO VT...."
					response = 'HTTP/1.0 500 Request Limit\r\nDescription:Too many virus Total Requests\r\n'


				elif vtresponse.status_code == 400:
					print "BAD REQUEST... ARGS/VALS?"
					response = 'HTTP/1.0 500 Server Error\r\nDescription:Virus Total Request Error\r\n'



				elif vtresponse.status_code == 403:
					print "BAD REQUEST, FORBIDDEN. CHECK APIKEY"				
					response = 'HTTP/1.0 500 API Error\r\nDescription:Bad API key given.\r\n'
				








	
			except socket.timeout:
				response = 'HTTP/1.0 400 Bad Request\r\nDescription:Timeout occurred, check address.\r\n'
			except Exception as e:
				response = 'HTTP/1.0 400 Bad Request\r\nDescription:Bad URL or Port could not connect\r\n'
			finally:	
				serversock.close()
				

		elif fields[0] == 'POST':
			response = 'HTTP/1.0 501 Not Implemented\r\n'
		elif fields[0] == 'PUT':
			response = 'HTTP/1.0 501 Not Implemented\r\n'
		elif fields[0] == 'DELETE':
			response = 'HTTP/1.0 501 Not Implemented\r\n'
		elif fields[0] == 'TRACE':
			response = 'HTTP/1.0 501 Not Implemented\r\n'
		elif fields[0] == 'CONNECT':
			response = 'HTTP/1.0 501 Not Implemented\r\n'
		else:
			response = 'HTTP/1.0 400 Bad Request\r\n'
		conid.sendall(response)
		#break
	conid.close()






for txt in sys.argv:
	if txt == '-h' or txt == '--help' or txt == '-H' or txt == '-Help' or txt == '--Help':
		print 'To use the proxy server with default values, run python2 HTTPproxy.py ... To specify what port and an API key, add a space and then the port number, then add a space and the API key for virus total.(IE: python2 HTTPproxy.py <PORT> <API KEY>)... To just use default port but a new API key, run python2 HTTPproxy.py <API KEY>...'
		quit()


#Check if port number was given otherwise default to 50007
if len(sys.argv) == 3:
	#Get Port to Listen On, then get API Key
	PORT = int(sys.argv[1])
	APIKEY = sys.argv[2] 
elif len(sys.argv) == 2:
	APIKEY = sys.argv[1]
else:
	#Default Port
	PORT = 50007
	APIKEY = "df3025ef1a333d30139307a0bd53adc8846ad24bbddb841a12ab71e808ec8c28"
HOST = ''

#Set up socket and listen for connections.
sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sck.bind((HOST,PORT))
sck.listen(4)

#Loop to accept new connections and then start a thread for them.
while 1:
	
	conn, addr = sck.accept()

	thread.start_new_thread(new_connection,(conn,addr,APIKEY))
	
sck.close()	





