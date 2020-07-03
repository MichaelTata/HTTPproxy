# HTTPproxy
Basic HTTP proxy server in python. 
Defaulted to listen on port 50007, but a port can be provided as an argument, as can a VirusTotal API key.

Example Usage:

```
python2 HTTPproxy.py <PORT> <API KEY>

```

Data returned from the get request will be turned into an MD5 Hash, which is then sent to the VirusTotal API.
If their database recognizes the hash as malware, it will be filtered out and the user will be notified.
