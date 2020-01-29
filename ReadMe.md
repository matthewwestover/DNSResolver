## DNS Resolver
This was a simple DNS Resolver project created in my Masters of Software Development program. It was created for CS6014 - Network Systems and Security.

Run main() from DNSServer.java
From commandline you can run ```dig URL @127.0.0.1 -p8053```

DNSServer keeps a cache of recent DNSRecords. If a DNSQuestion does not have a matching record in the cache, DNSServer forwards the request to Google (8.8.8.8). When Google responds, it adds its response to the cache and sends the answer back to the requestor. Any record that has passed its time to live is removed from the cache. 

![Demo](https://github.com/matthewwestover/DNSResolver/blob/master/ExampleOutput.png?raw=true)