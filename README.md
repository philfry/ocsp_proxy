# ocsp_proxy
a caching ocsp proxy

## why?
If your servers are configured to do ocsp stapling, the server checks whether or not it has a valid (aka: signed) ocsp response for the requested certificate and, if so, attaches that ocsp-response to its certificate on each client request.

That ocsp response can be and usually is cached by the server. Unfortunately, some server's caching mechanisms aren't meant to survive a server reboot, not even a service restart, and it happens that the server asks for a fresh ocsp response when the cached ocsp response has expired.
If, in this situation, the ocsp responder is down (*hi, letsencrypt*), bad things happen. Worst case: the website is no longer reachable.

Now `ocsp-proxy` sits between the ocsp requestor and the ocsp responder, caching both the request and the response in a redis db.

## how?
`ocsp-proxy` is a simple perl-driven http server which accepts ocsp requests, which usually are something like:
```
POST / HTTP/1.1
Host: ocsp.yourcahere.example:80
Content-Type: application/ocsp-request
Content-Length: 123

$asn1encodedocsprequest
```
and forwards them to the corresponding servers, storing the ocsp response in the database and passing it to the client.
Once in a while (i.e. every 30mins) `ocsp-proxy` checks its cache for freshness. It re-requests the ocsp responses from the ocsp responders every day and, if we're past the validity's half time, every hour.
This way we (should) always have a fresh ocsp response in our cache. Yay.

## usage
install all dependent perl modules, install redis, take a look at `perldoc ./ocsp-proxy.pl` and have fun.
To make `apache httpd` use the proxy, add this to your ssl config:
```
SSLOCSPProxyURL http://127.0.0.1:8888/
```

## caveat
ocsp responses with NONCEs are, for obvious reasons, not cached.

## known bugs
`ocsp-proxy` cannot handle multiple ocsp requests per client request (`requestList`).
