#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# ocsp_proxy
# author, (c): Philippe Kueck <projects at unixadm dot org>

from time import time, mktime, sleep
import sys

from argparse import ArgumentParser

from http.server import HTTPServer, BaseHTTPRequestHandler
from http.client import HTTPConnection

import threading

from pyasn1.codec.der.decoder import decode as der_decoder
try: from pyasn1_modules import rfc6960
except ImportError: import rfc6960

from redis import Redis

__version__ = "0.5.0"

mutex = threading.Lock()
redis_c = None


class OCSPRefresh(threading.Thread):
    def __init__(self, r_prefix):
        super().__init__()
        self._prefix = r_prefix

    def _get_intv(self, thisupd, nextupd):
        if thisupd + (nextupd-thisupd)/2 > time(): return 86400
        return 3600

    def refresh(self):
        with mutex:
            for k in redis_c.keys(self._prefix+"*"):
                cache_obj = redis_c.hgetall(k)
                i = self._get_intv(
                    int(cache_obj[b'thisupd']), int(cache_obj[b'nextupd'])
                )
                if int(cache_obj[b'lastchecked']) + i > time(): continue
                ocsp = OCSPProcessor(
                    cache_obj[b'ocsp_responder'],
                    cache_obj[b'request'],
                    self._prefix,
                    force_refresh=True
                )
                status, _, _ = ocsp.query()
                print("refreshed %s -> %d" % (k, status))

    def run(self):
        while True:
            self.refresh()
            sleep(1800)


class OCSPParserError(Exception):
    pass

class OCSPProcessor:
    def __init__(self, host, request, r_prefix, force_refresh=False):
        self.cached = False
        self.force_refresh = force_refresh
        self.host = host
        self.ocsp_req = request
        ocsp_req, null = der_decoder(
            request, asn1Spec=rfc6960.OCSPRequest()
        )
        try:
            assert null == b''
            assert int(ocsp_req['tbsRequest']['version']) == 0
        except AssertionError as e:
            raise OCSPParserError from e

        if len(ocsp_req['tbsRequest']['requestList']) > 1:
            return

        req = ocsp_req['tbsRequest']['requestList'][0]['reqCert']
        self.cache_key = ("%s%s0x%x" % (
            r_prefix, req['issuerKeyHash']._value.hex(),
            req['serialNumber']
        )).encode()

    def get_cache_status(self):
        return self.cached

    def get_cache_key(self):
        if hasattr(self, 'cache_key'): return self.cache_key.decode()
        return None

    def clear_cache_entry(self):
        if not hasattr(self, 'cache_key'): return
        redis_c.delete(self.cache_key)

    def _get_from_cache(self):
        if not hasattr(self, 'cache_key'): return None
        cached_response = redis_c.hgetall(self.cache_key)
        if not cached_response: return None
        try:
            if int(cached_response[b'nextupd']) <= time():
                return None
        except KeyError:
            redis_c.delete(self.cache_key)
            return None
        self.cached = True
        return cached_response[b'response']

    def _parse_ocsp_response(self, data):
        ocsp_res, null = der_decoder(
            data, asn1Spec=rfc6960.OCSPResponse()
        )
        assert null == b''

        ocsp_bdy, null = der_decoder(
            ocsp_res['responseBytes']['response'],
            asn1Spec=rfc6960.BasicOCSPResponse()
        )
        assert null == b''

        has_nonce = False
        for ext in ocsp_bdy['tbsResponseData']['responseExtensions']:
            if ext['extnID'] == '1.3.6.1.5.5.7.48.1.2':
                has_nonce = True
                break

        res = ocsp_bdy['tbsResponseData']['responses'][0]
        return {
            'resp_status': ocsp_res['responseStatus'],
            'has_nonce': has_nonce,
            'nextupd': int(mktime(res['nextUpdate'].asDateTime.timetuple())),
            'thisupd': int(mktime(res['thisUpdate'].asDateTime.timetuple())),
            'status': res['certStatus'].getName()
        }

    def query(self):
        with mutex:
            data = self._get_from_cache()
            if data:
                return 200, {
                    'content-type': 'application/ocsp-response',
                    'content-length': len(data)
                }, data

            conn = HTTPConnection(self.host)
            conn.request("POST", "", self.ocsp_req, headers={
                'content-type': 'application/ocsp-request',
                'content-length': len(self.ocsp_req)
            })
            res = conn.getresponse()
            data = res.read()
            conn.close()

            if res.status == 200:
                try: ocsp_data = self._parse_ocsp_response(data)
                except: return 503, None, None

                if (hasattr(self, 'cache_key') and
                        ocsp_data['resp_status'] == 0 and
                        not ocsp_data['has_nonce'] and
                        ocsp_data['status'] != "unknown"):
                    redis_c.hset(self.cache_key, mapping={
                        'status': ocsp_data['status'],
                        'thisupd': ocsp_data['thisupd'],
                        'nextupd': ocsp_data['nextupd'],
                        'lastchecked': int(time()),
                        'ocsp_responder': self.host,
                        'request': self.ocsp_req,
                        'response': data
                    })

        return res.status, dict(res.headers.items()), data


class OCSPProxy(BaseHTTPRequestHandler):

    def log_request(self, code='-', size='-'):
        cached = self.ocsp.get_cache_status()
        cache_key = self.ocsp.get_cache_key()
        print("%s %s (%s) -> %d" % ("%s:%d" % self.connection.getpeername(),
            cache_key, ("direct", "cached")[cached], code
            ), file=sys.stderr
        )

    def log_error(self, format, *args):
        return

    def do_HEAD(self):
        self.send_error(403)
        self.end_headers()

    def do_GET(self):
        self.send_error(403)
        self.end_headers()

    def do_POST(self):
        if self.headers.get("Host") is None:
            self.send_error(400, explain="'Host' missing")
            return

        if self.headers.get_content_type() != "application/ocsp-request":
            self.send_error(400, explain="'application/ocsp-request' required")
            return

        try: data = self.rfile.read(int(self.headers['Content-Length']))
        except KeyError:
            self.send_error(400)
            return

        try:
            self.ocsp = OCSPProcessor(
                self.headers.get("Host"), data, options.prefix
            )
        except OCSPParserError:
            self.send_error(400, explain="Cannot parse ocsp request")
            return
        except:
            self.send_error(503, explain="Unknown error")
            return

        if "X-prune-from-cache" in self.headers:
            self.ocsp.clear_cache_entry()
            self.send_error(410, explain="Cache cleared")
            return

        r_status, r_hdr, r_data = self.ocsp.query()

        self.send_response(r_status)
        for h in r_hdr: self.send_header(h, r_hdr[h])
        self.end_headers()
        self.wfile.write(r_data)


def run(server_class=HTTPServer, handler_class=OCSPProxy, addr="localhost", port=8888):
    global redis_c
    redis_c = Redis(unix_socket_path=options.socket)

    server_address = (addr, port)
    httpd = server_class(server_address, handler_class)

    try:
        refresher = OCSPRefresh(options.prefix)
        refresher.daemon = True
        refresher.start()
    except (KeyboardInterrupt, SystemExit):
        pass

    httpd.serve_forever()


if __name__ == "__main__":
    desc = "%(prog)s proxies ocsp requests and caches their responses."
    parser = ArgumentParser(description=desc)
    parser.add_argument(
        "-H", "--host", default="localhost",
        help="The ip address/hostname to listen on, defaults to localhost"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=8888,
        help="The port to listen on, defaults to 8888"
    )
    parser.add_argument(
        "-s", "--socket", default="/run/redis/redis.sock",
        help="Path to the redis socket, defaults to /run/redis/redis.sock"
    )
    parser.add_argument(
        "-x", "--prefix", default="ocspxy_",
        help="Select the redis key prefix, defaults to ocspxy_"
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s "+__version__)

    options = parser.parse_args()
    try: run(addr=options.host, port=options.port)
    except (KeyboardInterrupt, SystemExit): pass
