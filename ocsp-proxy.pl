#!/usr/bin/perl 
#
# ocsp proxy
#
# author, (c) Philippe Kueck <projects at unixadm dot org>
#

use strict;
use warnings;

use HTTP::Daemon;
use HTTP::Status;
use HTTP::Response;
use LWP;

use Redis;

use Net::SSLeay;
use Convert::ASN1;

use POSIX;

# config goes here
my $redis = new Redis(
	'sock' => '/run/redis/redis.sock',
	'reconnect' => 60, 'every' => 1_000_000
);

my $rprefix = "ocspxy_";
# config done

my $asn = new Convert::ASN1;
my $asn_ret = $asn->prepare(q<
OCSPRequest ::= SEQUENCE { tbsRequest TBSRequest }
TBSRequest ::= SEQUENCE { requestList SEQUENCE OF Request }
Request ::= SEQUENCE { reqCert CertID }
CertificateSerialNumber ::= INTEGER

CertID ::= SEQUENCE {
    hashAlgorithm  AlgorithmIdentifier,
    issuerNameHash OCTET STRING,
    issuerKeyHash  OCTET STRING,
    serialNumber   CertificateSerialNumber
}

AlgorithmIdentifier ::= SEQUENCE {
	algorithm  OBJECT IDENTIFIER,
    parameters ANY DEFINED BY algorithm OPTIONAL
}

>);
die "asn1 definition preparation failed: ". $asn->error() unless $asn_ret;
my $asn_top = $asn->find("OCSPRequest");
die "asn1 cannot find top of structure: ". $asn->error() unless $asn_top;

my $daemon = new HTTP::Daemon('LocalPort' => 8888, Reuse => 1) or die;
while (my $c = $daemon->accept) {
	while (my $r = $c->get_request) {

		unless ($r->method eq 'POST') {
			print STDERR "[err] method is not POST\n";
			$c->send_error(RC_FORBIDDEN);
			next
		}

		unless ($r->header('Host')) {
			print STDERR "[err] no 'Host' header found\n";
			$c->send_error(RC_BAD_REQUEST);
			next
		}

		unless ($r->header('Content-Type') eq "application/ocsp-request") {
			print STDERR "[err] Content-Type is not 'application/ocsp-request'\n";
			$c->send_error(RC_BAD_REQUEST);
			next
		}

		my $ocsp_req = $asn_top->decode($r->content);
		unless ($ocsp_req) {
			print STDERR "[err] cannot parse ocsp request\n";
			$c->send_error(RC_BAD_REQUEST);
			next
		}

		my $cache_key = $rprefix . unpack("H*",
			$ocsp_req->{'tbsRequest'}->{'requestList'}->[0]->{'reqCert'}->{'issuerKeyHash'}
			) . 
			$ocsp_req->{'tbsRequest'}->{'requestList'}->[0]->{'reqCert'}->{'serialNumber'}->as_hex;

		my $cache_is_valid = 0;
		my %cache = $redis->hgetall($cache_key);

		$cache_is_valid++ if %cache && $cache{'nextupd'} > time && $cache{'thisupd'} > 0 && $cache{'data'};

		if (!$cache_is_valid || $cache{'nextupd'} - time < (86400*2)) {

			my $ua = new LWP::UserAgent('agent' => "ocsp_proxy");
			my $proxy_req = new HTTP::Request('POST' => "http://".$r->header('Host'));
			$proxy_req->header(
				'Host' => $r->header('Host'),
				'Content-Type' => 'application/ocsp-request',
				'Content-Length' => $r->header('Content-Length')
			);
			$proxy_req->content($r->content);
			my $proxy_res = $ua->request($proxy_req);
	

			if ($proxy_res->code == 200 &&
				$proxy_res->header('Content-Type') eq "application/ocsp-response") {

				my $ocsp_resp = eval {
					Net::SSLeay::d2i_OCSP_RESPONSE($proxy_res->content)
				};
	
				if (Net::SSLeay::OCSP_response_status($ocsp_resp) ==
					Net::SSLeay::OCSP_RESPONSE_STATUS_SUCCESSFUL()) {
					my @ocsp_res = Net::SSLeay::OCSP_response_results($ocsp_resp);
					%cache = (
						'thisupd' => $ocsp_res[0]->[2]->{'thisUpdate'},
						'nextupd' => $ocsp_res[0]->[2]->{'nextUpdate'},
						'status'  => $ocsp_res[0]->[2]->{'statusType'},
						'data'    => $proxy_res->content
					);
					$redis->hmset($cache_key, %cache);
					$cache_is_valid++
				}
			}

			unless ($cache_is_valid) {
				print "[err] cache is invalid and cannot get valid data from ocsp responder\n";
				$c->send_error(RC_SERVICE_UNAVAILABLE);
				next
			}

		}

		my $client_res = new HTTP::Response(RC_OK);
		$client_res->header(
			'Content-Type' => 'application/ocsp-response',
			'Content-Length' => length $cache{'data'},
			'Date' => strftime("%a, %d %b %Y %T %Z", localtime),
			'Expires' => strftime("%a, %d %b %Y %T %Z", localtime $cache{'nextupd'}),
			'Last-Modified' => strftime("%a, %d %b %Y %T %Z", localtime $cache{'thisupd'})
		);
		$client_res->content($cache{'data'});
		$c->send_response($client_res);
	}

	$c->close;
	undef $c
}

__END__

=head1 NAME

ocsp-proxy - a caching ocsp proxy :)

=head1 VERSION

 0.1

=head1 SYNOPSIS

 ocsp-proxy.pl

=head1 OPTIONS

TODO: add command line switches for address, port and redis path

=head1 DESCRIPTION

This daemon acts as a proxy for ocsp requests.
You may use it together with apache httpd / mod_ssl:

 SSLOCSPProxyURL http://127.0.0.1:8888/

OCSP responses are stored in a redis db and are only refreshed when the data has expired.

TODO: refresh sooner.

=head1 DEPENDENCIES

=over 8

=item L<HTTP::Daemon>

=item L<HTTP::Status>

=item L<HTTP::Response>

=item L<LWP>

=item L<Redis>

=item L<Net::SSLeay>

=item L<Convert::ASN1>

=back

=head1 AUTHOR

Philippe Kueck <projects at unixadm dot org>

=cut
