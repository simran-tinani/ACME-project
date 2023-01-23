import sys
import base64
import OpenSSL
from OpenSSL import crypto
import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import requests
import sys, time
import json
import copy
import configparser, subprocess
import dns.exception, dns.query, dns.name, dns.resolver, dns.rrset, dns.tsigkeyring, dns.update
import argparse
import logging, sys, configparser, re
from tempfile import NamedTemporaryFile
import os
import Crypto.Util.asn1
from Crypto.Util.asn1 import DerSequence
import binascii
from binascii import hexlify, unhexlify
import hashlib
from subprocess import Popen
import dnslib, binascii
from dnslib import *
import ipaddress
import dns.query
import dns.resolver
import datetime, time

parser = argparse.ArgumentParser(description='Start a DNS implemented in Python.')
parser.add_argument('--challenge', type=str, help='Challenge type.')
parser.add_argument('--dir', type=str, help='ACME Directory.')
parser.add_argument('--record', type=str, help='Record address.')
parser.add_argument('--domain', nargs='+')
parser.add_argument('--revoke', type=str)
args = parser.parse_args()

chall_type=args.challenge
domain_names=args.domain
record_address=args.record
acme_path=args.dir
dns_port=10053
http_port=5002

#record_address='127.0.0.1'
final_cert=""
priv_key_material_PEM=""
adtheaders = {'User-Agent': 'simran-tinani', 'Accept-Language': "en"}	
directory = requests.get(acme_path, headers=adtheaders, verify="pebble.minica.pem")
acme_config = directory.json()
terms_service = acme_config.get("meta", {}).get("termsOfService", "")
account_request = {}
if terms_service:
	account_request["termsOfServiceAgreed"] = True

def _base64(text):
    return base64.urlsafe_b64encode(text).decode("utf8").rstrip("=")

def generate_account_key(path=None):
	account_key = NamedTemporaryFile(delete=False)
	if path is None:
		acct_key = crypto.PKey()
		acct_key.generate_key(crypto.TYPE_RSA, 4096)
		acct_key_material_PEM = crypto.dump_privatekey(crypto.FILETYPE_PEM, acct_key)
		with open(account_key.name,'wt') as f: 
			f.write(acct_key_material_PEM.decode('utf-8'))
	else:
		with open(path, 'rb') as fh:
			acct_key = crypto.load_privatekey(crypto.FILETYPE_PEM, fh.read())
		acct_key_material_PEM=crypto.dump_privatekey(crypto.FILETYPE_PEM, acct_key)		
		with open(account_key.name,'wt') as f:
			f.write(acct_key_material_PEM.decode('utf-8'))
	return account_key
	
def get_ne_PEM(account_key):
	with open(account_key.name, 'rb') as fh:
		account_key1 = crypto.load_privatekey(crypto.FILETYPE_PEM, fh.read())
	acct_key_material_PEM = crypto.dump_publickey(crypto.FILETYPE_PEM, account_key1)
	key_val=acct_key_material_PEM.decode('utf-8')
	pubkey2 = serialization.load_pem_public_key(key_val.encode('ascii'))
	public_exponent=pubkey2.public_numbers().e
	modulus=pubkey2.public_numbers().n
	return public_exponent, modulus

def get_ne_ASN(account_key):
	with open(account_key.name, 'rb') as fh:
		account_key1 = crypto.load_privatekey(crypto.FILETYPE_PEM, fh.read())
	acct_key_material_ASN = crypto.dump_privatekey(crypto.FILETYPE_ASN1, account_key1)
	pub_der = DerSequence()
	pub_der.decode(acct_key_material_ASN)
	public_exponent=pub_der[2]
	modulus=pub_der[1] 
	return public_exponent, modulus

def generate_private_acme_signature(account_key):
	pub_exp, pub_hex=get_ne_ASN(account_key)
	pub_exp = "{0:x}".format(int(pub_exp)) 
	pub_exp = "0{0}".format(pub_exp) if len(pub_exp) % 2 else pub_exp
	pub_hex = "{0:x}".format(int(pub_hex)) 
	pub_hex = "0{0}".format(pub_hex) if len(pub_hex) % 2 else pub_hex
	private_acme_signature = {
        "alg": "RS256",
        "jwk": {
            "e": _base64(binascii.unhexlify(pub_exp.encode("utf-8"))),
            "kty": "RSA",
            "n": _base64(binascii.unhexlify(pub_hex.encode("utf-8"))),
		},
	}
	private_jwk = json.dumps(private_acme_signature["jwk"], sort_keys=True, separators=(",", ":"))
	jwk_thumbprint = _base64(hashlib.sha256(private_jwk.encode("utf8")).digest())
	return private_acme_signature, private_jwk, jwk_thumbprint


def send_signed_request(url, payload, private_acme_signature, account_key, extra_headers=None):
    with open(account_key.name, 'rb') as fh:
        account_key1 = crypto.load_privatekey(crypto.FILETYPE_PEM, fh.read())
    if payload == "":
        payload64 = ""
    else:
        payload64 = _base64(json.dumps(payload).encode("utf8"))
    protected = copy.deepcopy(private_acme_signature)
    nonce = requests.head(acme_config['newNonce'], headers=adtheaders, verify="pebble.minica.pem").headers['Replay-Nonce']        
    protected["nonce"] = nonce 
    del nonce
    protected["url"] = url
    if url == acme_config["newAccount"]:
        if "kid" in protected:
            del protected["kid"]
    else:
        del protected["jwk"]
    protected64 = _base64(json.dumps(protected).encode("utf8"))
    data="{0}.{1}".format(protected64, payload64).encode("utf8")
    signature4=crypto.sign(account_key1, data, "sha256")
    jose = {"protected": protected64, "payload": payload64, "signature": _base64(signature4)}
    joseheaders = {'Content-Type': 'application/jose+json'}
    joseheaders.update(adtheaders)
    extra_headers=None
    joseheaders.update(extra_headers or {})
    try:
        response = requests.post(url, json=jose, headers=joseheaders, verify="pebble.minica.pem", timeout=300)
    except requests.exceptions.RequestException as error:
        response = error.response
    if response:
        nonce = response.headers['Replay-Nonce']
        try:
            return (response, response.json())
        except ValueError:  # if body is empty or not JSON formatted
            return (response, json.loads("{}")) 
    else:
        raise RuntimeError("Unable to get response from ACME server.")

def new_account(url1, private_acme_signature, account_key):
	result=None
	nonce = requests.head(acme_config['newNonce'], headers=adtheaders, verify="pebble.minica.pem").headers['Replay-Nonce']
	http_response, account_info = send_signed_request(url1, account_request, private_acme_signature=private_acme_signature, account_key=account_key)
	if http_response.status_code == 201:
		private_acme_signature["kid"] = http_response.headers['Location']
	elif http_response.status_code == 200:
		private_acme_signature["kid"] = http_response.headers['Location']
		http_response, account_info = send_signed_request(private_acme_signature["kid"], "", private_acme_signature, account_key)	
	else:
		raise ValueError("Error registering account: {0} {1}".format(http_response.status_code, account_info))
	if ("contact" in account_request and set(account_request["contact"]) != set(account_info["contact"])):
		http_response, result = send_signed_request(private_acme_signature["kid"], account_request,private_acme_signature, account_key, acme_config)
		if http_response.status_code == 200:
			print("yay")
		else:
			raise ValueError("Error registering updates for the account: {0} {1}" .format(http_response.status_code, result))
	return http_response, account_info, result

def gen_new_order(url, private_acme_signature, account_key, domains, order_type="dns"):
	nonce = requests.head(acme_config['newNonce'], headers=adtheaders, verify="pebble.minica.pem").headers['Replay-Nonce']
	new_order = {"identifiers": [{"type": order_type, "value": domain} for domain in domains]}
	http_response, order = send_signed_request(url=url, payload=new_order, private_acme_signature=private_acme_signature, account_key=account_key)
	order_location = http_response.headers['Location']
	if http_response.status_code == 201:
		order_location = http_response.headers['Location']
		if order["status"] != "pending" and order["status"] != "ready":
			raise ValueError("Order status is neither pending neither ready, we can't use it: {0}".format(order))
	elif (http_response.status_code == 403 and order["type"] == "urn:ietf:params:acme:error:userActionRequired"):
		raise ValueError(("Order creation failed ({0}). Read Terms of Service ({1}), then follow " "your CA instructions: {2}").format(order["detail"],
			http_response.headers['Link'], order["instance"]))
	else:
		raise ValueError("Error getting new Order: {0} {1}".format(http_response.status_code, order))
	return order_location, order


def authorize_dns(order, private_keyring=None,dns_timeout=10):
	for authz in order["authorizations"]:
		http_response, authorization = send_signed_request(authz, "", private_acme_signature, account_key)
		domain=authorization["identifier"]["value"]
		dnsrr_domain="_acme-challenge." + domain +"."
		challenges = [c for c in authorization["challenges"] if c["type"] == "dns-01"]
		vers=[]
		for challenge in challenges:
			ver = False
			keyauthorization = challenge["token"] + "." + jwk_thumbprint
			keydigest64 = _base64(hashlib.sha256(keyauthorization.encode("utf8")).digest())
			dnsrr_set = dns.rrset.from_text(dnsrr_domain, dns_timeout, "IN", "TXT", keydigest64)
			q1=DNSQuestion("delete", QTYPE.TXT)
			d = DNSRecord(q=q1)
			pkt = d.send('student-project.com',dns_port,tcp=False)
			q1=DNSQuestion(dnsrr_domain, QTYPE.TXT)
			d = DNSRecord(q=q1)
			a1 = d.reply()
			string=str(dnsrr_set.to_text())
			a1.add_answer(*RR.fromZone(string))
			pkt = a1.send('student-project.com',dns_port,tcp=False)
			ppkt = DNSRecord.parse(pkt)
			domain1 = dns.name.from_text(dnsrr_domain)
			if not domain1.is_absolute():
				domain1 = domain1.concatenate(dns.name.root)
			for i in range(0,10):
				if ver is True:
					break
				request1 = dns.message.make_query(domain1, dns.rdatatype.TXT)
				data1 = dns.query.udp(request1, record_address, port=dns_port)
				answers=data1.answer
				for ans in answers:
					la=str(ans.to_text().split()[-1]).strip('\"')
					print(la,keydigest64)
					if la==str(keydigest64).strip():
						ver=True
			vers.append(ver)
		bool1=all(ver1 is True for ver1 in vers)
		print("The self-test verified that the challenge was successfully performed: {0}".format(bool1))			
	if ver is True:
		try:
			while True:
				http_response, challenge_status = send_signed_request(challenge["url"], "", private_acme_signature, account_key)
				if http_response.status_code != 200:
					raise ValueError("Error during challenge validation: {0} {1}".format(http_response.status_code, challenge_status))
				print(challenge_status["status"])
				if challenge_status["status"] == "pending":
					#time.sleep(float(http_response.headers["Retry-After"]))
					time.sleep(60)
				elif challenge_status["status"] == "valid":
					print("ACME has verified challenge for domain: %s", domain)
					break
				else:
					raise ValueError("Challenge for domain {0} did not pass: {1}".format(domain, challenge_status))
		finally:
			q1=DNSQuestion("delete", QTYPE.TXT)
			d = DNSRecord(q=q1)
			pkt = d.send(domain,dns_port,tcp=False)


def authorize_http(order, jwk_thumbprint):
	for authz in order["authorizations"]:
		http_response, authorization = send_signed_request(authz, "", private_acme_signature, account_key)
		domain=authorization["identifier"]["value"]
		challenges = [c for c in authorization["challenges"] if c["type"] == "http-01"]
		vers=[]
		for challenge in challenges:
			ver = False
			token=challenge["token"]
			keyauthorization = challenge["token"] + "." + jwk_thumbprint
			keydigest64 = _base64(hashlib.sha256(keyauthorization.encode("utf8")).digest())
			wellknown_url = "http://{0}:5002/.well-known/acme-challenge/{1}".format(domain, token)
			data = {'post-value': keydigest64, 'password':'post-pw'}
			headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
			r = requests.post(url=wellknown_url, json = json.dumps(data), headers=headers)
			for i in range(0,10):
				if ver is True:
					break
				B=requests.get(wellknown_url)
				ver=(B.text==keydigest64)
			vers.append(ver)
		bool1=all(ver1 is True for ver1 in vers)
		print("The self-test verified that the challenge was successfully performed: {0}".format(bool1))
		try:
			while True:
				print('Trying to authorize through pebble server')
				http_response, challenge_status = send_signed_request(challenge["url"], "", private_acme_signature, account_key)
				if http_response.status_code != 200:
					raise ValueError("Error during challenge validation: {0} {1}".format(http_response.status_code, challenge_status))
				if challenge_status["status"] == "pending":
					time.sleep(60)
					#time.sleep(float(http_response.headers["Retry-After"]))
					print("Status pending, sleeping for 60 seconds")
				elif challenge_status["status"] == "valid":
					print("ACME has verified challenge for domain: %s", domain)
					break
				else:
					raise ValueError("Challenge for domain {0} did not pass: {1}".format(domain, challenge_status))
		except:
			raise ValueError("Connection to ACME server timed out")

def generate_csr(domain_names):
	priv_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
	csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
])).add_extension(x509.SubjectAlternativeName([
			name for name in [x509.DNSName(u"{0}".format(domain)) for domain in domain_names]
    ]),
    critical=False,
)
	csr=csr.sign(priv_key, hashes.SHA256())
	return csr,priv_key


def finalize(order):
	csr, priv_key=generate_csr(domain_names)
	priv_key_material_PEM = crypto.dump_privatekey(crypto.FILETYPE_PEM, priv_key)
	serialized = csr.public_bytes(
        serialization.Encoding.DER
    )
	csr_der = _base64(serialized)
	http_response, result = send_signed_request(order["finalize"], {"csr": csr_der}, private_acme_signature, account_key)
	if http_response.status_code != 200:
		raise ValueError("Error while sending the CSR: {0} {1}".format(http_response.status_code, result))
	while True:
		http_response, order = send_signed_request(order_location, "")
		if order["status"] == "processing":
			try:
				time.sleep(float(http_response.headers["Retry-After"]))
			except (OverflowError, ValueError, TypeError):
				time.sleep(10)
		elif order["status"] == "valid":
			print("Order finalized!")
			break
		else:
			raise ValueError("Finalizing order {0} got errors: {1}".format(order_location, order))
	http_response, result = send_signed_request(order["certificate"], "", {'Accept': "application/pem-certificate-chain"})
	if http_response.status_code != 200:
		raise ValueError("Finalizing order {0} got errors: {1}".format(http_response.status_code, result))
	final_cert=http_response.text
	return final_cert, priv_key_material_PEM

account_key=generate_account_key(path=None)
private_acme_signature, private_jwk, jwk_thumbprint=generate_private_acme_signature(account_key)
http_response, account_info, result = new_account(acme_config["newAccount"], private_acme_signature, account_key)	
print("Account created!")
order_location, order=gen_new_order(url=acme_config["newOrder"], private_acme_signature=private_acme_signature, account_key=account_key, domains=domain_names)
print("Order obtained!")


if chall_type=="http01":
	print("Performing HTTP Challenge")
	authorize_http(order, jwk_thumbprint)
else:
	print("Performing DNS Challenge")
	authorize_dns(order, jwk_thumbprint)

final_cert, priv_key_material_PEM=finalize(order)

with open('final-certificate.pem', 'w') as f:
	f.write(final_cert)

with open("domain_private_key.pem",'w') as f:
	f.write(priv_key_material_PEM)
