import json
import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import logging
# import requests
import whois


class DomainName(logging.Filter):
    def filter(self, record):
        record.domain = domain_name
        return True


logging.basicConfig(filename="demo.log", level=logging.INFO,
                    format='%(asctime)s :: %(levelname)s :: %(message)s')
logger = logging.getLogger(__name__)
logger.addFilter(DomainName())
syslog = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s %(domain)s : %(message)s')
syslog.setFormatter(formatter)
logger.setLevel(logging.INFO)
logger.addHandler(syslog)


def dnssec_generate_output(enabled=False, valid=False):
    output = {
        "domain": domain_name,
        "dnssec": {
            "enabled": enabled,
            "valid": valid
        }
    }
    print(json.dumps(output))


logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s',
                    level=logging.DEBUG)
logger = logging.getLogger('test_logger')
logger.warning('This will not show up')
logger.info('This will')

# domain_name = 'google.com'
domain_name = 'softcell.com'
# domain_name = 'fincaresfbank.in'
try:
    response = dns.resolver.resolve(domain_name, dns.rdatatype.NS)
    ns_name = response.rrset[0].to_text()  # name
    response = dns.resolver.resolve(ns_name, dns.rdatatype.A)
    ns_addr = response.rrset[0].to_text()  # IPv4
    # print(f"ns_addr: {ns_addr}")
    logger.info('Valid domain name')
    # print("Valid")

    # get DNSKEY for zone
    request = dns.message.make_query(domain_name,
                                     dns.rdatatype.DNSKEY,
                                     want_dnssec=True)

    # send the query
    response = dns.query.udp(request, ns_addr)
    if response.rcode() != 0 or not response.answer:
        dnssec_generate_output()
    else:
        # answer should contain two RRSET: DNSKEY and RRSIG(DNSKEY)
        if len(response.answer) == 2:
            # the DNSKEY should be self signed, validate it:
            try:
                dns.dnssec.validate(response.answer[0], response.answer[1],
                                    {dns.name.from_text(domain_name): response.answer[0]})
            except dns.dnssec.ValidationFailure:
                dnssec_generate_output(enabled=True)
            else:
                dnssec_generate_output(enabled=True, valid=True)
        else:
            dnssec_generate_output(enabled=True)
except dns.exception.DNSException:
    # logging.exception("exception logged", exc_info=True)
    logger.info('Invalid domain name')
    # print("Invalid")
