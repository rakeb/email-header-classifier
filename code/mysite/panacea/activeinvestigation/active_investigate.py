"""
author: Md Mazharul Islam
email: mislam7@uncc.edu, rakeb.mazharul@gmial.com

site: https://domain-reputation-api.whoisxmlapi.com/docs
user: rakeb.void
account type: free
url type: https://domain-reputation-api.whoisxmlapi.com/api/v1?apiKey=&domainName=google.com
whois = https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_TSPQESosvGwr4qyXGg7ZhmOBnqJAI&domainName=google.com

The input is:
{
	"investigation-type": "geo-location",  # or "domain-reputation" or "dns-lifetime"
	"domain-name": "google.com",
	"api-key": "NA",
	"ip-address": "65.190.141.7"
}

The output for "domain-reputation":
{
    "reputationScore": 84.2
}

The output for "dns-lifetime":
{
    "WhoisRecord": {
        "expiresDate": "2020-09-13T21:00:00-0700",
        "customField1Name": "RegistrarContactEmail",
        "contactEmail": "abusecomplaints@markmonitor.com",
        "header": "",
        "customField3Value": "http://www.markmonitor.com",
        "registrant": {
            "rawText": "Registrant Organization: Google LLC\nRegistrant State/Province: CA\nRegistrant Country: US",
            "organization": "Google LLC",
            "state": "CA",
            "countryCode": "US",
            "country": "UNITED STATES"
        },
        "createdDateNormalized": "1997-09-15 07:00:00 UTC",
        "whoisServer": "whois.markmonitor.com",
        "customField1Value": "abusecomplaints@markmonitor.com",
        "expiresDateNormalized": "2020-09-14 04:00:00 UTC",
        "technicalContact": {
            "rawText": "Tech Organization: Google LLC\nTech State/Province: CA\nTech Country: US",
            "organization": "Google LLC",
            "state": "CA",
            "countryCode": "US",
            "country": "UNITED STATES"
        },
        "registrarName": "MarkMonitor, Inc.",
        "parseCode": 3579,
        "updatedDateNormalized": "2018-02-21 18:45:07 UTC",
        "status": "clientUpdateProhibited clientTransferProhibited clientDeleteProhibited serverUpdateProhibited serverTransferProhibited serverDeleteProhibited",
        "audit": {
            "updatedDate": "2019-02-09 02:42:10.000 UTC",
            "createdDate": "2019-02-09 02:42:10.000 UTC"
        },
        "domainNameExt": ".com",
        "administrativeContact": {
            "rawText": "Admin Organization: Google LLC\nAdmin State/Province: CA\nAdmin Country: US",
            "organization": "Google LLC",
            "state": "CA",
            "countryCode": "US",
            "country": "UNITED STATES"
        },
        "nameServers": {
            "rawText": "ns4.google.com\nns3.google.com\nns1.google.com\nns2.google.com\n",
            "ips": [],
            "hostNames": [
                "ns4.google.com",
                "ns3.google.com",
                "ns1.google.com",
                "ns2.google.com"
            ]
        },
        "customField2Name": "RegistrarContactPhone",
        "createdDate": "1997-09-15T00:00:00-0700",
        "registryData": {
            "expiresDate": "2020-09-14T04:00:00Z",
            "customField1Name": "RegistrarContactEmail",
            "header": "",
            "customField3Value": "http://www.markmonitor.com",
            "createdDateNormalized": "1997-09-15 04:00:00 UTC",
            "whoisServer": "whois.markmonitor.com",
            "customField1Value": "abusecomplaints@markmonitor.com",
            "expiresDateNormalized": "2020-09-14 04:00:00 UTC",
            "registrarName": "MarkMonitor Inc.",
            "parseCode": 251,
            "updatedDateNormalized": "2018-02-21 18:36:40 UTC",
            "status": "clientDeleteProhibited clientTransferProhibited clientUpdateProhibited serverDeleteProhibited serverTransferProhibited serverUpdateProhibited",
            "audit": {
                "updatedDate": "2019-02-09 02:42:04.000 UTC",
                "createdDate": "2019-02-09 02:42:04.000 UTC"
            },
            "nameServers": {
                "rawText": "NS1.GOOGLE.COM\nNS2.GOOGLE.COM\nNS3.GOOGLE.COM\nNS4.GOOGLE.COM\n",
                "ips": [],
                "hostNames": [
                    "NS1.GOOGLE.COM",
                    "NS2.GOOGLE.COM",
                    "NS3.GOOGLE.COM",
                    "NS4.GOOGLE.COM"
                ]
            },
            "customField2Name": "RegistrarContactPhone",
            "createdDate": "1997-09-15T04:00:00Z",
            "customField2Value": "+1.2083895740",
            "rawText": "Domain Name: GOOGLE.COM\n   Registry Domain ID: 2138514_DOMAIN_COM-VRSN\n   Registrar WHOIS Server: whois.markmonitor.com\n   Registrar URL: http://www.markmonitor.com\n   Updated Date: 2018-02-21T18:36:40Z\n   Creation Date: 1997-09-15T04:00:00Z\n   Registry Expiry Date: 2020-09-14T04:00:00Z\n   Registrar: MarkMonitor Inc.\n   Registrar IANA ID: 292\n   Registrar Abuse Contact Email: abusecomplaints@markmonitor.com\n   Registrar Abuse Contact Phone: +1.2083895740\n   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\n   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\n   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited\n   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\n   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited\n   Name Server: NS1.GOOGLE.COM\n   Name Server: NS2.GOOGLE.COM\n   Name Server: NS3.GOOGLE.COM\n   Name Server: NS4.GOOGLE.COM\n   DNSSEC: unsigned\n   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\n>>> Last update of whois database: 2019-02-09T02:41:48Z <<<\n\nFor more information on Whois status codes, please visit https://icann.org/epp\n\nNOTICE: The expiration date displayed in this record is the date the\nregistrar's sponsorship of the domain name registration in the registry is\ncurrently set to expire. This date does not necessarily reflect the expiration\ndate of the domain name registrant's agreement with the sponsoring\nregistrar.  Users may consult the sponsoring registrar's Whois database to\nview the registrar's reported date of expiration for this registration.\n\nTERMS OF USE: You are not authorized to access or query our Whois\ndatabase through the use of electronic processes that are high-volume and\nautomated except as reasonably necessary to register domain names or\nmodify existing registrations; the Data in VeriSign Global Registry\nServices' (\"VeriSign\") Whois database is provided by VeriSign for\ninformation purposes only, and to assist persons in obtaining information\nabout or related to a domain name registration record. VeriSign does not\nguarantee its accuracy. By submitting a Whois query, you agree to abide\nby the following terms of use: You agree that you may use this Data only\nfor lawful purposes and that under no circumstances will you use this Data\nto: (1) allow, enable, or otherwise support the transmission of mass\nunsolicited, commercial advertising or solicitations via e-mail, telephone,\nor facsimile; or (2) enable high volume, automated, electronic processes\nthat apply to VeriSign (or its computer systems). The compilation,\nrepackaging, dissemination or other use of this Data is expressly\nprohibited without the prior written consent of VeriSign. You agree not to\nuse electronic processes that are automated and high-volume to access or\nquery the Whois database except as reasonably necessary to register\ndomain names or modify existing registrations. VeriSign reserves the right\nto restrict your access to the Whois database in its sole discretion to ensure\noperational stability.  VeriSign may restrict or terminate your access to the\nWhois database for failure to abide by these terms of use. VeriSign\nreserves the right to modify these terms at any time.\n\nThe Registry database contains ONLY .COM, .NET, .EDU domains and\nRegistrars.",
            "domainName": "google.com",
            "footer": "\n",
            "strippedText": "Domain Name: GOOGLE.COM\nRegistry Domain ID: 2138514_DOMAIN_COM-VRSN\nRegistrar WHOIS Server: whois.markmonitor.com\nRegistrar URL: http://www.markmonitor.com\nUpdated Date: 2018-02-21T18:36:40Z\nCreation Date: 1997-09-15T04:00:00Z\nRegistry Expiry Date: 2020-09-14T04:00:00Z\nRegistrar: MarkMonitor Inc.\nRegistrar IANA ID: 292\nRegistrar Abuse Contact Email: abusecomplaints@markmonitor.com\nRegistrar Abuse Contact Phone: +1.2083895740\nDomain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\nDomain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\nDomain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\nDomain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited\nDomain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited\nDomain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited\nName Server: NS1.GOOGLE.COM\nName Server: NS2.GOOGLE.COM\nName Server: NS3.GOOGLE.COM\nName Server: NS4.GOOGLE.COM\nDNSSEC: unsigned\nURL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/\n>>> Last update of whois database: 2019-02-09T02:41:48Z <<<\nFor more information on Whois status codes, please visit https://icann.org/epp\nNOTICE: The expiration date displayed in this record is the date the\nregistrar's sponsorship of the domain name registration in the registry is\ncurrently set to expire. This date does not necessarily reflect the expiration\ndate of the domain name registrant's agreement with the sponsoring\nregistrar.  Users may consult the sponsoring registrar's Whois database to\nview the registrar's reported date of expiration for this registration.\nTERMS OF USE: You are not authorized to access or query our Whois\ndatabase through the use of electronic processes that are high-volume and\nautomated except as reasonably necessary to register domain names or\nmodify existing registrations; the Data in VeriSign Global Registry\nServices' (\"VeriSign\") Whois database is provided by VeriSign for\ninformation purposes only, and to assist persons in obtaining information\nabout or related to a domain name registration record. VeriSign does not\nguarantee its accuracy. By submitting a Whois query, you agree to abide\nby the following terms of use: You agree that you may use this Data only\nfor lawful purposes and that under no circumstances will you use this Data\nto: (1) allow, enable, or otherwise support the transmission of mass\nunsolicited, commercial advertising or solicitations via e-mail, telephone,\nor facsimile; or (2) enable high volume, automated, electronic processes\nthat apply to VeriSign (or its computer systems). The compilation,\nrepackaging, dissemination or other use of this Data is expressly\nprohibited without the prior written consent of VeriSign. You agree not to\nuse electronic processes that are automated and high-volume to access or\nquery the Whois database except as reasonably necessary to register\ndomain names or modify existing registrations. VeriSign reserves the right\nto restrict your access to the Whois database in its sole discretion to ensure\noperational stability.  VeriSign may restrict or terminate your access to the\nWhois database for failure to abide by these terms of use. VeriSign\nreserves the right to modify these terms at any time.\nThe Registry database contains ONLY .COM, .NET, .EDU domains and\nRegistrars.\n",
            "updatedDate": "2018-02-21T18:36:40Z",
            "customField3Name": "RegistrarURL",
            "registrarIANAID": "292"
        },
        "customField2Value": "+1.2083895740",
        "rawText": "Domain Name: google.com\nRegistry Domain ID: 2138514_DOMAIN_COM-VRSN\nRegistrar WHOIS Server: whois.markmonitor.com\nRegistrar URL: http://www.markmonitor.com\nUpdated Date: 2018-02-21T10:45:07-0800\nCreation Date: 1997-09-15T00:00:00-0700\nRegistrar Registration Expiration Date: 2020-09-13T21:00:00-0700\nRegistrar: MarkMonitor, Inc.\nRegistrar IANA ID: 292\nRegistrar Abuse Contact Email: abusecomplaints@markmonitor.com\nRegistrar Abuse Contact Phone: +1.2083895740\nDomain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)\nDomain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)\nDomain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)\nDomain Status: serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)\nDomain Status: serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)\nDomain Status: serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)\nRegistrant Organization: Google LLC\nRegistrant State/Province: CA\nRegistrant Country: US\nAdmin Organization: Google LLC\nAdmin State/Province: CA\nAdmin Country: US\nTech Organization: Google LLC\nTech State/Province: CA\nTech Country: US\nName Server: ns4.google.com\nName Server: ns3.google.com\nName Server: ns1.google.com\nName Server: ns2.google.com\nDNSSEC: unsigned\nURL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/\n>>> Last update of WHOIS database: 2019-02-08T18:41:02-0800 <<<\n\nFor more information on WHOIS status codes, please visit:\n  https://www.icann.org/resources/pages/epp-status-codes\n\nIf you wish to contact this domain’s Registrant, Administrative, or Technical\ncontact, and such email address is not visible above, you may do so via our web\nform, pursuant to ICANN’s Temporary Specification. To verify that you are not a\nrobot, please enter your email address to receive a link to a page that\nfacilitates email communication with the relevant contact(s).\n\nWeb-based WHOIS:\n  https://domains.markmonitor.com/whois\n\nIf you have a legitimate interest in viewing the non-public WHOIS details, send\nyour request and the reasons for your request to whoisrequest@markmonitor.com\nand specify the domain name in the subject line. We will review that request and\nmay ask for supporting documentation and explanation.\n\nThe data in MarkMonitor’s WHOIS database is provided for information purposes,\nand to assist persons in obtaining information about or related to a domain\nname’s registration record. While MarkMonitor believes the data to be accurate,\nthe data is provided \"as is\" with no guarantee or warranties regarding its\naccuracy.\n\nBy submitting a WHOIS query, you agree that you will use this data only for\nlawful purposes and that, under no circumstances will you use this data to:\n  (1) allow, enable, or otherwise support the transmission by email, telephone,\nor facsimile of mass, unsolicited, commercial advertising, or spam; or\n  (2) enable high volume, automated, or electronic processes that send queries,\ndata, or email to MarkMonitor (or its systems) or the domain name contacts (or\nits systems).\n\nMarkMonitor.com reserves the right to modify these terms at any time.\n\nBy submitting this query, you agree to abide by this policy.\n\nMarkMonitor is the Global Leader in Online Brand Protection.\n\nMarkMonitor Domain Management(TM)\nMarkMonitor Brand Protection(TM)\nMarkMonitor AntiCounterfeiting(TM)\nMarkMonitor AntiPiracy(TM)\nMarkMonitor AntiFraud(TM)\nProfessional and Managed Services\n\nVisit MarkMonitor at https://www.markmonitor.com\nContact us at +1.8007459229\nIn Europe, at +44.02032062220\n--",
        "domainName": "google.com",
        "footer": "\n",
        "strippedText": "Domain Name: google.com\nRegistrar WHOIS Server: whois.markmonitor.com\nRegistrar URL: http://www.markmonitor.com\nUpdated Date: 2018-02-21T10:45:07-0800\nCreation Date: 1997-09-15T00:00:00-0700\nRegistrar Registration Expiration Date: 2020-09-13T21:00:00-0700\nRegistrar: MarkMonitor, Inc.\nRegistrar IANA ID: 292\nRegistrar Abuse Contact Email: abusecomplaints@markmonitor.com\nRegistrar Abuse Contact Phone: +1.2083895740\nDomain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)\nDomain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)\nDomain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)\nDomain Status: serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)\nDomain Status: serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)\nDomain Status: serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)\nRegistrant Organization: Google LLC\nRegistrant State/Province: CA\nRegistrant Country: US\nAdmin Organization: Google LLC\nAdmin State/Province: CA\nAdmin Country: US\nTech Organization: Google LLC\nTech State/Province: CA\nTech Country: US\nName Server: ns4.google.com\nName Server: ns3.google.com\nName Server: ns1.google.com\nName Server: ns2.google.com\n",
        "updatedDate": "2018-02-21T10:45:07-0800",
        "customField3Name": "RegistrarURL",
        "estimatedDomainAge": 7816,
        "registrarIANAID": "292"
    }
}

The output for "geo-location":
{
    "domains": [
        "cpe-65-190-141-7.nc.res.rr.com"
    ],
    "ip": "65.190.141.7",
    "location": {
        "city": "Apex",
        "country": "US",
        "region": "North Carolina",
        "postalCode": "27502",
        "lat": 35.7225,
        "timezone": "America/New_York",
        "lng": -78.8408
    }
}

"""
import logging
import pickle
import re
import traceback
from inspect import currentframe, getframeinfo
from random import randrange

import dns.resolver
import requests
from bs4 import BeautifulSoup
from django.core.exceptions import ObjectDoesNotExist

from mysite.settings import MEDIA_ROOT
from panacea.activeinvestigation import base_request
from panacea.models import GeoLocation, DomainAttributes, EmailVerification
# Get an instance of a logger
from panacea.utilities.custom_errors_logs import write_error_logs

time_when_calling_web_crawler = None
logger = logging.getLogger('active_investigation.py')
logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                    datefmt='%Y-%m-%d:%H:%M:%S',
                    level=logging.DEBUG)

INPUT_DOMAIN_LIST = 'domain_list'
API_KEY_FILE_NAME = MEDIA_ROOT + '/panacea/api_key'
REP_MATRIX_FILE_NAME = MEDIA_ROOT + '/panacea/reputation_matrix'
GEO_LOCATION_FILE_NAME = MEDIA_ROOT + '/panacea/geo_location'

# investigation types
DOMAIN_REPUTATION = "domain-reputation"
DNS_LIFETIME = "dns-lifetime"
GEO_LOCATION = "geo-location"
EMAIL_VERIFICATION = "email-verification"

INVESTIGATION_TYPE = "investigation-type"
DOMAIN_NAME = "domain-name"
IP_ADD = "ip-address"
API_KEY = "api-key"
EMAIL_ADDRESS = "email-address"

http_proxy = "http://ased-proxy-01.ased.io:8888"
https_proxy = "https://ased-proxy-01.ased.io:8888"
# https_proxy = "https://10.108.17.17:8888"
# ftp_proxy = "ftp://10.10.1.10:3128"

proxyDict = {
    "http": http_proxy,
    "https": https_proxy,
    # "ftp": ftp_proxy
}

MESSAGE_ID = None


def write_new_line_in_file(file_name=None, line=None):
    with open(file_name, 'a') as f:
        f.write('\n')
        f.write(line)


def read_input_file():
    with open(INPUT_DOMAIN_LIST) as f:
        content = f.readlines()
    # you may also want to remove whitespace characters like `\n` at the end of each line
    content = [x.strip() for x in content]
    return content


def read_api_key():
    with open(API_KEY_FILE_NAME) as f:
        content = f.readlines()
    content = [x.strip() for x in content]
    return content


def load_reputation_matrix(file_name):
    with open(file_name,
              'rb') as i:
        credential = pickle.load(i)
        return credential


def save_reputation_matrix(rep, file_name):
    with open(file_name,
              'wb') as output:
        pickle.dump(rep, output, pickle.HIGHEST_PROTOCOL)
        # print("reputation_matrix saved for further use.\n")


def get_whoisxml_credit(api_key, product_id):
    _url = 'https://user.whoisxmlapi.com/service/account-balance?apiKey=' + api_key + '&productId=' + product_id

    response = get_investigation_result(_url)

    score = response['data'][0]['credits']
    logger.debug("Credits remaining for product {} is: {} where [1=WHOIS API, 7=Email Verification API "
                 "8=IP Geolocation API 20=Domain Reputation API ]".format(product_id, score))
    return score


def get_whois_url(api_key=None, domain_name=None):
    product_id = '1'
    score = get_whoisxml_credit(api_key, product_id)
    if score <= 0:
        return 0
    whois_url = 'https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=' + api_key + '&domainName=' + domain_name + '&outputFormat=JSON'
    return whois_url


def get_domain_reputation_url(api_key=None, domain_name=None):
    product_id = '20'
    score = get_whoisxml_credit(api_key, product_id)
    if score <= 0:
        return 0
    domain_reputation_url = 'https://domain-reputation-api.whoisxmlapi.com/api/v1?apiKey=' \
                            + api_key + '&domainName=' + domain_name
    return domain_reputation_url


def get_geo_location_url(api_key=None, ip_add=None):
    product_id = '8'
    score = get_whoisxml_credit(api_key, product_id)
    if score <= 0:
        return 0
    # https://geoipify.whoisxmlapi.com/api/v1?apiKey=at_TSPQESosvGwr4qyXGg7ZhmOBnqJAI&ipAddress=8.8.8.8
    geo_location_url = 'https://geoipify.whoisxmlapi.com/api/v1?apiKey=' + api_key + '&ipAddress=' + ip_add
    return geo_location_url


def get_email_verification_url(api_key=None, email_address=None):
    product_id = '7'
    score = get_whoisxml_credit(api_key, product_id)
    if score <= 0:
        return 0
    # https://emailverification.whoisxmlapi.com/api/v1?apiKey=at_TSPQESosvGwr4qyXGg7ZhmOBnqJAI&emailAddress=support@whoisxmlapi.com
    _url = 'https://emailverification.whoisxmlapi.com/api/v1?apiKey=' + api_key + '&emailAddress=' + email_address
    return _url


def get_investigation_result(investigation_url):
    response = base_request.get_request(url=investigation_url, message_id=MESSAGE_ID)
    return response


def get_rep_matrix(plain_text):
    rep = []
    soup = BeautifulSoup(plain_text, features="lxml")
    for td in soup.findAll('td', {'class': 'bsnDataRow1'}):
        raw_txt = td.string
        try:
            if '%' in raw_txt:
                rep.append(int(raw_txt.split('%')[0]))
        except:
            pass
    return rep


def web_crawler(domain_name):
    global time_when_calling_web_crawler
    x = randrange(100)
    y = randrange(100)
    url = 'http://www.borderware.com/domain_lookup.php?ip=' + domain_name + '&ipvalid=&Submit.x=' + str(
        x) + '&Submit.y=' + str(y)

    headers = {
        'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36'}

    logger.debug("URL for web crawling to RepAuthority: {}".format(url))

    source_code = base_request.get_request(url=url, message_id=MESSAGE_ID, headers=headers)

    try:
        plain_text = source_code.text
        rep_list = []
        rep_list += get_rep_matrix(plain_text)
        if not rep_list:
            m = 0
        else:
            try:
                rep_list = [val for i, val in enumerate(rep_list) if i % 3 == 0]
                m = max(rep_list)
                m = int(m)
            except Exception as e:
                logger.error("Exception: {} from reputation list found in: {}".format(e, url))
                frameinfo = getframeinfo(currentframe())
                write_error_logs(message_id=MESSAGE_ID,
                                 message="[{}: {}] Exception while getting Reputation: {}".format(
                                     frameinfo.filename,
                                     frameinfo.lineno + 1,
                                     "Exception: {} from reputation list found in: {}".format(e, url)))
                raise Exception
        reputation = {
            "reputationScore": m
        }
        logger.info("Response from web crawler: {}".format(reputation))
        return reputation
    except Exception:
        logger.exception("Web crawler exception: {}".format(url))
        frameinfo = getframeinfo(currentframe())
        write_error_logs(message_id=MESSAGE_ID,
                         message="[{}: {}] Web crawler exception: {}, in url: {}".format(
                             frameinfo.filename,
                             frameinfo.lineno + 1,
                             traceback.format_exc(),
                             url))
        raise Exception


def get_request_attributes(request):
    try:
        investigation_type = request[INVESTIGATION_TYPE]
    except:
        investigation_type = None
    try:
        domain_name = request[DOMAIN_NAME]
    except:
        domain_name = None
    try:
        ip_add = request[IP_ADD]
    except:
        ip_add = None
    try:
        api_key = request[API_KEY]
    except:
        api_key = None
    try:
        email_address = request[EMAIL_ADDRESS]
    except:
        email_address = None
    return investigation_type, domain_name, ip_add, email_address, api_key


def get_geo_from_keycdn(ip_add):
    # https://tools.keycdn.com/geo
    url = 'https://tools.keycdn.com/geo.json?host=' + ip_add
    response = base_request.get_request(url=url, message_id=MESSAGE_ID)
    logger.debug("Response from KEYCDN: {}".format(response))
    return response


def investigate_using_db(json_req):
    logger.debug("Active Investigation starts... {}".format(json_req))
    investigation_type, domain_name, ip_add, email_address, api_key = get_request_attributes(json_req)

    if api_key and api_key != 'NA' and api_key != 'N/A':
        write_new_line_in_file(API_KEY_FILE_NAME, api_key)

    api_keys = read_api_key()

    if investigation_type == GEO_LOCATION:
        try:
            geo_db_obj = GeoLocation.objects.using('panacea').filter(ip_address=ip_add).latest('id')
            logger.debug("Response coming from DB: {}".format(geo_db_obj.json_attribute))
            return geo_db_obj.json_attribute
        except ObjectDoesNotExist:
            response = get_geo_from_keycdn(ip_add)

            if response['status'] == 'error':
                return response

            geo_db_obj = GeoLocation(ip_address=ip_add, json_attribute=response)
            geo_db_obj.save(using='panacea')
            logger.debug("Response saving to DB: {}".format(response))
            return response
    elif investigation_type == EMAIL_VERIFICATION:
        try:
            email_verification_db_obj = EmailVerification.objects.using('panacea').filter(
                email_address=email_address).latest('id')
            logger.debug("Response coming from DB: {}".format(email_verification_db_obj.json_attribute))
            return email_verification_db_obj.json_attribute
        except ObjectDoesNotExist:
            for api_key in api_keys:
                investigation_url = get_email_verification_url(api_key, email_address)
                if investigation_url == 0:
                    continue
                response = get_investigation_result(investigation_url)

                if 'ErrorMessage' in response:
                    return response

                if not response:
                    continue
                email_verification_db_obj = EmailVerification(email_address=email_address, json_attribute=response)
                email_verification_db_obj.save(using='panacea')
                logger.debug("Response saving to DB: {}".format(response))
                return response
    elif investigation_type == DOMAIN_REPUTATION or investigation_type == DNS_LIFETIME:
        try:
            domain_db_obj = DomainAttributes.objects.using('panacea').filter(
                domain_name=domain_name, attribute_name=investigation_type).latest('id')
            logger.info("Response coming from DB: {}".format(domain_db_obj.json_attribute))
            return domain_db_obj.json_attribute
        except ObjectDoesNotExist:
            for api_key in api_keys:
                if investigation_type == DOMAIN_REPUTATION:
                    try:
                        response = web_crawler(domain_name)
                    except Exception as e:
                        logger.error("Exception in web crawler: {}".format(e))
                        logger.info("Whois domain reputation is calling because web crawler failed")

                        investigation_url = get_domain_reputation_url(api_key, domain_name)
                        if investigation_url == 0:
                            continue
                        response = get_investigation_result(investigation_url)
                else:
                    investigation_url = get_whois_url(api_key, domain_name)
                    if investigation_url == 0:
                        continue
                    response = get_investigation_result(investigation_url)

                if 'ErrorMessage' in response:
                    return response

                if not response:
                    continue
                domain_db_obj = DomainAttributes(domain_name=domain_name, attribute_name=investigation_type,
                                                 json_attribute=response)
                domain_db_obj.save(using='panacea')
                logger.info("Response saving to DB: {}".format(response))
                return response
    else:
        return "Nothing found!"


def error_response(status):
    res = {
        "score": 1,
        "threshold": "80%",
        "classification": 'malicious',
        "justification": {
            "domain-reputation": "N/A",
            "email-verification": "N/A",
            "other-comment": status
        },
        "status": "Ok"
    }
    return res


def DMARC_SPF_STATUS(HEADER):
    if 'authentication-results' in HEADER.keys():
        a_res = HEADER['authentication-results'][len(HEADER['authentication-results']) - 1]

        if 'spf=' in a_res:
            spf = a_res.split('spf=')[1].split(' ')[0]
        else:
            spf = ''
        if 'dmarc=' in a_res:
            dmarc = a_res.split('dmarc=')[1].split(' ')[0]
        else:
            dmarc = ''
        return spf, dmarc
    else:
        return '', ''


def ORIGINATOR_domain(HEADER):
    org_domain = ''
    reg_domain2_1 = re.compile('(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]{2,6}')
    if 'received' in HEADER.keys():
        for i in range(len(HEADER['received']) - 1, -1, -1):
            org_domain = ''
            # print(i)
            rcvd = HEADER['received'][i]
            if (rcvd.startswith('from')):
                org_domain = reg_domain2_1.findall(rcvd)
                if len(org_domain) > 0:
                    org_domain = org_domain[0]
                else:
                    org_domain = ''
                break
            else:
                continue
    else:
        org_domain = ''
    return org_domain


def get_only_domain(fqdn):
    domain_only = ''
    new_s = fqdn.split(".")[-2:]
    if len(new_s) == 2:
        domain_only = new_s[0] + '.' + new_s[1]

    return domain_only


def is_from_diff_than_originator(from_domain, originator_domain):
    if from_domain == originator_domain:
        from_is_diff_than_originator = False
    else:
        from_is_diff_than_originator = True
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            answers = resolver.query(from_domain, 'MX')
            logger.info("DNS query for MX record resolved, domain: {}".format(from_domain))
        except Exception as e:
            logger.exception("Exception in DNS query for MX record: ")
            frameinfo = getframeinfo(currentframe())
            write_error_logs(message_id=MESSAGE_ID,
                             message="[{}: {}] Exception in DNS query for MX record: {}".format(
                                 frameinfo.filename,
                                 frameinfo.lineno,
                                 traceback.format_exc()))
            return True
        for rdata in answers:
            if originator_domain in rdata.to_text():
                from_is_diff_than_originator = False
                break
    return from_is_diff_than_originator


def spoofing_check(email_header):
    reg_email = re.compile("([a-zA-Z0-9+._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)")
    from_email_address = reg_email.findall(email_header['from'][0])[0]
    from_domain = from_email_address.split('@')[1]
    from_domain = get_only_domain(from_domain)
    try:
        rp_email_address = reg_email.findall(email_header['return-path'][0])[0]
        rp_domain = rp_email_address.split('@')[1]
        rp_domain = get_only_domain(rp_domain)
    except Exception as e:
        logger.exception("Return path error: ")
        return 1, 'return-path not found'
    spf, dmarc = DMARC_SPF_STATUS(email_header)

    score = 0
    justification = {}
    status = 'Not Spoofed'
    if dmarc == 'pass':
        status = 'DMARC PASSED'
        return 0, status
    if dmarc == 'fail':
        status = 'DMARC FAILED'
        return 1, status

    _originator_domain = ORIGINATOR_domain(email_header)
    originator_domain = get_only_domain(_originator_domain)

    from_is_diff_than_originator = is_from_diff_than_originator(from_domain, originator_domain)
    if from_is_diff_than_originator:
        justification[
            'from_originator'] = 'MX record of From domain does not allowed the Originator (sender SMTP server domain) ' \
                                 'to send email on behalf of the Sender. From domain: %s is different than the ' \
                                 'Originator domain: %s)' % (from_domain, originator_domain)
        if spf == 'pass' or spf == 'neutral':
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2
                resolver.lifetime = 2
                answers = resolver.query(rp_domain, 'TXT')
                logger.info("DNS query for TXT record resolved, domain: {}".format(rp_domain))
            except Exception as e:
                logger.exception("Exception in DNS query for TXT record: ")
                frameinfo = getframeinfo(currentframe())
                write_error_logs(message_id=MESSAGE_ID,
                                 message="[{}: {}] Exception in DNS query for TXT record: {}".format(
                                     frameinfo.filename,
                                     frameinfo.lineno,
                                     traceback.format_exc()))
                status = 'SPF failed or softfailed'
                score = 1
                justification['status'] = status
                return score, justification
            for rdata in answers:
                if 'spf' in rdata.to_text():
                    spf_record = rdata.to_text()
                    justification['spf'] = spf_record
                    logger.debug("SPF record for domain {} is: {}".format(rp_domain, spf_record))
                    # txt_records.append(rdata.to_text())
                    all_type = spf_record.split(" ")[-1:][0]
                    if '+' in all_type:
                        status = 'SPF (+) allows every domain'
                        score = 0.85
                        break
                    elif '?' in all_type:
                        status = 'SPF (?) neutrals to every domain'
                        score = 0.80
                        break
                    elif 'includes' in spf_record:
                        status = 'SPF (includes) includes third party spfs'
                        score = 0.75
                        break
                    else:
                        status = 'SPF record is ok. Attacker may using a Return-path domain that is allowing the ' \
                                 'Originator to send emails on their behalf.'
                        score = 0.70
                        break

        else:
            status = 'SPF failed or softfailed'
            score = 1
    justification['status'] = status

    return score, justification


# this function will provide domain reputation and email verification results based on sender email address
def start_investigate(json_req, message_id):
    global MESSAGE_ID
    MESSAGE_ID = message_id
    email_header = json_req['email-header']
    try:
        from_email_address = email_header['From'][0]
    except KeyError:
        try:
            from_email_address = email_header['from'][0]
        except KeyError:
            status = "'From' field not found in the email header"
            return error_response(status)

    score = 0
    spoofing_justification = 'not spoofed'
    classification = 'normal'
    try:
        score, spoofing_justification = spoofing_check(email_header)
        if score > 0:
            classification = 'spoofing'
    except Exception as e:
        logger.exception("Exception in spoofing detection: ")
        frameinfo = getframeinfo(currentframe())
        write_error_logs(message_id=MESSAGE_ID,
                         message="[{}: {}] Exception in spoofing detection: {}".format(
                             frameinfo.filename,
                             frameinfo.lineno,
                             traceback.format_exc()))

    reg_email = re.compile("([a-zA-Z0-9+._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)")
    try:
        from_email_address = reg_email.findall(from_email_address)[0]
        domain_name = from_email_address.split('@')[1]
        domain_name = get_only_domain(domain_name)
    except:
        status = "Not a valid From: {}".format(from_email_address)
        return error_response(status)

    req = {
        INVESTIGATION_TYPE: DOMAIN_REPUTATION,  # or "domain-reputation" or "dns-lifetime"
        DOMAIN_NAME: domain_name,
        API_KEY: "NA",
    }
    try:
        domain_reputation_response = investigate_using_db(req)
    except Exception as e:
        logger.exception("Exception in calculating domain reputation")
        frameinfo = getframeinfo(currentframe())
        write_error_logs(message_id=MESSAGE_ID,
                         message="[{}: {}] Exception in calculating domain reputation: {}".format(
                             frameinfo.filename,
                             frameinfo.lineno,
                             traceback.format_exc()))
        domain_reputation_response = 'Can not resolve domain reputation'
    # req = {
    #     INVESTIGATION_TYPE: EMAIL_VERIFICATION,  # or "domain-reputation" or "dns-lifetime"
    #     EMAIL_ADDRESS: from_email_address,
    #     "api-key": "NA",
    # }
    # email_verification_response = investigate_using_db(req)

    # req = {
    #     INVESTIGATION_TYPE: DNS_LIFETIME,  # or "domain-reputation" or "dns-lifetime"
    #     DOMAIN_NAME: domain_name,
    #     "api-key": "NA",
    # }
    # domain_lifetime_response = investigate_using_db(req)

    try:
        if domain_reputation_response['reputationScore'] < 50:
            score = 0.75
            classification = 'malicious'
    except Exception as e:
        logger.error("Exception in calculating domain_reputation_response: {}".format(e))
        domain_reputation_response = 'Can not resolve domain reputation'
    res = {
        "from_email_address": from_email_address,
        "score": score,
        "spoofing_justification": spoofing_justification,
        "threshold": "50%",
        "classification": classification,
        "justification": {
            "domain-reputation": domain_reputation_response,
            # "email-verification": email_verification_response,
            # "domain-lifetime": domain_lifetime_response
        },
        "status": "OK"
    }
    return res
