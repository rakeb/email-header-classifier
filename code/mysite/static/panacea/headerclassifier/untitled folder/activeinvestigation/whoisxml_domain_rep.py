"""
author: Md Mazharul Islam
email: mislam7@uncc.edu, rakeb.mazharul@gmial.com

site: https://domain-reputation-api.whoisxmlapi.com/docs
user: rakeb.void
account type: free
url type: https://domain-reputation-api.whoisxmlapi.com/api/v1?apiKey=&domainName=google.com
whois = https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_TSPQESosvGwr4qyXGg7ZhmOBnqJAI&domainName=google.com
"""

import pickle

from django.core.exceptions import ObjectDoesNotExist

import base_request

INPUT_DOMAIN_LIST = 'domain_list'
API_KEY_FILE_NAME = 'api_key'
REP_MATRIX_FILE_NAME = 'reputation_matrix'
GEO_LOCATION_FILE_NAME = 'geo_location'

DOMAIN_REPUTATION = "domain-reputation"
DNS_LIFETIME = "dns-lifetime"
GEO_LOCATION = "geo-location"

INVESTIGATION_TYPE = "investigation-type"
DOMAIN_NAME = "domain-name"
IP_ADD = "ip-address"
API_KEY = "api-key"


def write_new_line_in_file(file_name=None, line=None):
    with open(file_name, 'a') as f:
        f.write('\n')
        f.write(line)


def read_input_file():
    with open(INPUT_DOMAIN_LIST) as f:
        content = f.readlines()
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
        print("reputation_matrix saved for further use.\n")


def get_whosi_url(api_key=None, domain_name=None):
    whois_url = 'https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=' + api_key + '&domainName=' + domain_name + '&outputFormat=JSON'
    return whois_url


def get_domain_reputation_url(api_key=None, domain_name=None):
    domain_reputation_url = 'https://domain-reputation-api.whoisxmlapi.com/api/v1?apiKey=' \
                            + api_key + '&domainName=' + domain_name
    return domain_reputation_url


def get_geo_location_url(api_key=None, ip_add=None):
    # https://geoipify.whoisxmlapi.com/api/v1?apiKey=at_TSPQESosvGwr4qyXGg7ZhmOBnqJAI&ipAddress=8.8.8.8
    geo_location_url = 'https://geoipify.whoisxmlapi.com/api/v1?apiKey=' + api_key + '&ipAddress=' + ip_add
    return geo_location_url


def get_reputation(domain_name, api_key):
    # {
    #     "reputationScore": 98.67
    # }
    url_custom = 'https://domain-reputation-api.whoisxmlapi.com/api/v1?apiKey=' + api_key + '&domainName=' + domain_name
    response = base_request.get_request(url_custom)
    return response


def get_investigation_result(investigation_url):
    response = base_request.get_request(investigation_url)
    return response


def investigate(json_req):
    api_keys = read_api_key()
    file_name = ''
    search_criteria = ''
    for api_key in api_keys:
        if json_req[INVESTIGATION_TYPE] == DOMAIN_REPUTATION:
            domain_name = json_req[DOMAIN_NAME]
            investigation_url = get_domain_reputation_url(api_key, domain_name)
            file_name = REP_MATRIX_FILE_NAME
            search_criteria = domain_name

        if json_req[INVESTIGATION_TYPE] == DNS_LIFETIME:
            domain_name = json_req[DOMAIN_NAME]
            investigation_url = get_whosi_url(api_key, domain_name)
            file_name = REP_MATRIX_FILE_NAME
            search_criteria = domain_name

        if json_req[INVESTIGATION_TYPE] == GEO_LOCATION:
            ip_add = json_req[IP_ADD]
            investigation_url = get_geo_location_url(api_key, ip_add)
            file_name = GEO_LOCATION_FILE_NAME
            search_criteria = ip_add

        try:
            reputation_matrix = load_reputation_matrix(file_name)
            print("current reputation saved: ")
            print(reputation_matrix)
        except:
            reputation_matrix = {}

        if not reputation_matrix or not (search_criteria in reputation_matrix) or not (
                    json_req[INVESTIGATION_TYPE] in reputation_matrix[search_criteria]):
            response = get_investigation_result(investigation_url)

            if not response:
                continue

            dom_dict = {json_req[INVESTIGATION_TYPE]: response}
            try:
                existing_dic = reputation_matrix[search_criteria]
                existing_dic.update(dom_dict)
            except:
                reputation_matrix[search_criteria] = dom_dict
            print(reputation_matrix)
            save_reputation_matrix(reputation_matrix, file_name)
            break
        else:
            print('Printing form saved')
            print(reputation_matrix)
            break
    return reputation_matrix[search_criteria]


# def investigate_using_db(json_req):
#     investigation_type = json_req[INVESTIGATION_TYPE]
#     domain_name = json_req[DOMAIN_NAME]
#     ip_add = json_req[IP_ADD]
#     api_key = json_req[API_KEY]
#
#     if api_key and api_key != 'NA' and api_key != 'N/A':
#         write_new_line_in_file(API_KEY_FILE_NAME, api_key)
#     api_keys = read_api_key()
#
#     if investigation_type == GEO_LOCATION:
#         try:
#             geo_db_obj = GeoLocation.objects.using('panacea').get(ip_address=ip_add)
#             return geo_db_obj.json_attribute
#         except ObjectDoesNotExist:
#             for api_key in api_keys:
#                 investigation_url = get_geo_location_url(api_key, ip_add)
#                 response = get_investigation_result(investigation_url)
#                 if not response:
#                     continue
#                 geo_db_obj = GeoLocation(ip_address=ip_add, json_attribute=response)
#                 geo_db_obj.save(using='panacea')
#                 return response
#     elif investigation_type == DOMAIN_REPUTATION or investigation_type == DNS_LIFETIME:
#         try:
#             domain_db_obj = DomainAttributes.objects.using('panacea').get(domain_name=domain_name,
#                                                                           attribute_name=investigation_type)
#             return domain_db_obj.json_attribute
#         except ObjectDoesNotExist:
#             for api_key in api_keys:
#                 if investigation_type == DOMAIN_REPUTATION:
#                     investigation_url = get_domain_reputation_url(api_key, domain_name)
#                 else:
#                     investigation_url = get_whosi_url(api_key, domain_name)
#                 response = get_investigation_result(investigation_url)
#                 if not response:
#                     continue
#                 domain_db_obj = DomainAttributes(domain_name=domain_name, attribute_name=investigation_type,
#                                                  json_attribute=response)
#                 domain_db_obj.save(using='panacea')
#                 return response
#     else:
#         return "Nothing found!"

if __name__ == '__main__':
    # investigation - type can be domain-reputation, dns-lifetime or geo-location
    req = {
        "investigation-type": "geo-location",
        "domain-name": "google.com",
        "api-key": "NA",
        "ip-address": "65.190.141.7"
    }
    investigate(req)
