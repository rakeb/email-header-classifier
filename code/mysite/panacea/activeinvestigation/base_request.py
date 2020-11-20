"""
author: Md Mazharul Islam
email: mislam7@uncc.edu, rakeb.mazharul@gmial.com
"""

import json
import logging

import requests

from inspect import currentframe, getframeinfo

from panacea.utilities.custom_errors_logs import write_error_logs

logger = logging.getLogger('base_request.py')
logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                    datefmt='%Y-%m-%d:%H:%M:%S',
                    level=logging.DEBUG)

http_proxy = "http://ased-proxy-01.ased.io:8888"
https_proxy = "https://ased-proxy-01.ased.io:8888"

proxyDict = {
    "http": http_proxy,
    "https": https_proxy,
}


def post_request(url, data, auth):
    resp = requests.post(url, json=data, auth=auth)
    json_obj = json.loads(resp.text)
    return json_obj


def get_request(url=None, message_id=None, headers=None):
    try:
        if headers is None:
            r = requests.get(url, proxies=proxyDict, timeout=(5, 15))
        else:
            return requests.get(url, proxies=proxyDict, timeout=(5, 15), headers=headers)
    except requests.exceptions.Timeout as e:
        logger.error("Timeout: {}".format(e))
        frameinfo = getframeinfo(currentframe())
        write_error_logs(message_id=message_id,
                         message="[{}: {}] Timeout: {}".format(
                             frameinfo.filename,
                             frameinfo.lineno + 1,
                             "Timeout : {}".format(e)))
        raise requests.exceptions.Timeout
    except requests.exceptions.ProxyError as e:
        logger.error("ProxyError: {}".format(e))
        frameinfo = getframeinfo(currentframe())
        write_error_logs(message_id=message_id,
                         message="[{}: {}] ProxyError: {}".format(
                             frameinfo.filename,
                             frameinfo.lineno + 1,
                             "ProxyError : {}".format(e)))
        raise requests.exceptions.ProxyError
    except requests.exceptions.ConnectionError as e:
        logger.error("ConnectionError: {}".format(e))
        frameinfo = getframeinfo(currentframe())
        write_error_logs(message_id=message_id,
                         message="[{}: {}] ConnectionError: {}".format(
                             frameinfo.filename,
                             frameinfo.lineno + 1,
                             "ConnectionError : {}".format(e)))
        raise requests.exceptions.ConnectionError
    except requests.exceptions.HTTPError as e:
        logger.error("HTTPError: {}".format(e))
        frameinfo = getframeinfo(currentframe())
        write_error_logs(message_id=message_id,
                         message="[{}: {}] HTTPError: {}".format(
                             frameinfo.filename,
                             frameinfo.lineno + 1,
                             "HTTPError : {}".format(e)))
        raise requests.exceptions.ConnectionError

    except requests.exceptions.RequestException as e:
        logger.error("RequestException: {}".format(e))
        frameinfo = getframeinfo(currentframe())
        write_error_logs(message_id=message_id,
                         message="[{}: {}] RequestException: {}".format(
                             frameinfo.filename,
                             frameinfo.lineno + 1,
                             "RequestException : {}".format(e)))
        raise requests.exceptions.ConnectionError

    try:
        json_data = json.loads(r.text)
        return json_data
    except Exception as e:
        logger.error("Exception in base request, ULR: {}, Error message: {}".format(url, e))
        frameinfo = getframeinfo(currentframe())
        write_error_logs(message_id=message_id,
                         message="[{}: {}] Exception: {}".format(
                             frameinfo.filename,
                             frameinfo.lineno + 1,
                             "Exception in base request, ULR: {}, Error message: {}".format(url, e)))
        raise Exception


if __name__ == '__main__':
    # post_request(url=None, json={}, auth=('admin', 'admin'))
    get_request("http://google.com")
