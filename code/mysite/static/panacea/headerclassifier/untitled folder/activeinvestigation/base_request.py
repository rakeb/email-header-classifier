"""
author: Md Mazharul Islam
email: mislam7@uncc.edu, rakeb.mazharul@gmial.com
"""

import json

import requests


def post_request(url, data, auth):
    resp = requests.post(url, json=data, auth=auth)
    json_obj = json.loads(resp.text)
    return json_obj


def get_request(url=None):
    # contents = urllib.request.urlopen(url).read()
    r = requests.get(url)
    # print(r.status_code)
    # print(r.headers)
    # print(r.content)
    # print(r.text)
    # print(r.headers['content-type'])
    try:
        json_data = json.loads(r.text)
        # print(json_data)
        return json_data
    except:
        print('not an json response')

    return r


if __name__ == '__main__':
    # post_request(url=None, json={}, auth=('admin', 'admin'))
    get_request("http://google.com")
