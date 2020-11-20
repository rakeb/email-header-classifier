import ast
import json
import re
from collections import Counter
import numpy as np
from pathlib import Path

from panacea.activeinvestigation.active_investigate import investigate_using_db
from mysite.settings import STATICFILES_DIRS

mydict = {"Mon,": 1, "Tue,": 2, "Wed,": 3, "Thu,": 4,
          "Fri,": 5, "Sat,": 6, "Sun,": 7}
EN_THRESH = 0.75
MAX_DIST = 100000
MIN_NUM_VALUES = 10
PROFILE_THRESHOLD = 100
MIN = 0.00001
SUB_THRESH = 4
TOTAL_FEATURES = 15

static_dir_senderprofile = STATICFILES_DIRS[0] + '/panacea/senderprofile/'


#static_dir_senderprofile = 'data/'

def func_convert_HKEY_tolower(HKEY):
    s = str(HKEY).lower()
    return ast.literal_eval(s)


def geoIP(ip):
    # print(ip)
    req = {
        "investigation-type": "geo-location",  # or "domain-reputation" or "dns-lifetime"
        "domain-name": "google.com",
        "api-key": "NA",
        "ip-address": ip
    }
    # req ={
    #     "investigation-type" : "geo-location",
    #     "api-key" : "NA",
    #     "ip" : ip
    # }
    res = investigate_using_db(req)
    '''
    The output for "geo-location":
    {
        "status": "success",
        "description": "Data successfully received.",
        "data": {
            "geo": {
                "host": "169.254.8.177",
                "ip": "169.254.8.177",
                "rdns": "169.254.8.177",
                "asn": "",
                "isp": "",
                "country_name": "",
                "country_code": "",
                "region_name": "",
                "region_code": "",
                "city": "",
                "postal_code": "",
                "continent_name": "",
                "continent_code": "",
                "latitude": "",
                "longitude": "",
                "metro_code": "",
                "timezone": "",
                "datetime": ""
            }
        }
    }
    '''
    # geoLoc = {"country": "USA", "region": "NC", "city": "Charlotte"}
    geo_loc = res['data']['geo']
    country = ''
    state = ''
    city = ''
    if 'country_name' in geo_loc:
        country = geo_loc['country_name']
    if 'region_name' in geo_loc:
        state = geo_loc['region_name']
    if 'city' in geo_loc:
        city = geo_loc['city']
    return country + '#' + state + '#' + city


def extract_domain(dom_str):
    dom = 'empty'
    dom_ext = ''
    prefix = dom_str.split('@')
    if len(prefix) > 1:
        dom_ext = prefix[len(prefix) - 1]
    else:
        dom_ext = dom_str
    dom_parts = dom_ext.split('.')
    # print(dom_parts)
    parts_len = len(dom_parts)
    # print(dom_parts[parts_len-2])
    # print(dom_parts[parts_len-1])
    if len(dom_parts) >= 2:
        dom = dom_parts[parts_len - 2] + '.' + dom_parts[parts_len - 1]
        # print(dom)
    return dom


def dict_merge(dict1, dict2, total1, total2):
    for key, value in dict2.items():
        if key in dict1:
            dict1.update({key: (value * total2 + dict1[key] * total1) / (total1 + total2)})
        else:
            dict1.update({key: (value * total2) / (total1 + total2)})
    for key, value in dict1.items():
        if key not in dict2:
            dict1.update({key: (value * total1) / (total1 + total2)})
            # return dict1


def average(data_dict, total_count):
    for item, value in data_dict.items():
        data_dict.update({item: value / total_count})
        # return data_dict


def write_distri(data_dict, f_distri):
    # print(data_dict)
    f_distri.write(json.dumps(data_dict, indent=None))
    f_distri.write('\n')


def read_time(m):
    if m:
        time = m.group(0)
        zone_time = time.split(' ')[0]
        zone = time.split(' ')[1]
        hour = zone_time.split(':')[0]
        minute = zone_time.split(':')[1]
        second = zone_time.split(':')[2]
        # print( int(zone)/100 )
        universal_time = int(minute) * 60 + int(second) + ((int(hour) - int(zone) / 100)) * 3600
        # print(universal_time)
        return universal_time
    else:
        return 0


# entropy
def entropy(hist):
    sum = 0.0
    for key, value in hist.items():
        value_float = float(value)
        # print(value_float)
        if value_float > 0:
            sum += (- value_float * np.log(value_float))
            # print(sum)
    return sum


def insert(item, item_dict):
    fre = 0
    if item in item_dict:
        fre = item_dict.get(item)
        fre += 1  # ((fre *total) + 1 )/(total + 1)

    else:
        fre = 1
    item_dict.update({item: fre})


def read_address(add, head):
    address = ''
    if add in head:
        item = head[add]
        m = re.search('([a-zA-Z0-9+._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)', item[0])
        if m:
            address = m.group(0)
        else:
            address = ''
    return address


def read_reply(head):
    reply = 'empty'
    if 'reply-to' in head:
        item = head['reply-to']
        m = re.search('([a-zA-Z0-9+._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)', item[0])
        if m:
            reply = extract_domain(m.group(0))
    return reply


def read_spf(head):
    spf = 'empty'
    if 'received-spf' in head:
        item = head['received-spf'][0]
        word_list = item.split()
        if len(word_list) > 0:
            spf = word_list[0]
    return spf


def rindex(lst, val):
    try:
        return next(len(lst) - i for i, e in enumerate(reversed(lst), start=1) if e == val)
    except StopIteration:
        raise ValueError('{} is not in list'.format(val))


def read_originator(head):
    originator = 'empty'
    if 'received' in head:
        item = head['received'][0].lower()
        word_list = item.split()
        # print(word_list)
        if len(word_list) > 0:
            if 'from' in word_list:
                index = rindex(word_list, 'from')

                # print(index)
                originator = extract_domain(word_list[index + 1])
                # originator =  word_list[index+1]

    return originator


def read_dmarc(head):
    dmarc = 'empty'
    if 'authentication-results' in head:
        item = head['authentication-results'][0].lower()
        word_list = item.split()
        for word in word_list:
            if word.startswith('dmarc'):
                equal_parts = word.split("=")
                if len(equal_parts) > 0:
                    dmarc = equal_parts[1]
    if (dmarc == ''):
        dmarc = 'empty'
    return dmarc


def read_hour(date):
    send_hour = 'empty'
    m1 = re.search('\d{2}:\d{2}:\d{2}', date)
    if m1:
        hour_min_sec = m1[0].split(' ')[0]
        hour = hour_min_sec.split(':')[0]
        if (int(hour) >= 8 and int(hour) <= 20):
            send_hour = 'day'
        else:
            send_hour = 'night'
    return send_hour


# rakeb
# this function will take a request:
#     {
#       "req-id": request ID,
#       "number-of-header": n,
#       "header-list": [{header 1 as json object}, {header 2 as json object}, ... , {header n as json object}]
#     }
# and response whatever it should

def start_profiling(request):
    header_list = request['header-list']

    elist = []
    for head in header_list:
        from_address = read_address('from', head)
        to_address = read_address('to', head)

        if from_address == '' or to_address == '':
            continue
        elist.append(from_address.lower() + '-' + to_address.lower())

    file_num = 0
    cnt = Counter(elist)
    add_file = {}

    for key, value in cnt.items():

        file_num += 1

        # dict_fname = static_dir_senderprofile + 'dict' + str(file_num) + '.txt'
        dict_fname = static_dir_senderprofile + key
        # dict_fname = dict_fname.replace()
        add_file[key] = dict_fname

        total = 0
        feature_list_dict = []
        for i in range(TOTAL_FEATURES):
            feature_list_dict.append({})

        for head in header_list:
            from_address = ''
            to_address = ''

            from_address = read_address('from', head)
            to_address = read_address('to', head)

            if from_address == '' or to_address == '':
                break
            pair = from_address.lower() + '-' + to_address.lower()

            if key == pair:
                total += 1

                send_time = 0
                send_day = ''
                send_hour = ''
                rec_time = 0
                path_len = 0
                delay = 0
                user_agent = ''
                xmailer = ''
                ref = ''
                message_id = ''
                return_path = ''
                sub_len = 0
                geo = ''
                spf = ''
                reply = ''
                dmarc = ''
                originator = ''

                if 'date' in head:
                    date_item = head['date'][0]

                    m2 = date_item.split(' ')
                    day = m2[0]
                    # print(day)
                    if (day in mydict):
                        day_index = mydict[day]

                        if (day_index <= 5):
                            send_day = 'weekday'
                        else:
                            send_day = 'weekend'
                    else:
                        send_day = 'empty'

                    send_hour = read_hour(date_item)

                    m3 = re.search('\d{2}:\d{2}:\d{2}( (-|\+)\d{4})', date_item)
                    # print(m3.group(0))
                    if m3:
                        rec_time = read_time(m3)
                    else:
                        rec_time = 0

                else:
                    send_day = 'empty'
                    send_hour = 'empty'

                if 'received' in head:
                    rec_item = head['received'][0]
                    m1 = re.findall('\d{2}:\d{2}:\d{2}( (-|\+)\d{4})', rec_item)

                    if m1:
                        path_len = len(m1)
                        m2 = re.search('\d{2}:\d{2}:\d{2}( (-|\+)\d{4})', rec_item)
                        send_time = read_time(m2)

                    else:
                        send_time = 0
                        path_len = 0
                    m3 = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', rec_item)
                    if m3:
                        # geo = geoIP(m3.group(0))
                        geo = ''

                else:
                    send_time = 0
                    path_len = 0
                if 'user-agent' in head:
                    user_agent = head['user-agent'][0]
                else:
                    user_agent = 'empty'
                if 'message-id' in head:
                    message_id_item = read_address('message-id', head)
                    m2 = re.search('@((\w|\w[\w\-]*?\w)\.\w+)', message_id_item)
                    if m2:
                        # message_id = m2.group(1)
                        # print(message_id)
                        message_id = extract_domain(message_id_item.lower())
                        # print(message_id)
                    else:
                        message_id = 'empty'
                else:
                    message_id = 'empty'

                if 'references' in head:
                    ref_item = read_address('references', head)
                    m2 = re.search('@((\w|\w[\w\-]*?\w)\.\w+)', ref_item)
                    if m2:
                        # ref = m2.group(1)
                        ref = extract_domain(ref_item.lower())
                    else:
                        ref = 'empty'
                else:
                    ref = 'empty'

                if 'return-path' in head:
                    return_path_item = read_address('return-path', head)
                    m2 = re.search('@((\w|\w[\w\-]*?\w)\.\w+)', return_path_item)
                    if m2:
                        # ref = m2.group(1)
                        return_path = extract_domain(return_path_item.lower())
                    else:
                        return_path = 'empty'
                else:
                    return_path = 'empty'

                if 'x-mailer' in head:
                    xmailer = head['x-mailer'][0]

                else:
                    xmailer = 'empty'

                if 'subject' in head:
                    subject_item = head['subject'][0]
                    tokens = subject_item.split()
                    sub_len_num = len(tokens)
                else:
                    sub_len_num = 0
                if sub_len_num <= SUB_THRESH:
                    sub_len = 'short'
                else:
                    sub_len = 'long'

                if (send_time != 0 and rec_time != 0):
                    delay = int(rec_time - send_time)
                    if delay > 100:
                        delay = 100
                    elif delay < -100:
                        delay = -100

                    delay = int(delay / 10)

                else:
                    delay = 0

                reply = read_reply(head)
                spf = read_spf(head)
                originator = read_originator(head)
                dmarc = read_dmarc(head)

                path_len_str = str(path_len)
                delay_str = str("0")
                sub_len_str = str(sub_len)

                insert('empty', feature_list_dict[0])
                insert('empty', feature_list_dict[1])
                insert(delay_str, feature_list_dict[2])
                insert(path_len_str, feature_list_dict[3])
                insert(xmailer, feature_list_dict[4])
                insert(message_id, feature_list_dict[5])
                insert('empty', feature_list_dict[6])
                insert(user_agent, feature_list_dict[7])
                insert('0', feature_list_dict[8])
                insert(geo, feature_list_dict[9])
                insert(return_path, feature_list_dict[10])
                insert(reply, feature_list_dict[11])
                insert(spf, feature_list_dict[12])
                insert(originator, feature_list_dict[13])
                insert(dmarc, feature_list_dict[14])
        for i in range(TOTAL_FEATURES):
            average(feature_list_dict[i], total)

        # print(entropy_list)
        path = Path(dict_fname)
        old_total = 0
        # print(dict_fname)
        old_feature_dict = []
        for i in range(TOTAL_FEATURES):
            old_feature_dict.append({})
        if path.is_file():
            with open(dict_fname, 'r') as f_attr:
                index = 0
                for line_attr in f_attr:
                    # print(line_attr)
                    if index == 0:
                        old_total = int(line_attr)
                    elif index == 1:
                        old_coefficient = json.loads(line_attr)
                    else:
                        old_feature_dict[index - 2] = json.loads(line_attr)

                    index += 1
                    if index >= TOTAL_FEATURES + 2:
                        break
                for i in range(TOTAL_FEATURES):
                    dict_merge(feature_list_dict[i], old_feature_dict[i], total, old_total)

        entropy_list = []
        for i in range(TOTAL_FEATURES):
            entropy_list.append(entropy(feature_list_dict[i]))

        # print(entropy_list)
        # entropy_list = normalize(entropy_list)
        with open(dict_fname, 'w') as f2:
            f2.write(str(total + old_total) + '\n')
            # for i in range(len(entropy_list) ):
            f2.write(json.dumps(entropy_list, indent=None))
            f2.write('\n')
            for i in range(TOTAL_FEATURES):
                write_distri(feature_list_dict[i], f2)

            f2.close()
        for i in range(TOTAL_FEATURES):
            feature_list_dict[i].clear()

    return {
        "Status": 'OK'
    }


def get_fre(attr, attr_dict):
    if attr in attr_dict:
        fre = attr_dict[attr]
    else:
        fre = 0
    return fre


# rakeb
# this function will take a request:
#     {
#         "req-id": request ID,
#         "email-header": {email header as json object}
#     }
# and response whatever it should
def sender_testing(request, response):
    rule_result = response['rule-based']
    active_result = response['active-classification']
    rf_result = response['aggregate-classifier-(random-forest)']

    head = func_convert_HKEY_tolower(request['email-header'])

    from_address = ''
    to_address = ''
    from_address = read_address('from', head)
    to_address = read_address('to', head)
    # print(from_address)
    # print(to_address)
    if from_address == '' or to_address == '':
        return {
            "score": -1,
            "justification": "Not valid email:" + head['from'][0],
            "Status": "not valid email",
            "classification": 'N/A'
        }
    pair = from_address + '<' + to_address
    fname = static_dir_senderprofile + from_address.lower() + '-' + to_address.lower()

    if not Path(fname).is_file():
        if (rule_result['classification'] == 'Definitely' or active_result['classification'] == 'malicious' or
                rf_result['classification'] == 'phishing'):
            return {
                "score": -1,
                "justification": "Profile not Exist",
                "Status": "Profile not Exist",
                "classification": 'N/A'
            }
        else:
            header_list = []
            header_list.append(head)
            req = {"header-list": header_list}
            start_profiling(req)
            return {
                "score": -1,
                "justification": "First Time Sender: Add to Profile",
                "Status": "OK",
                "classification": 'N/A'
            }

    send_time = 0
    send_day = ''
    send_hour = ''
    rec_time = 0
    path_len = 0
    delay = 0
    user_agent = ''
    xmailer = ''
    ref = ''
    message_id = ''
    sub_len = 0
    return_path = ''
    geo = ''
    spf = ''
    reply = ''
    dmarc = ''
    originator = ''

    feature_list_dict = []
    for i in range(TOTAL_FEATURES):
        feature_list_dict.append({})

    if 'date' in head:
        date_item = head['date'][0]

        m2 = date_item.split(' ')
        day = m2[0]
        # print(day)
        if (day in mydict):
            day_index = mydict[day]

            if (day_index <= 5):
                send_day = 'weekday'
            else:
                send_day = 'weekend'
        else:
            send_day = 'empty'

        send_hour = read_hour(date_item)

        m3 = re.search('\d{2}:\d{2}:\d{2}( (-|\+)\d{4})', date_item)
        # print(m3.group(0))
        if m3:
            rec_time = read_time(m3)
        else:
            rec_time = 0

    else:
        send_day = 'empty'
        send_hour = 'empty'

    if 'received' in head:
        rec_item = head['received'][0]
        m1 = re.findall('\d{2}:\d{2}:\d{2}( (-|\+)\d{4})', rec_item)

        if m1:
            path_len = len(m1)
            m2 = re.search('\d{2}:\d{2}:\d{2}( (-|\+)\d{4})', rec_item)

            send_time = read_time(m2)

        else:
            send_time = 0
            path_len = 0
        m3 = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', rec_item)
        if m3:
            # geo = geoIP(m3.group(0))
            geo = ''
    else:
        send_time = 0
        path_len = 0
    if 'user-agent' in head:
        user_agent = head['user-agent'][0]
    else:
        user_agent = 'empty'
    if 'message-id' in head:
        message_id_item = read_address('message-id', head)
        m2 = re.search('@((\w|\w[\w\-]*?\w)\.\w+)', message_id_item)
        if m2:
            # message_id = m2.group(1)

            message_id = extract_domain(message_id_item.lower())
        else:
            message_id = 'empty'
    else:
        message_id = 'empty'

    if 'references' in head:
        ref_item = read_address('references', head)
        m2 = re.search('@((\w|\w[\w\-]*?\w)\.\w+)', ref_item)
        if m2:
            # ref = m2.group(1)
            ref = extract_domain(ref_item.lower())
        else:
            ref = 'empty'
    else:
        ref = 'empty'

    if 'return-path' in head:
        return_path_item = read_address('return-path', head)
        m2 = re.search('@((\w|\w[\w\-]*?\w)\.\w+)', return_path_item)
        if m2:
            # ref = m2.group(1)
            return_path = extract_domain(return_path_item.lower())
        else:
            return_path = 'empty'
    else:
        return_path = 'empty'

    if 'x-mailer' in head:
        xmailer = head['x-mailer'][0]

    else:
        xmailer = 'empty'

    if 'subject' in head:
        subject_item = head['subject'][0]
        tokens = subject_item.split()
        sub_len_num = len(tokens)
    else:
        sub_len_num = 0
    if sub_len_num <= SUB_THRESH:
        sub_len = 'short'
    else:
        sub_len = 'long'
    # print('sub_len'+str(sub_len))

    if (send_time != 0 and rec_time != 0):
        delay = int(rec_time - send_time)
        if delay > 100:
            delay = 100
        elif delay < -100:
            delay = -100

        delay = int(delay / 10)

    else:
        delay = 0

    reply = read_reply(head)
    spf = read_spf(head)
    originator = read_originator(head)
    dmarc = read_dmarc(head)
    delay = 0

    add_dict = {}

    total = 0

    coefficient = []
    value_count = []
    with open(fname, 'r') as f_attr:

        index = 0
        for line_attr in f_attr:
            # print(line_attr)
            if index == 0:
                total = int(line_attr)
            elif index == 1:
                coefficient = json.loads(line_attr)
            else:
                feature_list_dict[index - 2] = json.loads(line_attr)

                value_count.append(len(feature_list_dict[index - 2]))

                # attr_list.append(attr_dict)
            index += 1
            if index >= TOTAL_FEATURES + 2:
                break

    if total < PROFILE_THRESHOLD:


        header_list = []
        header_list.append(head)
        req = {"header-list": header_list}
        start_profiling(req)
        return {
            "score": -1,
            "justification": "Not sufficent profile, add to profile",
            "Status": "OK",
            "classification": 'N/A'
        }

    fre_list = []

    fre_list.append(get_fre('empty', feature_list_dict[0]))
    fre_list.append(get_fre('empty', feature_list_dict[1]))
    fre_list.append(get_fre(str(delay), feature_list_dict[2]))
    fre_list.append(get_fre(str(path_len), feature_list_dict[3]))

    fre_list.append(get_fre(xmailer, feature_list_dict[4]))
    fre_list.append(get_fre(message_id, feature_list_dict[5]))
    fre_list.append(get_fre('empty', feature_list_dict[6]))
    fre_list.append(get_fre(user_agent, feature_list_dict[7]))
    fre_list.append(get_fre('0', feature_list_dict[8]))
    fre_list.append(get_fre(geo, feature_list_dict[9]))
    fre_list.append(get_fre(return_path, feature_list_dict[10]))
    fre_list.append(get_fre(reply, feature_list_dict[11]))
    fre_list.append(get_fre(spf, feature_list_dict[12]))
    fre_list.append(get_fre(originator, feature_list_dict[13]))
    fre_list.append(get_fre(dmarc, feature_list_dict[14]))

    dist_original = 0
    dist_random = 0
    for i in range((len(fre_list))):
        if coefficient[i] < EN_THRESH or value_count[i] <= 10:
            if fre_list[i] > 0:
                dist_original += (-np.log(fre_list[i]))
            else:
                dist_original += MAX_DIST
        dist_random += np.log(value_count[i] + 1)

    # print(fre_list)
    score = 0.0
    justification = ''
    contribution = []
    for i in range(len(fre_list)):
        if coefficient[i] < EN_THRESH or value_count[i] <= 10:
            contribution.append(fre_list[i])
        else:
            contribution.append(1)
    small_index = contribution.index(min(contribution))
    justification_text_prefix = ['Send Weekday ', 'Send Daytime ', 'Sending Delay ', 'Receiver Path Length ',
                                 'X-Mailer ', 'Message_ID Domain ', 'References Domain ', 'User Agent ',
                                 'Subject Length ',
                                 'Sender Geo ',
                                 'Return Path ', 'Reply-To ', 'SPF ',
                                 'Originator (first received) ', 'dmarc ']
    first = 0
    for i in range(len(contribution)):
        if contribution[i] == 0:
            if first == 0:
                justification += justification_text_prefix[i]
                first = 1
            else:
                justification = justification + 'and ' + justification_text_prefix[i]
    if justification == '':
        justification = justification_text_prefix[small_index]

    classicification = ''
    if dist_original > dist_random:
        classicification = 'malicious'
        justification = justification + 'not comply with profile.'
        if (dist_random < MIN):
            score = 1
        else:
            score = min(dist_original / dist_random, 1)
    else:
        classicification = 'Normal'
        justification = 'Normal'
        score = dist_original / (2 * dist_random)

    # print(score)
    # print(justification)



    if justification == 'Normal':
        header_list = []
        header_list.append(head)
        req = {"header-list": header_list}
        start_profiling(req)
    return {
        "score": score,
        "classification": classicification,
        "justification": justification,
        "Status": "OK"
    }


if __name__ == '__main__':
    request = {
        "req-id": 1,
        "number-of-header": 4,
        "header-list": [
            {
                "Return-Path": "<postnett16@gmail.com>",
                "Received": "by 10.2.159.148 with HTTP; Sun, 31 Dec 2017 11:11:23 -0800 (PST)",
                "DKIM-Signature": "v=1; a=rsa-sha256; c=relaxed/relaxed;\n        d=gmail.com; s=20161025;\n        h=mime-version:reply-to:from:date:message-id:subject:to;\n        bh=+tb5NQTdmm4XItRSb7nKgyzr1IRMR3P15HfouJbfHW4=;\n        b=oJ1WXlEKNgMapjLSY5ja862I1WrxxNAgJd7E3ejDiRBV9YqyK25yy4aqHpxxpZ9TVM\n         Ig1WCQ4kSWdPjv5VweLYjZUmes2m4fthvTCNZe5ywOoBOsTrnds83yj+51Qf4hyv6MK7\n         R2c9Gwt/n/+flUkLLIWm15/KoTmOF264ISXPVoX37rpRoG83DQA6xqPyeBka4nzuhwr1\n         SsJw+Uo8koU1Uc/j8THmZ5lobqWQ8h3c+ZaLbfEA0fSgm/EolrozhyRWOekAXwQqJ1sv\n         s+gWfbSIOfE2u/4nubCgL4XPKrxEcG0p6plzptr2/ditmp2LFTruKWBKzu5UUumG1lLW\n         zeFA==",
                "X-Google-DKIM-Signature": "v=1; a=rsa-sha256; c=relaxed/relaxed;\n        d=1e100.net; s=20161025;\n        h=x-gm-message-state:mime-version:reply-to:from:date:message-id\n         :subject:to;\n        bh=+tb5NQTdmm4XItRSb7nKgyzr1IRMR3P15HfouJbfHW4=;\n        b=jm6D/c4CzrYOOtQ1zns8kH9WzXJ3JlzIaDSA2NKbhdasozJ0IwMwytaCtXMw7+d8mG\n         O1BRqlqWsQgxcAsCdAZtO8AUzkE8K50y+Gs+8zDFCqMbx3fJz4KqRPSBXLAP5K1mnbRS\n         dJ7VTQOE9EOTLEExjKqwwlc6+52asH8GrFuzTf/wxnjPPyoKFqvLYzRjLhxLe7liMOf1\n         +XhRze8opTI2gtpEM8L5+ZSXhc+kPo7SMsr9pJyUscj0FyolQqEiQK598lpJeUHdR/tI\n         Y31BYEwo1hrhZ1XvNnB55NU5FcsRjr6tmEhk/GawpSwt+Gt1vrww+rjCtDwLFd2xza7k\n         0Uuw==",
                "X-Gm-Message-State": "AKGB3mKmk3yoWJauyXMgmV/G42IFY9zv2t4IkoH2xv9Cylu+5ZeX8Arj\n\t6sUzcAkKH8vaqb7ElDE2sROKHGyweuEpIzUJzmk=",
                "X-Google-Smtp-Source": "ACJfBovGDHF5ZZuhUIu6Cwk5Qj/ThiycrRLKknBd4qUIUNK/gqohP4qSwlLPZMBwqcQY1aRwQVh+whoUjr4bRngWBs8=",
                "X-Received": "by 10.107.81.6 with SMTP id f6mr28377175iob.20.1514747484044; Sun,\n 31 Dec 2017 11:11:24 -0800 (PST)",
                "MIME-Version": "1.0", "Reply-To": "aa1@mail.com",
                "From": "<aa1@gmail.com>",
                "Date": "Sun, 31 Dec 2017 21:11:23 +0200",
                "Subject": "FIND MY SIB ANDA",
                "To": "<uuu@gmail.com>",
                "Content-Type": "multipart/mixed; boundary=089e0825a7a0b63ed80561a7a103",
                "x-aol-global-disposition": "S", "X-AOL-VSS-INFO": "5800.7501/124996",
                "X-AOL-VSS-CODE": "clean",
                "X-AOL-SCOLL-AUTHENTICATION": "mtaiw-aaj08.mx.aol.com ; domain : gmail.com DKIM : pass",
                "X-AOL-SCOLL-DMARC": "mtaiw-aaj08.mx.aol.com ; domain : gmail.com ; policy : none ; result : P",
                "Authentication-Results": "mx.aol.com;\n\tspf=pass (aol.com: the domain gmail.com reports 209.85.223.195 as a permitted sender.) smtp.mailfrom=gmail.com;\n\tdkim=pass (aol.com: email passed verification from the domain gmail.com.) header.i=@gmail.com;\n\tdmarc=pass (aol.com: the domain gmail.com reports that Both SPF and DKIM strictly align.) header.from=gmail.com;",
                "X-AOL-REROUTE": "YES", "x-aol-sid": "3039ac1b03c55a49365c5078", "X-AOL-IP": "209.85.223.195",
                "X-AOL-SPF": "domain : gmail.com SPF : pass",
                "Message-ID": "dshjdhs@sasa.com",
                "References": "b@ccc.com",
                "User-Agent": "bda dsa",
                "X-Mailer": "aassa"},
            {"Return-Path": "<return@academia.edu>",
             "Received": "from hastavidafi.com (hastavidafi.com. [173.82.177.231])\n        by mx.google.com with ESMTP id k33si32168844pld.22.2017.12.31.15.52.29\n        for <trblake@gmail.com>;\n        Sun, 31 Dec 2017 15:52:29 -0800 (PST)",
             "Received-SPF": "softfail (google.com: domain of transitioning return@academia.edu does not designate 173.82.177.231 as permitted sender) client-ip=173.82.177.231;",
             "Authentication-Results": "mx.google.com;\n       dkim=pass header.i=@hastavidafi.com header.s=default header.b=22xBc5jN;\n       spf=softfail (google.com: domain of transitioning return@academia.edu does not designate 173.82.177.231 as permitted sender) smtp.mailfrom=return@academia.edu",
             "DKIM-Signature": "v=1; a=rsa-sha1; c=relaxed/relaxed; s=default; d=hastavidafi.com;\n h=List-Unsubscribe:From:Date:Subject:To:Message-Id:Content-Type:Content-Transfer-Encoding; i=1Qn2114re701J6c8ijH@7IT87H1R3yks7HY3061.hastavidafi.com;\n bh=nTxOTzstHioOKjaatigYIaQodNs=;\n b=22xBc5jNpA52c1cZ2c9FYd9gjjo4KIg8i1XShfEHsBuUUg6+ys3nldv19Q1VuFTeAVxxRaWkPpRa\n   M1DtHYsjWZIdwdMmV3DudBIEG/k97jKBvDG53kp30ZTzT/pp0lcWIxQ2PB+CGHiooA7eQb3h4+5z\n   8VEIix4RH08mPAl1+dI=",
             "DomainKey-Signature": "a=rsa-sha1; c=nofws; q=dns; s=default; d=hastavidafi.com;\n b=T2/LxPeJ3fFntl3lDjZY9ojpKD3KGOoHxR0EPtNMixzgA2sjZuT8G8dvk/m4In5wWe+z+jEZ/qhr\n   I926Pf1wDEWCCf2puBAh3xYvatXyKoCtFAqipLaJBjtLu6uqb3JC2czgY/owUJC0ZGo8fq7gXLGT\n   R3n9OrpRVrjpBeKhoxU=;",
             "List-Unsubscribe": "<4NQC20m453CYJo32P48-64Tg1N209T8211IFaZJ@hastavidafi.com>",
             "From": "<aa2@7IT87H1R3yks7HY3061.hastavidafi.com>",
             "Date": "Sun, 31 Dec 2017 15:53:18 -0800 (PDT)",
             "Subject": "=?UTF-8?B?TGV 0IGJ lIE 5hdWdo  dHkgdGhpcyBDaHJpc3RtYXM=?=",
             "To": "<uuu@gmail.com>",
             "Message-Id": "<7joz19dyIWVY9562294-7Wt4X6QMfVDe0274223@hastavidafi.com>",
             "X-EMMAIL": "trblake@hastavidafi.com", "Content-Type": "text/html; charset=utf-8",
             "Content-Transfer-Encoding": "base64",
             "Message-ID": "dshjdhs@bbb.com",
             "References": "a@ddd.com",
             "X-Mailer": "ffsa"},
            {"Return-Path": "<postnett16@gmail.com>",
             "Received": "by 10.2.159.148 with HTTP; Sun, 31 Dec 2017 11:11:23 -0800 (PST)",
             "DKIM-Signature": "v=1; a=rsa-sha256; c=relaxed/relaxed;\n        d=gmail.com; s=20161025;\n        h=mime-version:reply-to:from:date:message-id:subject:to;\n        bh=+tb5NQTdmm4XItRSb7nKgyzr1IRMR3P15HfouJbfHW4=;\n        b=oJ1WXlEKNgMapjLSY5ja862I1WrxxNAgJd7E3ejDiRBV9YqyK25yy4aqHpxxpZ9TVM\n         Ig1WCQ4kSWdPjv5VweLYjZUmes2m4fthvTCNZe5ywOoBOsTrnds83yj+51Qf4hyv6MK7\n         R2c9Gwt/n/+flUkLLIWm15/KoTmOF264ISXPVoX37rpRoG83DQA6xqPyeBka4nzuhwr1\n         SsJw+Uo8koU1Uc/j8THmZ5lobqWQ8h3c+ZaLbfEA0fSgm/EolrozhyRWOekAXwQqJ1sv\n         s+gWfbSIOfE2u/4nubCgL4XPKrxEcG0p6plzptr2/ditmp2LFTruKWBKzu5UUumG1lLW\n         zeFA==",
             "X-Google-DKIM-Signature": "v=1; a=rsa-sha256; c=relaxed/relaxed;\n        d=1e100.net; s=20161025;\n        h=x-gm-message-state:mime-version:reply-to:from:date:message-id\n         :subject:to;\n        bh=+tb5NQTdmm4XItRSb7nKgyzr1IRMR3P15HfouJbfHW4=;\n        b=jm6D/c4CzrYOOtQ1zns8kH9WzXJ3JlzIaDSA2NKbhdasozJ0IwMwytaCtXMw7+d8mG\n         O1BRqlqWsQgxcAsCdAZtO8AUzkE8K50y+Gs+8zDFCqMbx3fJz4KqRPSBXLAP5K1mnbRS\n         dJ7VTQOE9EOTLEExjKqwwlc6+52asH8GrFuzTf/wxnjPPyoKFqvLYzRjLhxLe7liMOf1\n         +XhRze8opTI2gtpEM8L5+ZSXhc+kPo7SMsr9pJyUscj0FyolQqEiQK598lpJeUHdR/tI\n         Y31BYEwo1hrhZ1XvNnB55NU5FcsRjr6tmEhk/GawpSwt+Gt1vrww+rjCtDwLFd2xza7k\n         0Uuw==",
             "X-Gm-Message-State": "AKGB3mKmk3yoWJauyXMgmV/G42IFY9zv2t4IkoH2xv9Cylu+5ZeX8Arj\n\t6sUzcAkKH8vaqb7ElDE2sROKHGyweuEpIzUJzmk=",
             "X-Google-Smtp-Source": "ACJfBovGDHF5ZZuhUIu6Cwk5Qj/ThiycrRLKknBd4qUIUNK/gqohP4qSwlLPZMBwqcQY1aRwQVh+whoUjr4bRngWBs8=",
             "X-Received": "by 10.107.81.6 with SMTP id f6mr28377175iob.20.1514747484044; Sun,\n 31 Dec 2017 11:11:24 -0800 (PST)",
             "MIME-Version": "1.0", "Reply-To": "aa1@mail.com",
             "From": "<aa2@7IT87H1R3yks7HY3061.hastavidafi.com>",
             "Date": "Sun, 31 Dec 2017 21:11:23 +0200",
             "Subject": "FIND MY ATTACHED LETTER FROM MRS MARIA SIBANDA & REPLY TO ME +27781779673",
             "To": "<uuu@gmail.com>",
             "Content-Type": "multipart/mixed; boundary=089e0825a7a0b63ed80561a7a103",
             "x-aol-global-disposition": "S", "X-AOL-VSS-INFO": "5800.7501/124996",
             "X-AOL-VSS-CODE": "clean",
             "X-AOL-SCOLL-AUTHENTICATION": "mtaiw-aaj08.mx.aol.com ; domain : gmail.com DKIM : pass",
             "X-AOL-SCOLL-DMARC": "mtaiw-aaj08.mx.aol.com ; domain : gmail.com ; policy : none ; result : P",
             "Authentication-Results": "mx.aol.com;\n\tspf=pass (aol.com: the domain gmail.com reports 209.85.223.195 as a permitted sender.) smtp.mailfrom=gmail.com;\n\tdkim=pass (aol.com: email passed verification from the domain gmail.com.) header.i=@gmail.com;\n\tdmarc=pass (aol.com: the domain gmail.com reports that Both SPF and DKIM strictly align.) header.from=gmail.com;",
             "X-AOL-REROUTE": "YES", "x-aol-sid": "3039ac1b03c55a49365c5078", "X-AOL-IP": "209.85.223.195",
             "X-AOL-SPF": "domain : gmail.com SPF : pass",
             "Message-ID": "dshjdhs@sasa.com",
             "References": "b@ccc.com",
             "User-Agent": "bdadsa sdad",
             "X-Mailer": "aassa"},
            {"Return-Path": "<return@academia.edu>",
             "Received": "from hastavidafi.com (hastavidafi.com. [173.82.177.231])\n        by mx.google.com with ESMTP id k33si32168844pld.22.2017.12.31.15.52.29\n        for <trblake@gmail.com>;\n        Sun, 31 Dec 2017 15:52:29 -0800 (PST)",
             "Received-SPF": "softfail (google.com: domain of transitioning return@academia.edu does not designate 173.82.177.231 as permitted sender) client-ip=173.82.177.231;",
             "Authentication-Results": "mx.google.com;\n       dkim=pass header.i=@hastavidafi.com header.s=default header.b=22xBc5jN;\n       spf=softfail (google.com: domain of transitioning return@academia.edu does not designate 173.82.177.231 as permitted sender) smtp.mailfrom=return@academia.edu",
             "DKIM-Signature": "v=1; a=rsa-sha1; c=relaxed/relaxed; s=default; d=hastavidafi.com;\n h=List-Unsubscribe:From:Date:Subject:To:Message-Id:Content-Type:Content-Transfer-Encoding; i=1Qn2114re701J6c8ijH@7IT87H1R3yks7HY3061.hastavidafi.com;\n bh=nTxOTzstHioOKjaatigYIaQodNs=;\n b=22xBc5jNpA52c1cZ2c9FYd9gjjo4KIg8i1XShfEHsBuUUg6+ys3nldv19Q1VuFTeAVxxRaWkPpRa\n   M1DtHYsjWZIdwdMmV3DudBIEG/k97jKBvDG53kp30ZTzT/pp0lcWIxQ2PB+CGHiooA7eQb3h4+5z\n   8VEIix4RH08mPAl1+dI=",
             "DomainKey-Signature": "a=rsa-sha1; c=nofws; q=dns; s=default; d=hastavidafi.com;\n b=T2/LxPeJ3fFntl3lDjZY9ojpKD3KGOoHxR0EPtNMixzgA2sjZuT8G8dvk/m4In5wWe+z+jEZ/qhr\n   I926Pf1wDEWCCf2puBAh3xYvatXyKoCtFAqipLaJBjtLu6uqb3JC2czgY/owUJC0ZGo8fq7gXLGT\n   R3n9OrpRVrjpBeKhoxU=;",
             "List-Unsubscribe": "<4NQC20m453CYJo32P48-64Tg1N209T8211IFaZJ@hastavidafi.com>",
             "From": "<aa1@gmail.com>",
             "Date": "Sun, 31 Dec 2017 15:53:18 -0800 (PDT)",
             "Subject": "=?UTF-8?B?TGV0IGJlIE5hdWdodHkgdGhpcyBDaHJpc3RtYXM=?=",
             "To": "<uuu@gmail.com>",
             "Message-Id": "<7joz19dyIWVY9562294-7Wt4X6QMfVDe0274223@hastavidafi.com>",
             "X-EMMAIL": "trblake@hastavidafi.com", "Content-Type": "text/html; charset=utf-8",
             "Content-Transfer-Encoding": "base64",
             "Message-ID": "dshjdhs@bbb.com",
             "References": "a@ddd.com",
             "X-Mailer": "ffsa"}]
    }

    # response = start_profiling(request)

    request1 = {
        "req-id": 1,
        "number-of-header": 2,
        "email-header": {"Return-Path": "<postnett16@gmail.COM>",
                         "Received": "by from gmail.com with HTTP; Mon, 31 Dec 2017 11:11:23 -0800 (PST) by 10.2.159.148 with HTTP; Sun, 31 Dec 2017 11:11:23 -0800 (PST)",
                         "DKIM-Signature": "v=1; a=rsa-sha256; c=relaxed/relaxed;\n        d=gmail.com; s=20161025;\n        h=mime-version:reply-to:from:date:message-id:subject:to;\n        "
                                           "bh=+tb5NQTdmm4XItRSb7nKgyzr1IRMR3P15HfouJbfHW4=;\n        b=oJ1WXlEKNgMapjLSY5ja862I1WrxxNAgJd7E3ejDiRBV9YqyK25yy4aqHpxxpZ9TVM\n       "
                                           "  Ig1WCQ4kSWdPjv5VweLYjZUmes2m4fthvTCNZe5ywOoBOsTrnds83yj+51Qf4hyv6MK7\n         R2c9Gwt/n/+flUkLLIWm15/KoTmOF264ISXPVoX37rpRoG83DQA6xqPyeBka4nzuhwr1\n      "
                                           "   SsJw+Uo8koU1Uc/j8THmZ5lobqWQ8h3c+ZaLbfEA0fSgm/EolrozhyRWOekAXwQqJ1sv\n         s+gWfbSIOfE2u/4nubCgL4XPKrxEcG0p6plzptr2/ditmp2LFTruKWBKzu5UUumG1lLW\n   "
                                           "      zeFA==",
                         "X-Google-DKIM-Signature": "v=1; a=rsa-sha256; c=relaxed/relaxed;\n        d=1e100.net; s=20161025;\n        h=x-gm-message-state:mime-version:reply-to:from:date:message-id\n         :subject:to;\n        bh=+tb5NQTdmm4XItRSb7nKgyzr1IRMR3P15HfouJbfHW4=;\n        b=jm6D/c4CzrYOOtQ1zns8kH9WzXJ3JlzIaDSA2NKbhdasozJ0IwMwytaCtXMw7+d8mG\n         O1BRqlqWsQgxcAsCdAZtO8AUzkE8K50y+Gs+8zDFCqMbx3fJz4KqRPSBXLAP5K1mnbRS\n         dJ7VTQOE9EOTLEExjKqwwlc6+52asH8GrFuzTf/wxnjPPyoKFqvLYzRjLhxLe7liMOf1\n         +XhRze8opTI2gtpEM8L5+ZSXhc+kPo7SMsr9pJyUscj0FyolQqEiQK598lpJeUHdR/tI\n         Y31BYEwo1hrhZ1XvNnB55NU5FcsRjr6tmEhk/GawpSwt+Gt1vrww+rjCtDwLFd2xza7k\n         0Uuw==",
                         "X-Gm-Message-State": "AKGB3mKmk3yoWJauyXMgmV/G42IFY9zv2t4IkoH2xv9Cylu+5ZeX8Arj\n\t6sUzcAkKH8vaqb7ElDE2sROKHGyweuEpIzUJzmk=",
                         "X-Google-Smtp-Source": "ACJfBovGDHF5ZZuhUIu6Cwk5Qj/ThiycrRLKknBd4qUIUNK/gqohP4qSwlLPZMBwqcQY1aRwQVh+whoUjr4bRngWBs8=",
                         "X-Received": "by 10.107.81.6 with SMTP id f6mr28377175iob.20.1514747484044; S",
                         "MIME-Version": "1.0", "Reply-To": "aa21@mail.ew.com",
                         "From": "ew ew <no-reply@m.mail.coursera.org>",
                         "Date": "Mon, 31 Dec 2017 22:11:23",
                         "Subject": "FIND dw",
                         "To": "qi duan <qiduan@gmail.com>",
                         "Content-Type": "multipart/mixed; boundary=089e0825a7a0b63ed80561a7a103",
                         "x-aol-global-disposition": "S", "X-AOL-VSS-INFO": "5800.7501/124996",
                         "X-AOL-VSS-CODE": "clean",
                         "X-AOL-SCOLL-AUTHENTICATION": "mtaiw-aaj08.mx.aol.com ; domain : gmail.com DKIM : pass",
                         "X-AOL-SCOLL-DMARC": "mtaiw-aaj08.mx.aol.com ; domain : gmail.com ; policy : none ; result : P",
                         "Authentication-Results": "mx.aol.com;\n\tspf=neutral (aol.com: the domain gmail.com reports 209.85.223.195 as a permitted sender.)"
                                                   " smtp.mailfrom=gmail.com;\n\tdkim=pass (aol.com: email passed verification from the domain gmail.com.) "
                                                   "header.i=@gmail.com;\n\tdmarc=neutral (aol.com: the domain gmail.com reports that Both SPF and DKIM strictly align.) header.from=gmail.com;",
                         "X-AOL-REROUTE": "YES", "x-aol-sid": "3039ac1b03c55a49365c5078", "X-AOL-IP": "209.85.223.195",
                         "X-AOL-SPF": "domain : gmail.com SPF : pass",
                         "Message-ID": "<dshj@dsdewe.gmail.cm>",
                         "References": "<wew@ew.com>",
                         "User-Agent": "dssdsrerere",
                         "X-Mailer": "43",
                         "Received-SPF": "pass"}
    }

    res = {"rule-based": {"classification": "likely"}, "active-classification": {"classification": "Normal"},
           "aggregate-classifier-(random-forest)": {"classification": "benign"}}
    header = request1['email-header']
    header1 = {}
    for key, value in header.items():
        header1[key] = [header[key],""]
    req2 = {}
    req2['email-header'] = header1
    out = sender_testing(req2, res)
    print(out)
