import ast
import collections
import email
import json
import pickle
import re
from email.utils import parsedate_to_datetime
from operator import itemgetter

from datetime import datetime

# import publicsuffix
from Utility import FILE_ROOT

anti_phishing_dom = ['@apwg.org', '@antiphishing.org', '@ecrimex.net', '@apwgmta.apwg.net', 'Void']
standard_HKEYS = [x.lower() for x in list(set(['Return-Path', 'Delivered-To', 'Authentication-Results', 'DKIM-Signature', 'X-YMail-OSG',
                            'Received', 'From', 'Content-Type', 'Content-Transfer-Encoding', 'Mime-Version', 'Date',
                            'Subject',
                            'Message-Id', 'References', 'To', 'X-Mailer', 'X-BESS-ID', 'X-BESS-VER',
                            'X-BESS-Apparent-Source-IP',
                            'Content-Type', 'Content-Transfer-Encoding', 'Content-Disposition', 'Return-Path',
                            'Delivered-To',
                            'Authentication-Results', 'Received', 'Date', 'From', 'Reply-To', 'Message-ID', 'Subject',
                            'MIME-Version', 'Content-Type',
                            'Content-Transfer-Encoding', 'X-eC-messenger-mid', 'List-Id', 'X-eC-messenger-cid',
                            'X-eC-messenger-token',
                            'X-Route-Id', 'List-Unsubscribe', 'X-eC-messenger-sender-domain',
                            'X-eC-messenger-sendouttypeid',
                            'X-eC-messenger-addresseeroleid', 'X-eC-messenger-recipienttypeid', 'List-Help',
                            'X-CSA-Complaints',
                            'X-Mailer', 'X-eC-messenger-email', 'X-BESS-ID', 'X-BESS-VER',
                            'X-BESS-Apparent-Source-IP']))]
authentication_HKEYS = [x.lower() for x in
                        ['ARC-Seal', 'ARC-Message-Signature', 'ARC-Authentication-Results', 'Received-SPF',
                         'Authentication-Results',
                         'DKIM-Signature', 'X-Google-DKIM-Signature', 'X-Gm-Message-State',
                         'X-Original-Authentication-Results',
                         'x-microsof-antispam', 'x-exchange-antispam-report-test', 'x-microsof-antispam-prvs',
                         'x-exchange-antispam-report-cfa-test',
                         'x-forefront-prvs', 'X-SG-EID', 'X-SG-ID', 'X-AOL-SCOLL-AUTHENTICATION', 'X-AOL-SCOLL-DMARC',
                         'X-AOL-SPF', 'X-AOL-VSS-CODE', 'X-MS-Exchange-Organization-MessageDirectionality',
                         'X-MS-Exchange-Organization-AuthSource',
                         'X-MS-Exchange-Organization-AuthAs', 'X-MS-Exchange-Organization-AuthMechanism',
                         'X-MS-Exchange-Organization-AVStamp-Mailbox',
                         'X-MS-TNEF-Correlator']]


def read_phishing_headers():
    # header_ph_fname = input("Enter the phishing email header file to import: ")
    header_ph_fname = FILE_ROOT + '/phishing.txt'
    headers = load_dict_from_file(header_ph_fname)
    # spam = load_dict_from_file('spam.txt')
    # headers =headers+spam
    header_ph = headers
    return header_ph, headers


def read_benign_headers():
    # header_b1_list, header_b1 = func_import_benign_data(static_dir_headerclassifier + "benign_header/benign.txt", "+++")
    # header_b2_list, header_b2 = func_import_benign_data(static_dir_headerclassifier + "benign_header/benign_gmail.txt",
    #                                                     "+++")
    # header_b3_list, header_b3 = func_import_benign_data(static_dir_headerclassifier + "benign_header/benign_qi.txt",
    #                                                     "+++")
    # header_b4_list, header_b4 = func_import_benign_data(static_dir_headerclassifier + "benign_header/benign_sash.txt",
    #                                                     "+++")
    header_b = load_dict_from_file(FILE_ROOT + '/benign_header/benign.txt')
    # header_b = header_b1 + header_b2 + header_b3 + header_b4 + header_b_jpl
    # del header_b1, header_b2, header_b3, header_b4
    return header_b


# def extract_unique_headers():
#     stdh_list = []
#     for instance in headers:
#         keys = instance.keys()
#         for element in keys:
#             stdh_list.append(element)
#     stdh_list_domain = func_elementCounter(stdh_list, len(stdh_list))
#     stdh_list_domain = func_sort_listOfTuples(stdh_list_domain, 1)
#     Weird_keys = stdh_list_domain[4220:]
#     Weird_keys = list(map(itemgetter(0), Weird_keys))
#     return stdh_list, stdh_list_domain, Weird_keys


def unify_stdh_list(stdh_list):
    stdh_list_norm = []
    for txt in stdh_list:
        txt = txt.lower()
        stdh_list_norm.append(func_clean(txt))
    return stdh_list_norm

def func_import_model(fname):
    return pickle.load(open(fname, 'rb'))

def init_all_global_variables():
    header_ph = func_import_model(FILE_ROOT + '\\init\\header_ph.pkl')
    headers = header_ph
    header_b = func_import_model(FILE_ROOT + '\\init\\header_b.pkl')
    Weird_keys = ['xxx', 'yyy']
    # header_ph, headers = read_phishing_headers()
    # header_b = read_benign_headers()
    # Weird_keys = ['xxx', 'yyy']
    # headers = func_convert_HKEY_tolower(headers)
    # header_b = func_convert_HKEY_tolower(header_b)
    # header_ph = func_convert_HKEY_tolower(header_ph)
    Message_IDs = cls_header.get_header_content(header_ph, 'message-id') + cls_header.get_header_content(header_b,
                                                                                                         'message-id')
    return header_ph, headers, header_b, Weird_keys, Message_IDs

def func_readfile(fname, separator):
    file = open(fname, 'r+')
    flist = file.read().split(sep=separator)
    file.close()
    return flist

def func_readfile_tolist(fname):
    file = open(fname, 'r+')
    flist = file.read().splitlines()
    file.close()
    return flist

def func_readfile_todict(fname):
    dicts_from_file = []
    with open(fname, 'r', encoding="ISO-8859-1") as inf:
        for line in inf:
            dicts_from_file.append(eval(line))
    return dicts_from_file

def func_readjfile(fname):
    with open(fname, 'r') as f:
        datastore = json.load(f)
    return datastore

def func_read_blacklist(fname):
    Blacklist = func_readfile_tolist(fname)
    Blacklist_cleaned = []
    for dmn in Blacklist:
        dmn = re.sub(";\d\d\d" or ";\d\d" or ";\d", "", dmn)
        dmn = re.sub(";\d", "", dmn)
        Blacklist_cleaned.append(dmn)
    return Blacklist_cleaned

def func_import_benign_data(fname, separator):
    input_list = func_readfile(fname, separator)
    Benign_headers = []
    for hdr in input_list:
        if hdr.startswith("\n"):
            try:
                # removes the TIME appears at the beggining of some emails
                hdr = re.sub(r'^\n\s\d\d:\d\d:\d\d\s-\d\d\d\d\s\W\w\w\w\W\n', "", hdr)
                hdr = re.sub(r'^\n', "", hdr)
            except:
                continue
        Benign_headers.append(hdr)
    Benign_headers = func_convertToMessageObj(Benign_headers)
    Benign_headers = filter(None, Benign_headers)
    Benign_headers = cls_header.get_header(Benign_headers)
    return input_list, Benign_headers

def save_to_file(lst, fname):
    with open(fname + '.txt', 'w') as f:
        for item in lst:
            item = list(item)
            f.write("%s\n" % item)

def save_tupleList_to_file(lst, fname):
    with open(fname + '.txt', 'w') as f:
        for item in list:
            item = list
            f.write("%s\n" % item)

def save_dict_to_file(dic, fname):
    f = open(fname, 'w')
    f.write(str(dic))
    f.close()


def load_dict_from_file(fname):
    f = open(fname, 'r', encoding="ISO-8859-1")
    data = f.read()
    f.close()
    return eval(data)


# Extracts multiple emails from a single file if needed.
# The most recent email will be removed since it is a report to anti phishing organization
# (this will be applied to the files even with one email)
def func_split_keepDel(delimiter, txt):
    txt = txt.split(delimiter)
    for e in range(len(txt)):
        txt[e] = delimiter + txt[e]
    return txt


def func_emailList_split(Email_lst, delimiter):
    lst = []
    for eml in range(len(Email_lst)):
        a = func_split_keepDel(delimiter, Email_lst[eml])
        del a[0]
        # del a[0]
        lst.append(a)
    lst = sum(lst, [])
    return lst


# find real and full headers
def func_findRealHeader(Email_headers, header_size_threshold=int):
    email_headers = []
    for eml in Email_headers:
        if len(eml) > header_size_threshold:
            email_headers.append(eml)
    return email_headers


# This should be changed in PANACEA_function. Copy and paste
def func_findDomain_fromtxt(txt):
    try:
        dmn = re.search("(?<=@)[^.]*.[^.]*(?=\.)", txt)
        dmn = dmn.group()
    except:
        dmn = ['Void']
        pass
    return dmn


def func_findDomain(txt_list):
    Domain_list = []
    indx = 0
    cntr = 0
    for txt in txt_list:
        try:
            dmn = re.search("@[\w.]+", txt)
            dmn = dmn.group()
            Domain_list.append(dmn)
        except:
            cntr += 1
            continue
        indx += 1
    return Domain_list


def func_findEmail_fromtxt(txt):
    return re.findall(r"[a-zA-Z0-9+._!#$%^&*()?/\|\-}{~;]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+", txt)
    #


def func_findTime_fromtxt(txt):
    return re.findall(r"\d\d:\d\d:\d\d", txt)


def func_elementCounter(lst, top=int):
    return collections.Counter(lst).most_common(top)


def func_sort_listOfTuples(lst, sorting_tuple_index=int, ):
    return sorted(lst, key=itemgetter(sorting_tuple_index), reverse=True)


def func_clean(txt):
    return re.sub(r'[()\"#/@;:<>{}`+=~|.!?,*&]', "", txt)


def func_read_email_obj(Path, Filelist):
    email_list = []
    for file in Filelist:
        try:
            with open(Path + file, 'r') as f:
                fin = f.read()
                f.close()
            email_list.append(fin)
        except:
            continue
    return email_list


def intersection(lst1, lst2):
    return list(set(lst1) & set(lst2))


def difference(lst1, lst2):
    return list(set(lst1) - set(lst2))


# Convert to Message object
def func_convertToMessageObj(Email_list):
    Messages = []
    for eml in Email_list:
        Messages.append(email.message_from_string(eml))
    return Messages


def func_convertToString(Email_list):
    Messages = []
    for eml in Email_list:
        Messages.append(eml.as_string())
    return Messages


# extract email headers
class cls_header():
    def get_header(Messages):
        Msg_headers = []
        for msg in Messages:
            Dict = {}
            m = list(map(list, msg._headers))
            for element in m:
                Dict[element[0]] = element[1]
            Msg_headers.append(Dict)
        return Msg_headers

    def get_header_content(Msg_headers, Content):
        Header_content = []
        i = 0
        indx = 0
        Header_content_indx = []
        for hdr in Msg_headers:
            try:
                Header_content.append(hdr[Content])
                Header_content_indx.append(indx)
                indx += 1
            except:
                i += 1
                continue
        return Header_content, Header_content_indx

    def filter_nonForwardedEmails(Msg_headers, Content1, Content2):
        filtered_email_list = []
        indx = 0
        for hdr in Msg_headers:
            if 'Subject' in hdr:
                if not hdr["Subject"].startswith('Fwd:'):
                    try:
                        if hdr[Content1] == hdr[Content2]:
                            filtered_email_list.append(hdr)
                    except:
                        continue
            indx += 1
        return filtered_email_list

    # find emails that are not sent to antiphishing emails
    def func_find_useful_header(Msg_headers):
        real_user_header = []
        for header in Msg_headers:
            try:
                if func_findDomain_fromtxt(header['To']) not in anti_phishing_dom:
                    real_user_header.append(header)
            except:
                continue
        return real_user_header


def func_check_blacklist(Header_list, Blacklist, Type_):
    Blacklisted = []
    for hdr in Header_list:
        try:
            if Type_ == "domain":
                if func_findDomain_fromtxt(hdr['From']) in Blacklist:
                    Blacklisted.append(func_findDomain_fromtxt(hdr['From']))
            elif Type_ == "sender":
                if func_findEmail_fromtxt(hdr['From']) in Blacklist:
                    Blacklisted.append(func_findEmail_fromtxt(hdr['From']))
        except:
            continue
    return Blacklisted


from dateutil import parser
def func_tolocaltime(DATETIME_STRING):
    loc_time = datetime.fromtimestamp(parsedate_to_datetime(DATETIME_STRING).timestamp()).strftime('%Y-%m-%d %H:%M:%S')
    loc_time_obj = parser.parse(loc_time)
    return loc_time_obj


# ---------------------------------------------------------------------------------------------Rules

# regex
# reg_email = re.compile("[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+")
reg_email = re.compile("[a-zA-Z0-9+._!#$%^&*()?/|\-}{~;]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+")
reg_date = re.compile("\d{1,2} \w\w\w \d\d\d\d")
reg_time = re.compile("\d\d:\d\d:\d\d")
reg_timezone = re.compile("[+-]\d{4}")
reg_IP = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[0-9]")
reg_SMTPID = re.compile("[a-zA-Z0-9]+\.+[a-zA-Z0-9]+\.+[a-zA-Z0-9]+\s")
reg_serverIP = re.compile("(?<=from )\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[0-9]")
reg_extension = re.compile("(?<=@[a-zA-Z0-9\.\-+_]\.)[a-z]+")
special_chars = re.compile('[@!#$%^&*()<>?/\|}{~;]')
reg_domain = re.compile("(?<=@)[^.]*.[^.]*(?=\.)")
reg_wholedate = re.compile("\w{3}, \d{1,2} \w\w\w \d\d\d\d \d\d:\d\d:\d\d [+-]\d{4}")
reg_datetime = re.compile("\d{1,2} \w\w\w \d\d\d\d \d\d:\d\d:\d\d [+-]\d{4}")
reg_domain2 = re.compile('(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]{2,6}')
reg_domain3 = re.compile('(([\da-zA-Z])([_\w-]{,62})\.){,127}(([\da-zA-Z])[_\w-]{,61})?([\da-zA-Z]\.((xn\-\-[a-zA-Z\d]+)|([a-zA-Z\d]{2,})))')
reg_domain4 = re.compile('(\.|\/)(([A-Za-z\d]+|[A-Za-z\d][-])+[A-Za-z\d]+){1,63}\.([A-Za-z]{2,3}\.[A-Za-z]{2}|[A-Za-z]{2,6})')

# a = reg_domain2.findall(rc[2])[0]
# reg_domain4.findall(rc[1])


def ORIGINATOR_domain(HEADER):
    reg_domain2_1 = re.compile('(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]{2,6}')
    # reg_domain4 = re.compile(
    #     '(\.|\/)(([A-Za-z\d]+|[A-Za-z\d][-])+[A-Za-z\d]+){1,63}\.([A-Za-z]{2,3}\.[A-Za-z]{2}|[A-Za-z]{2,6})')
    if 'received' in HEADER.keys():
        for i in range(len(HEADER['received'])-1,-1,-1):
            org_domain = ''
            # print(i)
            rcvd = HEADER['received'][i]
            if (rcvd.startswith('from')):
                org_domain = reg_domain2_1.findall(rcvd)
                if len(org_domain)> 0:
                    org_domain = org_domain[0]
                    # org_domain = reg_domain4.findall(org_domain[0])
                    # if len(org_domain)>0:
                    #     org_domain = org_domain[0][1]
                    # else:
                    #     org_domain=''
                else:
                    org_domain = ''
                break
            else:
                continue
    else:
        org_domain = ''
    return org_domain

def DOMAIN(HEADER,KEY):
    reg_domain2 = re.compile('(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9]{2,6}')
    if KEY in HEADER.keys():
        doms = reg_domain2.findall(HEADER[KEY][0])
        if len(doms)>0:
            dom = doms[0]
        else:
            dom = ''
    else:
        dom = ''
    return dom




def intersection(lst1, lst2):
    return list(set(lst1) & set(lst2))


def difference(lst1, lst2):
    return list(set(lst1) - set(lst2))


def func_convert_HKEY_tolower(HKEY):
    s = str(HKEY).lower()
    return ast.literal_eval(s)


def find_Regex_fromtxt(REGEX, txt):
    try:
        context = re.findall(REGEX, txt)[0]
    except:
        context = ['NA']
        pass
    return context


def HKEY_existence(HEADER, HKEY):
    try:
        hkey = HEADER[HKEY]
        return 1
    except:
        return 0

def DMARC_existence(HEADER):
    if 'authentication-results' in HEADER.keys():
        if 'dmarc' in " ".join(HEADER['authentication-results']):
            return 1
        else:
            return 0
    else:
        return 0


def DMARC_SPF_STATUS(HEADER):
    if 'authentication-results' in HEADER.keys():
        a_res = HEADER['authentication-results'][len(HEADER['authentication-results'])-1]
        # a_res = " ".join(HEADER['authentication-results'])
        # if 'dmarc=fail' in a_res:
        #     return True
        # else:
        #     return False

        if 'spf=' in a_res:
            spf = a_res.split('spf=')[1].split(' ')[0]
        else:
            spf = ''
        if 'dmarc=' in a_res:
            dmarc = a_res.split('dmarc=')[1].split(' ')[0]
        else:
            dmarc = ''
        return spf,dmarc
    else:
        return '',''

def DKIM_STATUS(HEADER):
    if 'authentication-results' in HEADER.keys():
        a_res = HEADER['authentication-results'][len(HEADER['authentication-results']) - 1]
        if 'dkim=' in a_res:
            try:
                dkim = a_res.split('dkim=')[1].split(' ')[0]
            except:
                dkim = 'NAN'
        else:
            dkim = ''
    else:
        dkim = 'NAN'
    return dkim








# def originator_domain(HEADER):
#     rcvds = HEADER['received']
#     for rcvd in rcvds:




# def extract_domain(HEADER,HKEY):
#     return publicsuffix.PublicSuffixList(publicsuffix.fetch()).get_public_suffix(reg_domain2.findall(HEADER[HKEY][0])[0])


def HVALUE_existence(HEADER, HKEY):
    checksum = HKEY_existence(HEADER, HKEY)
    if checksum == 1:
        hvalue = HEADER[HKEY]
        if len(hvalue) > 5:
            return 1
        else:
            return 0
    else:
        return 0
