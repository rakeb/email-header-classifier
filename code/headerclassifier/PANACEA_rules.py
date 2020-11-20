import logging

from PANACEA_functions import func_findDomain_fromtxt, reg_email, special_chars, HKEY_existence, intersection, \
    authentication_HKEYS, func_tolocaltime, reg_datetime
from Utility import is_message_id_in_history

from PANACEA_functions import reg_domain2, DMARC_existence

logger = logging.getLogger('header_classifier_rules.py')
logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                    datefmt='%Y-%m-%d:%H:%M:%S',
                    level=logging.DEBUG)


def rule1(HEADER):
    try:
        from_dom = func_findDomain_fromtxt(HEADER['from'][0])
        msgid_dom = func_findDomain_fromtxt(HEADER['message-id'][0])
        res = ''
        score = 0
    except:
        res = 'from/message-id does not exist!' \
              '----> Definitely malicious'
        score = 1
    return res, score


# rule2 : sender HKEY (FROM:) exist and if so, address does not include special character but "_", "-", and "."
def rule2(HEADER):
    try:
        from_address = reg_email.findall(HEADER['from'][0])[0]
        from_ID = from_address.split('@')[0]
        if special_chars.search(from_ID) == None:
            res = ''
            score = 0
        else:
            res = 'Email address contains special character!' \
                  '----> Definitely malicious'
            score = 1
    except:
        # alert_HKEY('FROM')
        res = ''
        score = 0
    return res, score


# rule3 : blacklisted emails and domain
def rule3(HEADER):
    blacklist_email = []
    try:
        from_address = reg_email.findall(HEADER['from'][0])[0]
        if from_address in blacklist_email:
            res = 'Sender is blacklisted!' \
                  '----> Definitely malicious'
            score = 1
        else:
            res = ''
            score = 0
    except:
        res = ''
        score = 0
    return res, score


# rule4 : message ID existence
def rule4(HEADER):
    if HKEY_existence(HEADER, 'message-id') == 1:
        res = ''
        score = 0
    else:
        res = 'message-id does not exist!' \
              '----> Definitely malicious'
        score = 1
    return res, score


# rule 4.1: message_ID

# rule5 : uniqueness of message ID
def rule5(HEADER, MESSAGE_IDs):
    if rule4(HEADER) == 0:
        msg_id = HEADER['message-id'][0]
        if msg_id in MESSAGE_IDs:
            res = 'Message-ID is not unique!' \
                  '----> Definitely malicious'
            score = 1
        else:
            res = ''
            score = 0
    else:
        res = ''
        score = 0
    return res, score


# rule 6 : Equivalent From: and Return path: address
def rule6(HEADER):
    try:
        from_dom = func_findDomain_fromtxt(HEADER['from'][0])
        RP_dom = func_findDomain_fromtxt(HEADER['return-path'][0])
        if from_dom in RP_dom:
            res = ''
            score = 0
        else:
            res = 'Return-Path and From are not the same!' \
                  '----> Likely malicious'
            score = 3
    except:
        res = ''
        score = 0
    return res, score


# rule 7 :  CC or BCC included? More than threshold?
def rule7(HEADER):
    try:
        cc = HEADER['cc']
        cc_contacts = reg_email.findall(cc)
        if len(cc_contacts > 10):
            res = 'CC is too long!' \
                  '----> Highly likely malicious'
            score = 2

        else:
            res = ''
            score = 0
    except:
        res = ''
        score = 0
    return res, score


# rule 8_0 : date existence
def rule8_0(HEADER):
    if HKEY_existence(HEADER, 'date') == 1:
        res = ''
        score = 0
    else:
        res = 'DATE does not exist!' \
              '----> Definitely malicious'
        score = 1
    return res, score


def rule8_1(HEADER):
    if HKEY_existence(HEADER, 'to') == 1:
        res = ''
        score = 0
    else:
        res = 'To does not exist!' \
              '----> Definitely malicious'
        score = 1
    return res, score


def rule8_2(HEADER):
    if HKEY_existence(HEADER, 'return-path') == 1:
        res = ''
        score = 0
    else:
        res = 'Return-path does not exist!' \
              '----> Highly likely malicious'
        score = 2
    return res, score  # rule 8 : date is empty


def rule8(HEADER):
    res = ''
    score = 0
    if HKEY_existence(HEADER, 'date') == 1:
        if not HEADER['date']:
            res = 'DATE has no value!' \
                  '----> Definitely malicious'
            score = 1
    if HKEY_existence(HEADER, 'to') == 1:
        if not HEADER['to']:
            res = 'To has no value!' \
                  '----> Definitely malicious'
            score = 1
    if HKEY_existence(HEADER, 'return-path') == 1:
        if not HEADER['return-path']:
            res = 'Return-Path has no value!' \
                  '----> Definitely malicious'
            score = 1
    else:
        pass
    return res, score


def rule8_3(HEADER):
    if HKEY_existence(HEADER, 'date') == 1 and HKEY_existence(HEADER, 'received') == 1:
        try:
            send_date = func_tolocaltime(reg_datetime.findall(HEADER['date'][0])[0])
            receiced_idx = len(HEADER['received'])
            for i in range(receiced_idx-1,-1,-1):
                try:
                    rec_date = func_tolocaltime(reg_datetime.findall(HEADER['received'][i])[0])
                    timedelta = rec_date - send_date
                    break
                except:
                    continue
            if timedelta:
                if timedelta.total_seconds() < 0:
                    res = 'Sent time is before Received time!' \
                          '----> Highly likely malicious'
                    score = 2
                else:
                    res = ''
                    score = 0
            else:
                res = ''
                score = 0
        except:
            res = ''
            score = 0
    else:
        res = ''
        score = 0
    return res, score


# rule 9 : X-mailer existence
def rule9(HEADER):
    if HKEY_existence(HEADER, 'x-mailer') == 1:
        res = ''
        score = 0
    else:
        res = 'x-mailer does not exist' \
              '----> Likely malicious'
        score = 3
    return res, score


# rule 10 : X-mailer value existence.
def rule10(HEADER):
    if HKEY_existence(HEADER, 'x-mailer') == 1:
        xmlr = HEADER['x-mailer'][0]
        if len(xmlr) > 5:
            res = ''
            score = 0
        else:
            res = 'X-mailer value is not legit!' \
                  '----> Definitely malicious'
            score = 1
    else:
        # alert_HKEY('x-mailer')
        res = ''
        score = 0
    return res, score


# rule 11 : subject has speciale character?
def rule11(HEADER):
    if HKEY_existence(HEADER, 'subject') == 1:
        subject = HEADER['subject'][0]
        if special_chars.search(subject) == None:
            res = ''
            score = 0
        else:
            res = 'Subject contains special characters!' \
                  '----> Highly likely malicious'
            score = 2

    else:
        res = 'Subject does not exist!'
        score = 0
    return res, score


# rule 12 : authentication
def rule12(HEADER):
    all_keys = list(HEADER.keys())
    if len(intersection(all_keys, authentication_HKEYS)) == 0:
        res = 'No authentication!' \
              '----> Highly likely malicious'
        score = 2
    else:
        res = ''
        score = 0
    return res, score


# rule 13: received existance
def rule13(HEADER):
    if HKEY_existence(HEADER, 'received') == 1:
        res = ''
        score = 0
    else:
        res = 'Received does not exist!' \
              '----> Highly likely malicious'
        score = 2
    return res, score


# rule 14: received-spf is standard
def rule14(HEADER):
    if 'received-spf' in HEADER:
        rcvd_spf = HEADER['received-spf'][0]
        if 'unknown' in rcvd_spf or rcvd_spf.startswith('fail'):
            res = 'Received-SPF is not standard or SPF is failed' \
                  '----> Highly likely malicious'
            score = 2
        else:
            res = ''
            score = 0
    else:
        res = ''
        score = 0
    return res, score

def rule14_1(HEADER):
    try:
        rcvd_spf = HEADER['received'][len(HEADER['received'])-1]
        if 'unknown' in rcvd_spf:
            res = 'Received is unknown' \
                  '----> Highly likely malicious'
            score = 2
        else:
            res = ''
            score = 0
    except:
        res = ''
        score = 0
    return res, score



# rule 15: SPF and DMARC
def rule15(HEADER):
    if 'authentication-results' in HEADER.keys():
        auth_res = " ".join(HEADER['authentication-results'])
        if 'spf=pass' in auth_res:
            if 'dmarc=fail' in auth_res:
                res = 'SPF is passed but DMARC is fail' \
                      '----> Definitely malicious'
                score = 1
            else:
                res = ''
                score = 0
        else:
            res = ''
            score = 0
    else:
        res = 'Authentication-Results does not exist' \
              '----> Likely malicious'
        score = 3

    return res, score


#rule 16: SPF
def rule16(HEADER):
    try:
        rcvd_spf = HEADER['received-spf'][0]
        if rcvd_spf.startswith('neutral' or 'none'):
            res = 'SPF is Neutral/None' \
                  '----> Likely malicious'
            score = 3
        else:
            res = ''
            score = 0

    except:
        res = 'Received-SPF does not exist' \
              '----> Highly likely malicious'
        score = 2
    return res, score

#rule 17: SPF passed but DMARC is missing
def rule17(HEADER):
    if HKEY_existence(HEADER, 'received-spf') ==1:
        rcvd_spf = HEADER['received-spf'][0]
        if rcvd_spf.startswith('pass'):
            if DMARC_existence(HEADER) == 0:
                res = 'SPF is passed but DMARC is missed' \
                      '----> Likely malicious'
                score = 3
            else:
                res = ''
                score = 0
        else:
            res = ''
            score = 0
    else:
        res = ''
        score = 0
    return res, score

#rule 18: SPF passed but DMARC is missing
def rule18(HEADER):
    if HKEY_existence(HEADER, 'received-spf') == 0:
        if DMARC_existence(HEADER) == 0:
            res = 'SPF and DMARC are missed' \
                  '----> Likely malicious'
            score = 3
        else:
            res = ''
            score = 0
    else:
        res = ''
        score = 0
    return res, score


#rule 19:   1- If From (domain) <> Originator (domain) && From == Reply-to && (DMARK is missing ) && SPF <> pass
def rule19(HEADER):
    if DMARC_existence(HEADER) == 0 and \
            HKEY_existence(HEADER, 'received-spf') == 1 and\
            HKEY_existence(HEADER, 'from')==1 and\
            HKEY_existence(HEADER, 'received')==1 and\
            HKEY_existence(HEADER, 'return-path')==1:

        try:

            from_dom = reg_domain2.findall(HEADER['from'][0])
            rcvd_dom = reg_domain2.findall(HEADER['received'][len(HEADER['received'])-1])
            rp_dom = reg_domain2.findall(HEADER['return-path'][0])

            if from_dom and rcvd_dom and rp_dom:
                if (from_dom[0] not in rcvd_dom[0]) and (from_dom[0] in rp_dom[0]) and HEADER['received-spf'][0].startswith('pass'):
                    res = 'sender domain matches with return-path but not with originator, and SPF is passed' \
                          '----> Likely malicious'
                    score = 3
                else:
                    res = ''
                    score = 0
            else:
                res = ''
                score = 0
        except:
            res = ''
            score = 0
    else:
        res = ''
        score = 0
    return res, score

#rule 20: If F <> O && O = R && (DMARK is missing ) && (SPF = pass or missing)
def rule20(HEADER):
    if DMARC_existence(HEADER) == 0 and \
            HKEY_existence(HEADER, 'from')==1 and\
            HKEY_existence(HEADER, 'received')==1 and\
            HKEY_existence(HEADER, 'return-path')==1:
        try:

            from_dom = reg_domain2.findall(HEADER['from'][0])
            rcvd_dom = reg_domain2.findall(HEADER['received'][len(HEADER['received'])-1])
            rp_dom = reg_domain2.findall(HEADER['return-path'][0])

            if (from_dom[0] not in rcvd_dom[0]) and (rp_dom[0] in rcvd_dom[0]):
                if (HKEY_existence(HEADER, 'received-spf') == 0):
                    res = 'originator domain matches with return-path but not with sender, and SPF is missing' \
                          '----> Highly likely malicious'
                    score = 2
                elif (HKEY_existence(HEADER, 'received-spf') == 1):
                    if HEADER['received-spf'][0].startswith('pass'):
                        res = 'originator domain matches with return-path but not with sender, and SPF is pass' \
                              '----> Highly likely malicious'
                        score = 2
                    else:
                        res = ''
                        score = 0
                else:
                    res = ''
                    score = 0
            else:
                res = ''
                score = 0
        except:
            res = ''
            score = 0
    else:
        res = ''
        score = 0
    return res, score

#rule 21: If F <> O && F <> R && R<>O && SPF= pass or missing && (DMARK is missing)
def rule21(HEADER):
    if DMARC_existence(HEADER) == 0 and \
            HKEY_existence(HEADER, 'from')==1 and\
            HKEY_existence(HEADER, 'received')==1 and\
            HKEY_existence(HEADER, 'return-path')==1:
        try:

            from_dom = reg_domain2.findall(HEADER['from'][0])
            rcvd_dom = reg_domain2.findall(HEADER['received'][len(HEADER['received'])-1])
            rp_dom = reg_domain2.findall(HEADER['return-path'][0])

            if (from_dom[0] not in rcvd_dom[0]) and (from_dom[0]!= rp_dom[0]) and (rp_dom[0] not in rcvd_dom[0]):
                if (HKEY_existence(HEADER, 'received-spf') == 0):
                    res = 'originator domain matches with return-path but not with sender, and SPF is missed' \
                          '----> Highly likely malicious'
                    score = 2
                elif (HKEY_existence(HEADER, 'received-spf') == 1):
                    if HEADER['received-spf'][0].startswith('pass'):
                        res = 'originator domain matches with return-path but not with sender, and SPF is pass' \
                              '----> Highly likely malicious'
                        score = 2
                    else:
                        res = ''
                        score = 0
                else:
                    res = ''
                    score = 0
            else:
                res = ''
                score = 0
        except:
            res = ''
            score = 0
    else:
        res = ''
        score = 0
    return res, score

#rule 22: If F = O && F<>R && (SPF= pass/missing) && (DMARK is missing) & F= Deliver-to
def rule22(HEADER):
    if DMARC_existence(HEADER) == 0 and\
            HKEY_existence(HEADER, 'from')==1 and\
            HKEY_existence(HEADER, 'received')==1 and\
            HKEY_existence(HEADER, 'return-path')==1 and\
            HKEY_existence(HEADER, 'delivered-to')==1:
        try:


            from_dom = reg_domain2.findall(HEADER['from'][0])
            rcvd_dom = reg_domain2.findall(HEADER['received'][len(HEADER['received'])-1])
            rp_dom = reg_domain2.findall(HEADER['return-path'][0])
            dlvrdto_dom = reg_domain2.findall(HEADER['delivered-to'][0])

            if (from_dom[0] in rcvd_dom[0]) and (from_dom[0]!= rp_dom[0]) and (from_dom[0] != dlvrdto_dom[0]):
                if (HKEY_existence(HEADER, 'received-spf') == 0):
                    res = 'sender domain matches with originator and delivered-to but sender and return-path are not matched, and SPF is missed' \
                          '----> Likely malicious'
                    score = 3
                elif (HKEY_existence(HEADER, 'received-spf') == 1):
                    if HEADER['received-spf'][0].startswith('pass'):
                        res = 'sender domain matches with originator and delivered-to but sender and return-path are not matched, and SPF is pass' \
                              '----> Likely malicious'
                        score = 3
                    else:
                        res = ''
                        score = 0
                else:
                    res = ''
                    score = 0
            else:
                res = ''
                score = 0
        except:
            res = ''
            score = 0
    else:
        res = ''
        score = 0
    return res, score




#
def rule_check_unique_message_id(raw_email_header):
    response_text = ''
    score = 0
    try:
        email_header = {k.lower(): v for k, v in raw_email_header.items()}
        message_id = email_header['message-id'][0]
        logger.info("message_id inside rule_check_unique_message_id: {}".format(message_id))
        history = is_message_id_in_history(message_id, 'benign')
        if history:
            response_text = 'Message-ID is not unique! (found in benign cache)' \
                            '----> Definitely malicious'
            score = 1
            logger.info("History Benign: {}".format(history))
            return response_text, score
        history = is_message_id_in_history(message_id, 'spam')
        if history:
            response_text = 'Message-ID is not unique! (found in spam cache)' \
                            '----> Definitely malicious'
            score = 1
            logger.info("History Spam: {}".format(history))
            return response_text, score
    except:
        logger.info("message-id not found in header: {}".format(email_header))
    return response_text, score


###test framework
def rbased_classifier(HEADER, MESSAGE_IDs, raw_header):
    from operator import is_not
    from functools import partial
    rule_responses = []
    rule_scores = []
    score = 0
    rule_responses.append(rule1(HEADER)[0])
    rule_responses.append(rule2(HEADER)[0])
    rule_responses.append(rule3(HEADER)[0])
    rule_responses.append(rule4(HEADER)[0])
    rule_responses.append(rule5(HEADER, MESSAGE_IDs)[0])
    rule_responses.append(rule6(HEADER)[0])
    rule_responses.append(rule7(HEADER)[0])
    rule_responses.append(rule8_0(HEADER)[0])
    rule_responses.append(rule8_1(HEADER)[0])
    rule_responses.append(rule8_2(HEADER)[0])
    rule_responses.append(rule8(HEADER)[0])
    rule_responses.append(rule9(HEADER)[0])
    rule_responses.append(rule10(HEADER)[0])
    rule_responses.append(rule11(HEADER)[0])
    rule_responses.append(rule12(HEADER)[0])
    rule_responses.append(rule13(HEADER)[0])
    rule_responses.append(rule14(HEADER)[0])
    rule_responses.append(rule14_1(HEADER)[0])
    rule_responses.append(rule15(HEADER)[0])
    rule_responses.append(rule16(HEADER)[0])
    rule_responses.append(rule17(HEADER)[0])
    rule_responses.append(rule18(HEADER)[0])
    rule_responses.append(rule19(HEADER)[0])
    rule_responses.append(rule20(HEADER)[0])
    rule_responses.append(rule21(HEADER)[0])
    rule_responses.append(rule22(HEADER)[0])

    response_txt, score = rule_check_unique_message_id(raw_header)
    logger.info("response_txt: {} and score: {}".format(response_txt, score))
    rule_responses.append(response_txt)

    rule_scores.append(rule1(HEADER)[1])
    rule_scores.append(rule2(HEADER)[1])
    rule_scores.append(rule3(HEADER)[1])
    rule_scores.append(rule4(HEADER)[1])
    rule_scores.append(rule5(HEADER, MESSAGE_IDs)[1])
    rule_scores.append(rule6(HEADER)[1])
    rule_scores.append(rule7(HEADER)[1])
    rule_scores.append(rule8_0(HEADER)[1])
    rule_scores.append(rule8_1(HEADER)[1])
    rule_scores.append(rule8_2(HEADER)[1])
    rule_scores.append(rule8(HEADER)[1])
    rule_scores.append(rule9(HEADER)[1])
    rule_scores.append(rule10(HEADER)[1])
    rule_scores.append(rule11(HEADER)[1])
    rule_scores.append(rule12(HEADER)[1])
    rule_scores.append(rule13(HEADER)[1])
    rule_scores.append(rule14(HEADER)[1])
    rule_scores.append(rule14_1(HEADER)[1])
    rule_scores.append(rule15(HEADER)[1])
    rule_scores.append(rule16(HEADER)[1])
    rule_scores.append(rule17(HEADER)[1])
    rule_scores.append(rule18(HEADER)[1])
    rule_scores.append(rule19(HEADER)[1])
    rule_scores.append(rule20(HEADER)[1])
    rule_scores.append(rule21(HEADER)[1])
    rule_scores.append(rule22(HEADER)[1])
    rule_scores.append(score)
    response_txt, score = rule8_3(HEADER)
    rule_responses.append(response_txt)
    rule_scores.append(score)

    if 1 in rule_scores:
        score = 1
        classification = 'Definitely'
    elif 2 in rule_scores:
        score = 0
        classification = 'Highly Likely'
    elif 3 in rule_scores:
        score = 0
        classification = 'Likely'
    elif 0 in rule_scores:
        score = 0
        classification = 'Not Sure'
    else:
        score = 0
        classification = 'Not Sure'

    rule_responses = list(filter(partial(is_not, ''), rule_responses))
    if not rule_responses:
        rule_responses.append('No rule is satisfied!')
    else:
        rule_responses = {i: rule_responses[i] for i in range(0, len(rule_responses))}
    res = {"score": score,
           "classification": classification,
           "justification": rule_responses,
           "status": "OK"
           }
    return res
