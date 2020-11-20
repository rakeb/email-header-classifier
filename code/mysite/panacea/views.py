# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import json
import logging
import math
import os
import pickle
import traceback
from datetime import datetime
from inspect import currentframe, getframeinfo
from subprocess import run, PIPE

import eml_parser
from django.http import HttpResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt

from mysite.settings import MEDIA_ROOT
from panacea.activeinvestigation import active_investigate
from panacea.senderprofile import sender_classification
from panacea.utilities.custom_errors_logs import write_error_logs, get_saved_error_logs, error_log_file_name
from panacea.utilities.unlabeled_data_processed_counter import get_unlabeled_data_processed_count, \
    update_unlabeled_data_processed_count, counter_file_name

logger = logging.getLogger('views.py')
logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                    datefmt='%Y-%m-%d:%H:%M:%S',
                    level=logging.DEBUG)

PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
header_classifier_files_dir = str(PROJECT_ROOT.split('mysite/panacea')[0])

header_classifier_main_python_file_dir = header_classifier_files_dir + 'headerclassifier/PANACEA_main.py'

header_classifier_input_file_name = header_classifier_files_dir + 'headerclassifier/PANACEA_main_input.txt'

benign_message_id_file_name = header_classifier_files_dir + 'headerclassifier/benign_message_id_list.pkl'
spam_message_id_file_name = header_classifier_files_dir + 'headerclassifier/spam_message_id_list.pkl'

TRAINING_STATUS_FILE_NAME = os.path.join(MEDIA_ROOT, 'training_status.pkl')

MESSAGE_ID = None

ERROR_STRING_LIST = ['error', 'Error', 'ERROR']


def index(request):
    return render(request, 'panacea/index.html')


@csrf_exempt
def active_investigation(request):
    if request.method == 'POST':
        json_loads = json.loads(request.body.decode("utf-8"))
        logger.info("Request: {}".format(json_loads))
        json_response = active_investigate.investigate_using_db(json_loads)
    else:
        json_response = {"Status": "Use JSON POST request."}

    logger.info("Response: {}".format(json_response))
    return HttpResponse(
        json.dumps(json_response),
        content_type="application/json"
    )


@csrf_exempt
def email_header_training(request):
    logger.info("Request Training...")
    emails_list_url = []
    if request.method == 'GET':
        emails_list_url = request.GET['url']
    if request.method == 'POST':
        emails_list_url = request.POST['url']

    logger.info("Training URL: {}".format(emails_list_url))

    command = 'python3 ' + header_classifier_main_python_file_dir + ' ' + emails_list_url
    out_str, std_err = external_out_command(command)

    if any(x in out_str for x in ERROR_STRING_LIST):
        write_error_logs(message_id=None, message=out_str)

    logger.info("Header Classifier Training Output: {}, error: {}".format(out_str, std_err))
    if std_err:
        write_error_logs(message_id=None, message=std_err)
    output_json = {
        "Output": out_str,
        "timestamp": datetime.today().strftime('%Y-%m-%d %H:%M:%S'),
        "error": std_err
    }

    save_pickle_to_file(TRAINING_STATUS_FILE_NAME, output_json)

    logger.info("Response Training: {}".format(output_json))
    return HttpResponse(
        json.dumps(output_json),
        content_type="application/json"
    )


def func_parse_eml(raw_eml):
    raw_eml = raw_eml.encode()
    return eml_parser.eml_parser.decode_email_b(raw_eml)


def eml_to_json(eml_header_list):
    json_header_list = []
    for header in eml_header_list:
        json_header = func_parse_eml(header)
        json_header_list.append(json_header['header']['header'])
    return json_header_list


def check_request_api_for_testing(json_loads):
    checked = True
    status = ''
    try:
        json_loads['email-header']
    except:
        checked = False
        status = {"Status": "Not OK", "Reason": "'email-header' keyword not found in the Request"}

    try:
        json_loads['req-id']
    except:
        checked = False
        status = {"Status": "Not OK", "Reason": "'req-id' keyword not found in the Request"}
    return checked, status


def check_request_api_for_training(json_loads):
    checked = True
    status = {}
    try:
        json_loads['number-of-header']
    except:
        checked = False
        status["Reason 1"] = "'number-of-header' keyword not found in the Request"
    try:
        json_loads['header-list']
    except:
        checked = False
        status["Reason 2"] = "'header-list' keyword not found in the Request"
    status["Status"] = "Not OK"
    return checked, status


def external_out_command(command):
    result = run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)

    logger.debug("Command Results: {}".format(result))
    return result.stdout, result.stderr


def load_pickle_from_file(file_name):
    with open(file_name, 'rb') as handle:
        _output = pickle.load(handle)
    return _output


def save_pickle_to_file(file_name, _object):
    with open(file_name, 'wb') as handle:
        pickle.dump(_object, handle, protocol=pickle.HIGHEST_PROTOCOL)


def get_message_id(json_loads):
    global MESSAGE_ID
    raw_email_header = json_loads['email-header']
    email_header = {k.lower(): v for k, v in raw_email_header.items()}
    try:
        MESSAGE_ID = email_header['message-id'][0]
    except Exception as e:
        logger.error("message-id not found in email header: {}".format(e))
        MESSAGE_ID = None


def cache_message_id(output_json):
    global MESSAGE_ID

    if MESSAGE_ID is None:
        return

    scores = 0
    indexed_score = 0

    if output_json["rule-based"]["score"] >= 0:
        scores += output_json["rule-based"]["score"]
        indexed_score += 1
    if output_json["active-classification"]["score"] >= 0:
        scores += output_json["active-classification"]["score"]
        indexed_score += 1
    if output_json["aggregate-classifier-(random-forest)"]["score"] >= 0:
        scores += output_json["aggregate-classifier-(random-forest)"]["score"]
        indexed_score += 1
    # if output_json["sender-profile"]["score"] >= 0:
    #     scores += output_json["aggregate-classifier-(random-forest)"]["score"]
    #     indexed_score += 1

    if scores / indexed_score <= 0.5:
        file_name = benign_message_id_file_name
    else:
        file_name = spam_message_id_file_name
    try:
        message_id_list = load_pickle_from_file(file_name)
    except:
        message_id_list = []

    message_id_list.append(MESSAGE_ID)

    if len(message_id_list) > 1000:
        new_message_id_list = message_id_list[1:]
        save_pickle_to_file(file_name, new_message_id_list)
    else:
        save_pickle_to_file(file_name, message_id_list)
    logger.debug("Message id: {} is cached into file: {}".format(MESSAGE_ID, file_name))


def get_sophistication_status(output_json):
    if output_json["rule-based"]["score"] > 0:
        level = 'naive'
        justification = 'Rule based'
    elif output_json["active-classification"]["score"] > 0:
        level = 'moderately sophisticated'
        justification = 'Active investigation'
    elif output_json["aggregate-classifier-(random-forest)"]["classification"] != 'benign':
        level = 'sophisticated'
        justification = 'Random forest'
    # elif output_json["sender-profile"]["classification"] == 'malicious':
    #     level = 'highly sophisticated: likely spear-phishing'
    #     justification = 'Subject classifier'
    else:
        level = 'normal'
        justification = 'Benign header'

    res = {
        "level": level,
        "justification": justification,
        "status": "OK"
    }
    return res


def convert_range(old_value):
    old_max = 1
    old_min = 0
    new_max = 6
    new_min = 1
    old_range = (old_max - old_min)
    new_range = (new_max - new_min)
    new_value = (((old_value - old_min) * new_range) / old_range) + new_min
    return round(new_value)


def set_determination_status_old(output_json):
    old_rule_based_score = output_json["rule-based"]["score"]
    new_rule_based_score = convert_range(old_rule_based_score)
    old_active_invst_score = output_json["active-classification"]["score"]
    new_active_invst_score = convert_range(old_active_invst_score)
    old_random_forest_score = output_json["aggregate-classifier-(random-forest)"]["score"]
    new_random_forest_score = convert_range(old_random_forest_score)
    old_sender_profile_score = output_json["sender-profile"]["score"]
    new_sender_profile_score = -1

    confidence = 0
    if old_sender_profile_score != -1:
        new_sender_profile_score = convert_range(old_sender_profile_score)

        confidence = (new_rule_based_score + new_random_forest_score + new_sender_profile_score
                      + new_active_invst_score) / 4

        old_confidence = (old_rule_based_score + old_random_forest_score + old_sender_profile_score
                          + old_active_invst_score) / 4
    else:
        confidence = (new_rule_based_score + new_random_forest_score + new_active_invst_score) / 3
        old_confidence = (old_rule_based_score + old_random_forest_score + old_active_invst_score) / 3

    confidence = round(confidence)

    if output_json["sophistication"]["level"] == "normal":
        result = 'friend'
    else:
        result = 'foe'

    res = {
        "result": result,
        "confidence": confidence,
        "x-confidence": old_confidence,
        "status": "OK"
    }
    return res


def set_determination_status(output_json):
    old_rule_based_score = output_json["rule-based"]["score"]
    old_active_invst_score = output_json["active-classification"]["score"]
    old_random_forest_score = output_json["aggregate-classifier-(random-forest)"]["score"]
    # old_sender_profile_score = output_json["sender-profile"]["score"]

    old_confidence = 0
    if old_rule_based_score >= old_confidence:
        old_confidence = old_rule_based_score
    if old_active_invst_score >= old_confidence:
        old_confidence = old_active_invst_score
    if old_random_forest_score >= old_confidence:
        old_confidence = old_random_forest_score
    # if old_sender_profile_score >= old_confidence:
    #     old_confidence = old_sender_profile_score

    if output_json["sophistication"]["level"] == "normal":
        result = 'friend'
    else:
        result = 'foe'

    res = {
        "result": result,
        "x-confidence": old_confidence,
        "status": "OK"
    }
    return res


# "determination": "friend"
# "confidence": 0.7
# "credibility": 3
def set_d_c_c(output_json):
    determination = output_json['x-determination']['result']

    x_confidence = output_json['x-determination']['x-confidence']

    if determination == 'foe':
        confidence = (-1) * x_confidence
        x_credibility = 1 - x_confidence
    else:
        if x_confidence == 0:
            confidence = 1
        else:
            confidence = x_confidence
        x_credibility = x_confidence

    confidence = math.ceil(confidence * 100) / 100
    output_json['assessment'] = confidence

    credibility = convert_range(x_credibility)

    output_json['credibility'] = credibility


def set_all_classifier_output(output_json):
    all_classifier = {
        "rules_based": output_json['rule-based']['score'],
        "anomaly_based": output_json['aggregate-classifier-(random-forest)']['score'],
        "active_investigation": output_json['active-classification']['score'],
        # "sender_profile": output_json['sender-profile']['score'],
    }
    output_json['all_classifier'] = all_classifier


def check_and_clear_health_dashboard(request):
    json_loads = json.loads(request.body.decode("utf-8"))
    try:
        clear = json_loads['clear']
        if clear is True:
            clear_errors = json_loads['clear_errors']
            clear_message_counts = json_loads['clear_message_counts']
            if clear_errors is True:
                open(error_log_file_name, 'w').close()
                logger.info("Cleared health dashboard errors log")
            if clear_message_counts is True:
                open(counter_file_name, 'w').close()
                logger.info("Cleared health dashboard message processing statistics")
    except:
        logger.exception("Error while clearing health dashboard")


@csrf_exempt
def health_dashboard(request):
    logger.info("Request Health Dashboard...")

    if request.method == 'POST':
        check_and_clear_health_dashboard(request)
    saved_error_logs = get_saved_error_logs()
    try:
        training_status = load_pickle_from_file(TRAINING_STATUS_FILE_NAME)
    except:
        training_status = []
    message_counts = get_unlabeled_data_processed_count()

    output_json = {
        "name": 'uncc-header-classifier',
        "timestamp": datetime.today().strftime('%Y-%m-%d %H:%M:%S'),
        "errors": saved_error_logs,
        "message_counts": message_counts,
        "ta1_or_ta2": 'TA1',
        "other": training_status
    }

    logger.info("Response Health Dashboard: {}".format(output_json))

    return HttpResponse(
        json.dumps(output_json),
        content_type="application/json"
    )


def test_header(json_loads):
    global MESSAGE_ID
    eml_header_list = [json_loads['email-header']]
    json_header_list = eml_to_json(eml_header_list)
    json_loads['email-header'] = json_header_list[0]

    # sets global MESSAGE_ID
    get_message_id(json_loads)
    output_json = {'req-id': json_loads['req-id']}
    # TODO Ehsans' classification first
    with open(header_classifier_input_file_name, 'wb') as handle:
        pickle.dump(json_loads, handle, protocol=pickle.HIGHEST_PROTOCOL)
    logger.debug("Header is loaded into input file: {}".format(header_classifier_input_file_name))

    command = 'python3 ' + header_classifier_main_python_file_dir
    logger.debug("Header Classifier is processing by command: {}".format(command))
    out_str, std_err = external_out_command(command)

    if any(x in out_str for x in ERROR_STRING_LIST):
        write_error_logs(message_id=MESSAGE_ID, message=out_str)

    logger.debug("External Header Classifier output: {}".format(out_str))
    out_str = out_str.rstrip()
    try:
        json_response = json.loads(out_str)
        logger.info("Header Classifier testing response: {}".format(json_response))
        output_json["aggregate-classifier-(random-forest)"] = json_response['random_forest_response']
        output_json["rule-based"] = json_response['rule-based-responses']
    except Exception as e:
        logger.exception("Exception in Header Classifier: ")
        frameinfo = getframeinfo(currentframe())
        write_error_logs(message_id=MESSAGE_ID,
                         message="[{}: {}] Exception in Header Classifier: {}".format(frameinfo.filename,
                                                                                      frameinfo.lineno,
                                                                                      traceback.format_exc()))
        logger.error("Error from header classifier: {}".format(std_err))
        write_error_logs(message_id=MESSAGE_ID,
                         message="[{}: {}] Error from header classifier: {}".format(frameinfo.filename,
                                                                                    frameinfo.lineno, std_err))
        output_json["aggregate-classifier-(random-forest)"] = {
            "score": 0,
            "classification": "",
            "status": "Error occurred from header classifier"
        }
        output_json["rule-based"] = {
            "score": 0,
            "classification": "",
            "justification": '',
            "status": "Error occurred from header classifier: {}".format(e)
        }

    # TODO Rakebs' investigation next
    try:
        json_response = active_investigate.start_investigate(json_loads, MESSAGE_ID)
        logger.info("Active investigation response: {}".format(json_response))
        output_json["active-classification"] = json_response
    except Exception as e:
        logger.exception("Exception in Active investigation: ")
        frameinfo = getframeinfo(currentframe())
        write_error_logs(message_id=MESSAGE_ID,
                         message="[{}: {}] Exception in Active investigation: {}".format(frameinfo.filename,
                                                                                         frameinfo.lineno,
                                                                                         traceback.format_exc()))
        output_json["active-classification"] = {
            "score": 0,
            "threshold": "50%",
            "classification": "",
            "justification": {
            },
            "status": "Error: {}".format(e)
        }

    # TODO Qis' last
    try:
        json_response = sender_classification.sender_testing(json_loads, output_json)
        logger.info("Sender Classification response: {}".format(json_response))
        output_json["sender-profile"] = json_response
    except Exception as e:
        logger.exception("Exception in Sender Profiling")
        frameinfo = getframeinfo(currentframe())
        write_error_logs(message_id=MESSAGE_ID,
                         message="[{}: {}] Exception in Sender Profiling: {}".format(frameinfo.filename,
                                                                                     frameinfo.lineno,
                                                                                     traceback.format_exc()))
        output_json["sender-profile"] = {
            "score": 0,
            "justification": "",
            "status": "Error",
            "classification": ""
        }

    # cache_message_id(output_json)
    sophistication = get_sophistication_status(output_json)
    output_json['sophistication'] = sophistication

    determination = set_determination_status(output_json)
    output_json['x-determination'] = determination

    set_d_c_c(output_json)
    set_all_classifier_output(output_json)

    update_unlabeled_data_processed_count(email_processed_message_count=True)

    return output_json


@csrf_exempt
def email_header_testing(request):
    global MESSAGE_ID
    if request.method == 'POST':
        logger.info("Request Testing...")
        json_loads = json.loads(request.body.decode("utf-8"))
        checked, status = check_request_api_for_testing(json_loads)

        update_unlabeled_data_processed_count(email_received_message_count=True)

        if checked:
            try:
                output_json = test_header(json_loads)
            except Exception as e:
                logger.exception("Exception while testing header")
                frameinfo = getframeinfo(currentframe())
                write_error_logs(message_id=MESSAGE_ID,
                                 message="[{}: {}] Exception while testing header: {}".format(frameinfo.filename,
                                                                                              frameinfo.lineno,
                                                                                              traceback.format_exc()))
                output_json = {
                    "status": "Not OK",
                    "reason": traceback.format_exc()
                }
        else:
            output_json = status
    else:
        output_json = {"status": "Use JSON POST request."}
    logger.info("Response Testing: {}".format(output_json))

    return HttpResponse(
        json.dumps(output_json),
        content_type="application/json"
    )
