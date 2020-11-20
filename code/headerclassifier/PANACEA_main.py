import json
import logging
import os
import pickle
import sys
import time
import traceback
import urllib.request
from pathlib import Path

import eml_parser
import numpy as np
from eml_parser.decode import json_serial

from PANACEA_Classifier import RandomForest_Model, Preprocess, save_incr_RandomForest
from PANACEA_functions import func_convert_HKEY_tolower
from PANACEA_rules import rbased_classifier
from Utility import FILE_ROOT, BASE_DIR, load_pickle_from_file

logger = logging.getLogger('header_classifier_main.py')
logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                    datefmt='%Y-%m-%d:%H:%M:%S',
                    level=logging.DEBUG)

file_name_header_ph = FILE_ROOT + '/init/header_ph.pkl'
file_name_header_ph_train_xy = FILE_ROOT + '/init/header_ph_train_xy.pkl'
file_name_header_benign_train_xy = FILE_ROOT + '/init/header_b_train_xy.pkl'
file_name_Weird_keys = FILE_ROOT + '/init/Weird_keys.pkl'
file_name_message_IDs = FILE_ROOT + '/init/message_IDs.pkl'
file_name_subject_classifier_nb = FILE_ROOT + '/model/subject_classifier.pkl'
file_name_baseline_rand_forest_model = FILE_ROOT + '/model/random_forest_model_incr.pkl'
file_name_updated_rand_forest_model = FILE_ROOT + '/model2/random_forest_model_incr.pkl'


def func_parseeml(raw_eml):
    raw_eml = raw_eml.encode()
    return eml_parser.eml_parser.decode_email_b(raw_eml)


timestr = time.strftime("%Y%m%d-%H%M%S")
LOG_FILE_NAME = 'rakeb_log_' + str(timestr) + '.log'


def write_training_header_into_files(json_header_list):
    global LOG_FILE_NAME
    with open(LOG_FILE_NAME, 'a') as the_file:
        for json_header in json_header_list:
            the_file.write(json.dumps(json_header, default=json_serial))
            the_file.write('\n\n')
    statinfo = os.stat(LOG_FILE_NAME)
    if statinfo.st_size > 5242880:
        timestr = time.strftime("%Y%m%d-%H%M%S")
        LOG_FILE_NAME = 'rakeb_log_' + str(timestr) + '.log'


def play_with_eml_list(email_list):
    json_header_list = []
    for raw_email in email_list:
        json_header = func_parseeml(raw_email['raw'])
        json_header_list.append(json_header['header']['header'])
    # write_training_header_into_files(json_header_list)
    return json_header_list


def start_training(_url):
    subject_classifier_nb = load_pickle_from_file(file_name_subject_classifier_nb)
    Weird_keys = load_pickle_from_file(file_name_Weird_keys)
    online_eml_trained = 0
    offline_benign_eml_trained = 0
    offline_phishing_eml_trained = 0
    total_eml_trained = 0
    output_json = {
        "progress": 'Training complete',
        "Status": '200 OK',
        "online_eml_trained": online_eml_trained,
        "offline_benign_eml_trained": offline_benign_eml_trained,
        "offline_phishing_eml_trained": offline_phishing_eml_trained,
        "total_eml_trained": total_eml_trained,
    }
    try:
        with open(file_name_header_benign_train_xy, 'rb') as f:  # Python 3: open(..., 'rb')
            train_X, train_Y = pickle.load(f)
            train_Y = len(train_Y) * ['benign']

        offline_benign_eml_trained = len(train_X)

        with open(file_name_header_ph_train_xy, 'rb') as f:  # Python 3: open(..., 'rb')
            train_Xp, train_Yp = pickle.load(f)

        offline_phishing_eml_trained = len(train_Xp)

        train_X = np.append(train_X, train_Xp, axis=0)
        train_Y = np.append(train_Y, train_Yp, axis=0)

        try:  # for paginated ONLINE training
            with urllib.request.urlopen(_url, timeout=10) as response:
                emails_list = json.loads(response.read())
                online_eml_trained = online_eml_trained + len(emails_list)
                json_header_list = play_with_eml_list(emails_list)
                train_X1, train_Y1 = \
                    np.array(Preprocess(json_header_list, None, None, Weird_keys, subject_classifier_nb))[
                        [1, 3]].tolist()
                train_X = np.append(train_X, train_X1, axis=0)
                train_Y = np.append(train_Y, train_Y1, axis=0)

            page = 2
            while page > 1:
                with urllib.request.urlopen(_url + '?page=%d' % page, timeout=10) \
                        as response:
                    emails_list = json.loads(response.read())
                    online_eml_trained = online_eml_trained + len(emails_list)

                    if not emails_list:
                        break
                    else:
                        page += 1

                    json_header_list = play_with_eml_list(emails_list)
                    train_X2, train_Y2 = \
                        np.array(Preprocess(json_header_list, None, None, Weird_keys, subject_classifier_nb))[
                            [1, 3]].tolist()
                    train_X = np.append(train_X, train_X2, axis=0)
                    train_Y = np.append(train_Y, train_Y2, axis=0)
        except Exception:
            traceback.print_exc(file=sys.stdout)
            output_json['progress'] = traceback.format_exc()
            output_json["Status"] = 'Not OK'

        # print(len(train_X), len(train_Y))
        if not Path(file_name_updated_rand_forest_model).is_file():
            os.makedirs(os.path.dirname(file_name_updated_rand_forest_model), exist_ok=True)
            with open(file_name_updated_rand_forest_model, "w") as f:
                pass
        save_incr_RandomForest(train_X, train_Y, file_name_updated_rand_forest_model)
    except Exception:
        traceback.print_exc(file=sys.stdout)
        output_json['progress'] = traceback.format_exc()
        output_json["Status"] = 'Not OK'

    output_json["online_eml_trained"] = online_eml_trained
    output_json["offline_benign_eml_trained"] = offline_benign_eml_trained
    output_json["offline_phishing_eml_trained"] = offline_phishing_eml_trained

    total_eml_trained = online_eml_trained + offline_benign_eml_trained + offline_phishing_eml_trained

    output_json["total_eml_trained"] = total_eml_trained
    return output_json


def start_testing(request):
    header_b = None
    header_ph = None
    Weird_keys = load_pickle_from_file(file_name_Weird_keys)
    Message_IDs = load_pickle_from_file(file_name_message_IDs)

    test_instance = func_convert_HKEY_tolower(request['email-header'])
    subject_classifier_nb = load_pickle_from_file(file_name_subject_classifier_nb)
    # rand_forest_model_file_name = FILE_ROOT + '/model/random_forest_model_incr.pkl'

    # updated_rf_model_file = Path(file_name_updated_rand_forest_model)
    if Path(file_name_updated_rand_forest_model).is_file():
        try:
            rf_model = load_pickle_from_file(file_name_updated_rand_forest_model)
        except:
            rf_model = load_pickle_from_file(file_name_baseline_rand_forest_model)
    else:
        rf_model = load_pickle_from_file(file_name_baseline_rand_forest_model)

    random_forest_response = RandomForest_Model(rf_model, test_instance, header_b, header_ph,
                                                Weird_keys, subject_classifier_nb)
    rbased_response = rbased_classifier(test_instance, Message_IDs, request['email-header'])

    response = {
        'random_forest_response': random_forest_response,
        'rule-based-responses': rbased_response,
        'Status': '200 OK',
    }

    return response


if __name__ == '__main__':
    # # delete starts
    # # status = start_training('https://panacea-asteria.herokuapp.com/api/v1/classifications/normal/emls.json')
    # status = start_training('http://10.108.18.21:3000/api/v1/classifications/normal/emls.json')
    # print(status)
    # exit(1)
    # # delete ends

    if len(sys.argv) > 1:
        _url = sys.argv[1]

        resp = start_training(_url)

        print(resp)
    else:
        input_file_name = BASE_DIR + '/PANACEA_main_input.txt'
        request = load_pickle_from_file(input_file_name)

        # logger.info("Request: {}".format(request))
        resp = start_testing(request)
        print(json.dumps(resp))
