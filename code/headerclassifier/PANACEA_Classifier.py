import csv
import logging
import pickle
import sys
import traceback
from collections import Counter

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split

from PANACEA_functions import intersection, func_import_model, \
    reg_domain, authentication_HKEYS, DMARC_existence
from PANACEA_rules import HKEY_existence
from Utility import FILE_ROOT

# from PANACEA_subject import subject_classifier_nb

logger = logging.getLogger('header_classifier_classification.py')
logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                    datefmt='%Y-%m-%d:%H:%M:%S',
                    level=logging.DEBUG)


# rf_from_file = None


def loadCsv(filename):
    lines = csv.reader(open(filename, "rb"))
    dataset = list(lines)
    for i in range(len(dataset)):
        dataset[i] = [float(x) for x in dataset[i]]
    return dataset


def func_CSVread(fname):
    table = []
    with open(fname, 'r', encoding="ISO-8859-1") as csvfile:
        readCSV = csv.reader(csvfile)
        for row in readCSV:
            table.append(row)
        return table


def func_Create_dataset_list(Header_Dictlist, class_type, WEIRD_KEYS, SUB_Classifier):
    # print('Generating dataset....')
    if type(Header_Dictlist) != list:
        temp_list = []
        temp_list.append(Header_Dictlist)
        Header_Dictlist = temp_list

    ds_lst = []
    for hdr in Header_Dictlist:
        hdr_key = list(hdr.keys())
        counter = Counter(hdr_key)
        hdr_lst = []
        try:
            hdr_lst.append(int((hdr['date'][0].split()[5])))
        except:
            hdr_lst.append(2500)
        # No. of receivers (4)
        try:
            hdr_lst.append(len(hdr['received']))
        except:
            hdr_lst.append(0)
        # Contains D-KIM (5)
        if 'dkim-signature' in hdr_key:
            hdr_lst.append(1)
        else:
            hdr_lst.append(0)
        # Contains ARC_MSG_Sign(6)
        if 'arc-message-signature' in hdr_key:
            hdr_lst.append(1)
        else:
            hdr_lst.append(0)
        # Contains Authentication-Result
        if 'authentication-results' in hdr_key:
            hdr_lst.append(1)
        else:
            hdr_lst.append(0)
        # Contains any Authentication
        if len(intersection(hdr_key, authentication_HKEYS)) > 0:
            hdr_lst.append(1)
        else:
            hdr_lst.append((0))
        # Contains X-original-sender
        if 'x-original-sender' in hdr_key:
            hdr_lst.append(1)
        else:
            hdr_lst.append(0)
        # To existence
        if 'to' in hdr_key:
            hdr_lst.append(1)
        else:
            hdr_lst.append(0)

        # Received existence
        if 'received' in hdr_key:
            hdr_lst.append(1)
        else:
            hdr_lst.append(0)
        # Message_ID existence
        if 'message-id' in hdr_key:
            hdr_lst.append(1)
        else:
            hdr_lst.append(0)
        # Return_Path existence
        if 'return-path' in hdr_key:
            hdr_lst.append(1)
        else:
            hdr_lst.append(0)
        # Reply_to existence
        if 'reply-to' in hdr_key:
            hdr_lst.append(1)
        else:
            hdr_lst.append(0)
        # InReply_to existence
        if 'in-reply-to' in hdr_key:
            hdr_lst.append(1)
        else:
            hdr_lst.append(0)
        # Message-ID and From domain partial matching
        try:
            if reg_domain.findall(hdr['from'][0])[0] in reg_domain.findall(hdr['message-id'][0])[0]:
                hdr_lst.append(1)
            else:
                hdr_lst.append(0)
        except:
            hdr_lst.append(0)
        # Message-ID and return-path domain partial matching
        try:
            if reg_domain.findall(hdr['return-path'][0])[0] in reg_domain.findall(hdr['message-id'][0])[0]:
                hdr_lst.append(1)
            else:
                hdr_lst.append(0)
        except:
            hdr_lst.append(0)
            # From and reply-to domain partial matching
        try:
            if reg_domain.findall(hdr['from'][0])[0] in reg_domain.findall(hdr['reply-to'][0])[0]:
                hdr_lst.append(1)
            else:
                hdr_lst.append(0)
        except:
            hdr_lst.append(0)
        # 'subject_score',
        try:
            hdr_lst.append(SUB_Classifier.predict_proba(np.array([hdr['subject'][0]]))[0][0])
        except:
            hdr_lst.append(0.5)

        # 'SPF (pass/fail)',
        if HKEY_existence(hdr, 'received-spf') == 1:
            if hdr['received-spf'][0].startswith('pass'):
                hdr_lst.append(1)
            else:
                hdr_lst.append(0)
        else:
            hdr_lst.append(0)
        # 'DMARC exist',
        if DMARC_existence(hdr) == 1:
            hdr_lst.append(1)
        else:
            hdr_lst.append(-1)

        # 'DMARC(fail)',
        if DMARC_existence(hdr) == 1:
            if 'dmarc=fail' in " ".join(hdr['authentication-results']) or 'dmarc=none' in " ".join(
                    hdr['authentication-results']):
                hdr_lst.append(1)
            else:
                hdr_lst.append(0)
        else:
            hdr_lst.append(0)
        # 'Unknown host'
        if 'received' in hdr_key:
            if 'unknown' in hdr['received'][len(hdr['received']) - 1]:
                hdr_lst.append(1)
            else:
                hdr_lst.append(0)
        else:
            hdr_lst.append(0)
        hdr_lst.append(class_type)

        ds_lst.append(hdr_lst)

    return ds_lst


def Preprocess(HEADER_B, HEADER_PH, HEADER_NAN, WEIRD_KEYS, SUB_Classifier):
    features = ["Time-Zone", "Number of receivers", "Contains DKIM?", "Contains ARC_MSG_Sign?",
                "Contains Authentication-Result", "Contains X-original-sender?", "Contains any Authentication",
                "To: exist", "Received: exist", "Message_ID: exist", 'Return_Path: exist',
                'Reply_To: exist', 'InReply_To: exist', "Message-ID and From partial matching",
                "Message-ID and return-path partial matching", "From and reply-to domain partial matching",
                'subject_score', 'SPF (pass/fail)', 'DMARC exist', 'DMARC(pass/fail)', 'Unknown host', 'Class']

    if HEADER_NAN != None:
        h_nan = func_Create_dataset_list(HEADER_NAN, 'Unknown', WEIRD_KEYS, SUB_Classifier)
        # h_b = func_Create_dataset_list(HEADER_B, 'benign', WEIRD_KEYS)
        # h_ph = func_Create_dataset_list(HEADER_PH, 'phishing', WEIRD_KEYS)
        df = pd.DataFrame(h_nan, columns=features).set_index('Class', True)
        ## Data preparation

        # LE = preprocessing.LabelEncoder()
        # X = np.array(df)
        # for i in range(X.shape[1]):
        #     X[:, i] = LE.fit_transform(X[:, i])
        # df = df[df.index == 'Unknown']
        # new_test_sample = X[0]
        # Y = np.array(df.index)
        # X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.1, random_state=17)
        # Y_test = 'benign'

        return np.array(df)
    else:
        if HEADER_B != None:
            h_b = func_Create_dataset_list(HEADER_B, 'benign', WEIRD_KEYS, SUB_Classifier)
        else:
            h_b = []
        if HEADER_PH != None:
            h_ph = func_Create_dataset_list(HEADER_PH, 'phishing', WEIRD_KEYS, SUB_Classifier)
        else:
            h_ph = []
        ds = pd.DataFrame(h_b + h_ph, columns=features).set_index('Class', True)
        ds_size = ds.shape[0]
        X = np.array(ds)
        Y = np.array(ds.index)
        if ds_size <= 1:
            X_train = X
            Y_train = Y
            X_test = np.array('nan')
            Y_test = np.array('benign')
        else:
            X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.00001, random_state=17)
        return ds, X_train, X_test, Y_train, Y_test


def save_incr_RandomForest(X_train, Y_train, rand_forest_model_file_name):
    try:
        # logger.info('Building model...')
        RF = RandomForestClassifier(n_estimators=100, random_state=17)
        RF.fit(X_train, Y_train)
        # rand_forest_model_file_name = FILE_ROOT + '/model/random_forest_model_incr.pkl'
        logger.info("dumping modle into: {}".format(rand_forest_model_file_name))
        pickle.dump(RF, open(rand_forest_model_file_name, 'wb'))
    except Exception:
        traceback.print_exc(file=sys.stdout)
        logger.info('Building model failed')


def RandomForest(HEADER_B, HEADER_PH, HEADER_NAN, WEIRD_KEYS, SUB_Classifier):
    try:
        logger.info('Building model...')
        df, X_train, X_test, Y_train, Y_test = Preprocess(HEADER_B, HEADER_PH, HEADER_NAN, WEIRD_KEYS, SUB_Classifier)
        RF = RandomForestClassifier(n_estimators=100, random_state=17)
        RF.fit(X_train, Y_train)
        rand_forest_model_file_name = FILE_ROOT + '/model/random_forest_model.pkl'
        logger.info("dumping modle into: {}".format(rand_forest_model_file_name))
        pickle.dump(RF, open(rand_forest_model_file_name, 'wb'))
        lables = list(df.columns)
        feature_importance = RF.feature_importances_
        Y_pred = RF.predict(X_test)
        acc = accuracy_score(Y_test, Y_pred)
        conf = confusion_matrix(Y_test, Y_pred)
    except:
        return False
    return True


def RandomForest_temp(HEADER_B, HEADER_PH, HEADER_NAN, WEIRD_KEYS, SUB_Classifier):
    print('Building model...')
    df, X_train, X_test, Y_train, Y_test = Preprocess(HEADER_B, HEADER_PH, HEADER_NAN, WEIRD_KEYS, SUB_Classifier)
    RF = RandomForestClassifier(n_estimators=100, random_state=17)
    RF.fit(X_train, Y_train)
    rand_forest_model_file_name = FILE_ROOT + '\\model\\random_forest_model.pkl'
    print("dumping modle into: {}".format(rand_forest_model_file_name))
    pickle.dump(RF, open(rand_forest_model_file_name, 'wb'))
    print("dumping done!")
    # lables = list(df.columns)
    # feature_importance = RF.feature_importances_
    Y_pred = RF.predict(X_test)
    # acc = accuracy_score(Y_test, Y_pred)
    conf = confusion_matrix(Y_test, Y_pred)
    return RF


def RandomForest_Model(rf_from_file, TEST_SAMPLE, HEADER_B, HEADER_PH, WEIRD_KEYS, SUB_Classifier):
    # global rf_from_file
    # if not rf_from_file:
    #     logger.info("Loading model from file: {}".format(fname))
    #     rf_from_file = func_import_model(fname)
    # else:
    #     logger.info("Model already loaded")
    sample = Preprocess(HEADER_B, HEADER_PH, TEST_SAMPLE, WEIRD_KEYS, SUB_Classifier)
    RF_newtest_pred = rf_from_file.predict(sample.reshape(1, -1))
    RF_newtest_score = round(rf_from_file.predict_proba(sample.reshape(1, -1))[:, 1][0], 2)
    res = {"score": RF_newtest_score,
           "classification": RF_newtest_pred[0],
           "Status": "OK"
           }

    return res
