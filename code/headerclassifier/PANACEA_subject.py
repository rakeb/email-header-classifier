import pickle

import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_extraction.text import CountVectorizer
import nltk as nk
from sklearn.metrics import accuracy_score
# from tensorflow import confusion_matrix

from Utility import FILE_ROOT


#
# nk.download('wordnet')
prtr_stemmer = nk.stem.PorterStemmer()
from nltk.stem import WordNetLemmatizer
lemmatizer = WordNetLemmatizer()
import re
import random
# from PANACEA_functions import *
# from PANACEA_main import FILE_ROOT
from sklearn.naive_bayes import MultinomialNB
# static_dir_headerclassifier = FILE_ROOT
static_dir_headerclassifier = 'C:/Users/eaghaei/Dropbox/convertToPy/'
from PANACEA_functions import func_import_benign_data
from PANACEA_functions import func_convert_HKEY_tolower
from PANACEA_functions import load_dict_from_file
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
import tensorflow as tf

def read_benign():
    header_b1_list, header_b1 = func_import_benign_data(static_dir_headerclassifier + "benign_header/benign.txt", "+++")
    header_b2_list, header_b2 = func_import_benign_data(static_dir_headerclassifier + "benign_header/benign_gmail.txt",
                                                        "+++")
    header_b3_list, header_b3 = func_import_benign_data(static_dir_headerclassifier + "benign_header/benign_qi.txt",
                                                        "+++")
    header_b4_list, header_b4 = func_import_benign_data(static_dir_headerclassifier + "benign_header/benign_sash.txt",
                                                        "+++")
    headers = func_convert_HKEY_tolower(header_b1+header_b2+header_b3+header_b4)
    return headers

def read_phish():
    header_ph_fname = static_dir_headerclassifier + 'phishing.txt'
    headers = load_dict_from_file(header_ph_fname)
    headers = func_convert_HKEY_tolower(headers)
    return headers

# collect subjects
def subject_collector(HEADER_LIST):
    subject = []
    for hdr in HEADER_LIST:
        try:
            subject.append(hdr['subject'][0])
        except:
            continue
    return subject
# non english replace
def remove_utf_subjects(SUBJECT_LIST):
    subject_list = []
    for subject in SUBJECT_LIST:
        if '=?utf-8?b?' not in subject:
            subject_list.append(subject)
        else:
            subject = 'non_english'
            subject_list.append(subject)
    return subject_list

def stem(TXT):
    TXT = TXT.split(" ")
    for token in range(0, len(TXT)):
        TXT[token] = prtr_stemmer.stem(TXT[token])
    TXT = " ".join(TXT)
    return TXT
    return

def lemmitize(TXT):
    TXT = TXT.split(" ")
    for token in range(0, len(TXT)):
        TXT[token] = lemmatizer.lemmatize(TXT[token],pos='v')
    TXT = " ".join(TXT)
    return TXT


# merge list, separate special chars by space, stemming
def merge_clean(LIST):
    # STR = ''.join(map(str, LIST))
    # STR = ' '.join(STR.split())
    STR_list = []
    for STR in LIST:
        # STR = re.sub(r'(?<=[.,!;:?])(?=[^\s])', r' ', STR)
        # STR = re.sub(r'(?<=[\w])(?=[.,!;:?])', r' ', STR)
        STR = lemmitize(STR)
        STR_list.append(STR)
    return STR_list

# label list creator
def label_list_creator(LIST_B, LIST_PH):
    labels = []
    for i in range(0, len(LIST_B)):
        labels.append('benign')
    for j in range(0,len(LIST_PH)):
        labels.append('phishing')
    return labels
##
def subject_classifier(HEADER_PH,HEADER_B):
    header_ph_sub = subject_collector(HEADER_PH)
    header_b_sub = subject_collector(HEADER_B)
    header_ph_sub = remove_utf_subjects(header_ph_sub)
    header_b_sub = remove_utf_subjects(header_b_sub)
    bow_header_ph = merge_clean(header_ph_sub)
    bow_header_b = merge_clean(header_b_sub)
    x = np.array(bow_header_b + bow_header_ph)
    y = np.array(label_list_creator(bow_header_b,bow_header_ph))
    X_train, X_test, Y_train, Y_test = train_test_split(x, y, test_size=0.1, random_state=10)
    tfidf = TfidfVectorizer(analyzer="word",
                                    ngram_range = (1,3),
                                    max_df = 0.8,
                                    min_df = 1,
                                    use_idf = True,
                                    smooth_idf=True)
    vect = CountVectorizer()
    clf = MultinomialNB()
    subj_preprocess = Pipeline([('tfidf', tfidf),
                      ('clf',clf)])
    model = subj_preprocess.fit(X_train,Y_train)
    pickle.dump(model, open(FILE_ROOT + '/model/subject_classifier.pkl', 'wb'))
    # Y_pred = model.predict(X_test)
    # acc = accuracy_score(Y_test, Y_pred)
    # conf = confusion_matrix(Y_test, Y_pred)

    file_name = FILE_ROOT + '/model/subject_classifier.pkl'
    with open(file_name, 'rb') as handle:
        _output = pickle.load(handle)

    return model,X_test,Y_test
#
# from headerclassifier_code.headerclassifier.temp_main import header_ph, header_b
# subject_classifier(header_ph,header_b)



# test = subject_classifier_nb.predict(X_test)
# print(np.mean(test == Y_test))
# rf_test = rf.predict(X_test)

# def sub_classifier_test():
#     SUBJECT = None
#     while SUBJECT!='exit':
#         SUBJECT = input('Enter the subject: ')
#         print("Prediction: ",model.predict(np.array([SUBJECT]))[0])
#         print('Probabiliy([benign, malicious]): ',model.predict_proba(np.array([SUBJECT])))
# sub_classifier_test()


###############################################################################################################
# tfidf_vector = tfidf.fit_transform(X_train,Y_train)
# tfidf_array = tfidf_vector.toarray()
# trSet_tfidf = pd.DataFrame(tfidf_vector, columns=tfidf.get_feature_names(),index=['benign','phishing'])
# X = np.array(trSet_tfidf)
# Y = np.array(trSet_tfidf.index)
# clf = MultinomialNB()
# clf.fit(X,Y)

###test

