import os
import pickle

from mysite.settings import MEDIA_ROOT

counter_file_name = os.path.join(MEDIA_ROOT, 'unlabeled_data_processed_counter.pkl')


def save_pickle_to_file(file_name, _object):
    with open(file_name, 'wb') as handle:
        pickle.dump(_object, handle, protocol=pickle.HIGHEST_PROTOCOL)


def load_pickle_from_file(file_name):
    with open(file_name, 'rb') as handle:
        _output = pickle.load(handle)
    return _output


def update_unlabeled_data_processed_count(sms_received_message_count=False,
                                          linkedin_received_message_count=False,
                                          email_received_message_count=False,
                                          sms_processed_message_count=False,
                                          linkedin_processed_message_count=False,
                                          email_processed_message_count=False):
    try:
        message_counts = load_pickle_from_file(counter_file_name)
    except Exception as e:
        message_counts = {
            "sms_received_message_count": 0,
            "linkedin_received_message_count": 0,
            "email_received_message_count": 0,
            "sms_processed_message_count": 0,
            "linkedin_processed_message_count": 0,
            "email_processed_message_count": 0
        }

    if sms_received_message_count:
        message_counts['sms_received_message_count'] += 1
    if linkedin_received_message_count:
        message_counts['linkedin_received_message_count'] += 1
    if email_received_message_count:
        message_counts['email_received_message_count'] += 1
    if sms_processed_message_count:
        message_counts['sms_processed_message_count'] += 1
    if linkedin_processed_message_count:
        message_counts['linkedin_processed_message_count'] += 1
    if email_processed_message_count:
        message_counts['email_processed_message_count'] += 1

    save_pickle_to_file(counter_file_name, message_counts)


def get_unlabeled_data_processed_count():
    try:
        return load_pickle_from_file(counter_file_name)
    except:
        return []
