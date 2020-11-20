import logging
import os
import pickle
import numpy

logger = logging.getLogger('header_classifier_utility.py')
logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                    datefmt='%Y-%m-%d:%H:%M:%S',
                    level=logging.WARNING)

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
FILE_ROOT = os.path.join(BASE_DIR, 'files')


# call this function to check a message_id is benign or spam listed earlier
# filter_type must be 'benign' or 'spam
def is_message_id_in_history(message_id, filter_type):
    try:
        if filter_type == 'benign':
            file_name = BASE_DIR + '/benign_message_id_list.pkl'
        else:
            file_name = BASE_DIR + '/spam_message_id_list.pkl'
        logger.info("Searching cached message_id into file: {}".format(file_name))
        message_id_list = load_pickle_from_file(file_name)

        # logger.info("Cached message_id: {}".format(message_id_list))

        if message_id in message_id_list:
            return True
        else:
            return False
    except Exception as e:
        logger.info("Exception occured: {}".format(e))

        return False


def load_pickle_from_file(file_name):
    with open(file_name, 'rb') as handle:
        _output = pickle.load(handle)
    return _output
