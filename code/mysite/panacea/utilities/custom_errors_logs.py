import os
from collections import deque
from datetime import datetime
import pickle

from mysite.settings import MEDIA_ROOT

error_log_file_name = os.path.join(MEDIA_ROOT, 'error_logs.pkl')
total_error_size = 9999
stack = deque(maxlen=total_error_size)


def save_pickle_to_file(file_name, _object):
    with open(file_name, 'wb') as handle:
        pickle.dump(_object, handle, protocol=pickle.HIGHEST_PROTOCOL)


def load_pickle_from_file(file_name):
    with open(file_name, 'rb') as handle:
        _output = pickle.load(handle)
    return _output


def write_error_logs(message_id=None, message=None):
    global error_log_file_name
    global stack
    try:
        fixed_error_stack = load_pickle_from_file(error_log_file_name)
    except Exception as e:
        fixed_error_stack = stack

    error_body = {
        "message_id": message_id,
        "timestamp": datetime.today().strftime('%Y-%m-%d %H:%M:%S'),
        "error_message": message,
    }
    fixed_error_stack.append(error_body)
    save_pickle_to_file(error_log_file_name, fixed_error_stack)


def get_saved_error_logs():
    global error_log_file_name
    try:
        fixed_error_stack = load_pickle_from_file(error_log_file_name)
        all_error_logs = list(fixed_error_stack)
    except:
        return []
    return all_error_logs


if __name__ == '__main__':
    write_error_logs(message_id=1)
    print(get_saved_error_logs())
