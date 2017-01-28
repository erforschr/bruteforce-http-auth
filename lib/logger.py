import os
import sys
import datetime

RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
MAGENTA = '\033[35m'
CYAN = '\033[36m'
WHITE = '\033[37m'
RESET = '\033[39m'


class logger:
    def __init__(self, debug=False):
        self.__debug = debug

        project_path = (os.path.dirname(os.path.abspath(sys.argv[0])))
        file_basename = 'bruteforce_'
        date = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

        log_file_name = os.path.join(project_path, 'logs', file_basename + date + '.log')

        print(log_file_name)

        self.file = open(log_file_name, 'w')

    def __exit__(self, type, value, traceback):
        self.file.close()

    def success(self, msg):
        self.file.write(msg + '\n')
        print(GREEN + msg + RESET)

    def info(self, msg):
        self.file.write(msg + '\n')
        print(WHITE + msg + RESET)

    def warn(self, msg):
        self.file.write(msg + '\n')
        print(YELLOW + msg + RESET)

    def error(self, msg):
        self.file.write(msg + '\n')
        print(RED + msg + RESET)