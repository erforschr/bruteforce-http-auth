import datetime

RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
BLUE = '\033[34m'
MAGENTA = '\033[35m'
CYAN = '\033[36m'
WHITE = '\033[37m'
RESET = '\033[39m'


class log:
    def __init__(self, debug=False):
        self.__debug = debug

    def __enter__(self):
        file_basename = 'http_auth_bruteforce_'
        date = datetime.datetime.now().strftime('%Y-%m-%d_%H:%M:%S')

        self.file = open(file_basename + date + '.log')

    def __exit__(self, type, value, traceback):
        self.file.close()

    def success(self, msg):
        self.file.write(msg)

        date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print('[' + date + ']' + GREEN + msg + RESET)

    def info(self, msg):
        self.file.write(msg)

        if self.__debug:
            date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print('[' + date + ']' + BLUE + msg + RESET)

    def warn(self, msg):
        self.file.write(msg)

        if self.__debug:
            date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print('[' + date + ']' + YELLOW + msg + RESET)

    def error(self, msg):
        self.file.write(msg)

        if self.__debug:
            date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print('[' + date + ']' + RED + msg + RESET)