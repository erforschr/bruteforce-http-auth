#!/usr/bin/env python3
# -*- coding: utf8 -*-

import os
import sys
import datetime



class colors:
	RESET_ALL = '\033[0m'
	BRIGHT = '\033[1m'
	DIM = '\033[2m'
	UNDERLINE = '\033[4m'
	NORMAL_BRIGHTNESS = '\033[22m'

	GREY = '\033[30m'
	RED = '\033[31m'
	GREEN = '\033[32m'
	YELLOW = '\033[33m'
	BLUE = '\033[34m'
	MAGENTA = '\033[35m'
	CYAN = '\033[36m'
	WHITE = '\033[37m'
	RESET = '\033[39m'


class Logger:
	def __init__(self, debug=False):
		self.__debug = debug

		project_path = (os.path.dirname(os.path.abspath(sys.argv[0])))
		filename = 'bruteforce_{}.log'.format(datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S'))
		
		log_file_name = os.path.join(project_path, 'logs', filename)

		if not os.path.isdir(os.path.join(project_path, 'logs')):
			os.makedirs(os.path.join(project_path, 'logs'))

		self.file = open(log_file_name, 'w')

	def __exit__(self, type, value, traceback):
		self.file.close()

	def success(self, msg, update=False):
		self.file.write(msg + '\n')
		
		colored_msg  = colors.GREEN + msg + colors.RESET
		self.print(colored_msg, update)

	def warn(self, msg, update=False):
		self.file.write(msg + '\n')

		colored_msg = colors.YELLOW + msg + colors.RESET
		self.print(colored_msg, update)

	def error(self, msg, update=False):
		self.file.write(msg + '\n')
		
		colored_msg = colors.RED + msg + colors.RESET
		self.print(colored_msg, update)

	def info(self, msg, update=False):
		self.file.write(msg + '\n')
		
		colored_msg = colors.NORMAL_BRIGHTNESS + msg + colors.NORMAL_BRIGHTNESS
		self.print(colored_msg, update)

	def debug(self, msg, update=False):
		self.file.write(msg + '\n')
		
		colored_msg = colors.DIM + msg + colors.NORMAL_BRIGHTNESS
		self.print(colored_msg, update)
	
	def input(self, msg, update=False):
		time = '{}'.format(datetime.datetime.now().strftime('[%H-%M-%S] '))
		colored_time = colors.DIM + time + colors.NORMAL_BRIGHTNESS
		
		colored_msg = colors.BRIGHT + msg + colors.NORMAL_BRIGHTNESS
		
		ans = input(colored_time + colored_msg)
		
		self.file.write(msg + ' ' + ans + '\n')
		
		return ans
	
	def print(self, msg, update=False):
		time = '{}'.format(datetime.datetime.now().strftime('[%H-%M-%S] '))
		colored_time = colors.DIM + time + colors.NORMAL_BRIGHTNESS
		if update:
			print(colored_time + msg, end='\r')
		else:
			print(colored_time + msg)
