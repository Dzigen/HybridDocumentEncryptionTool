from extends.user_inter import error_msg, warning_msg
import os
from extends.global_vars import cmd_info, read_me_path, error_msgs

# @brief Вывод информации о программе с описанием имеющегося набора команд.
#
# @return void
def command_info():
	desc = read_file(read_me_path,[error_msgs['bad_read_me']],'')
	print(desc,end="\n\n")

	print("Список доступных команд: ")
	for cmd in cmd_info:
		print(f"{cmd} - {cmd_info[cmd]}")
	print(end='\n\n')
	
# @brief Чтение данных из файла.
#
# @param path Путь до файла.
# @param msgs Сообщения для вывода при определённых ситуациях.
# @param mode Дополнительный параметр для указания способа открытия файла.
# 
# @return None, если операция завершилась неудачно,
#         иначе прочитанные данные из файла.
def read_file(path, msgs, mode="b"):
	try:
		with open(path, "r"+mode) as fd:
			data = fd.read()

	except OSError:
		error_msg(msgs[0] + "\n" + path + "\n")
		return None

	else:
		return data

# @brief Сохранение данных в файл.
#
# @param path Путь до файла.
# @param data Сохраняемые данные.
# @param msgs Сообщения для вывода при определённых ситуациях.
# @param mode Дополнительный параметр для указания способа открытия файла.
# 
# @return True, если операция завершилась успешно,
#         иначе False.
def save_file(path, data, msgs, mode="b"):
	try:
		with open(path, "w"+mode) as fd:
			fd.write(data)

	except OSError:
		error_msg(msgs[0] + "\n" + path + "\n")
		return False

	else:
		return True

# @brief Создание нового каталога.
#
# @param path Путь до нвого каталога.
# @param name Имя новго каталога.
# @param msgs Сообщения для вывода при определённых ситуациях.
# 
# @return True, если операция завершилась успешно,
#         иначе False.
def create_dir(path, msgs):
	try:
		os.mkdir(path)

	except OSError:
		warning_msg(msgs[0] + "\n" + path + "\n")
		return False

	else:
		return True

# @brief Получение абсолютного пути до текущей директории
#
# @return Абсолютный путь текущей директории.
def get_abs_path():
	return os.path.abspath("")