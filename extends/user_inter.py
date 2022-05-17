from extends.global_vars import warning_msgs, \
								error_msgs, \
								spec_msgs, \
								RSA_E_PARAM_DEFAULT, \
								RSA_KEYS_BIT_SIZE_DEFAULT, \
								changable_rsa_params, \
								eas_key_size

import os
import re

# @brief Создание имени нового каталога для конкретной директории файлов
#
# @param path Путь до директории.
# @param msgs Сообщения для вывода при определённых ситуациях.
# 
# @return Имя новой директории, если операция завершилась успешно,
#         иначе None.
def create_dir_name(path, msgs):
	# Получаем список каталогов 
	dir_lst =os.listdir(path)
	
	while True:
		name = input("Введите имя каталога для создания >> ")
		if name in dir_lst:
			warning_msg(msgs[0])
		else:
			break

	return name 

# @brief Выбрать имя каталога в заданной директории.
#
# @param path Путь до директории.
# @param msgs Сообщения для вывода при определённых ситуациях.
# 
# @return Путь до выбранной каталога, если операция завершилась успешно,
#         иначе None.
def select_dir(path, msgs):
	# Получаем список каталогов 
	dir_lst =os.listdir(path)
	if not len(dir_lst):
		error_msg(msgs[0] + "\n" + path + "\n")
		return None

	print("Список каталогов:")
	for i,name in enumerate(dir_lst):
		print(f"{i+1}. {name} .")

	# Получаем номер каталога из списка от пользователя
	while True:
		try:
			value = int(input("Выберите нужный каталог >> "))
			if value < 1 or value > len(dir_lst):
				raise ValueError
		except ValueError:
			warning_msg(msgs[1])
		else:
			break

	return path+'/'+dir_lst[value-1]

# @brief Получение натурального числа от пользвателя.
#
# @param msgs Сообщения для вывода при определённых ситуациях.
#
# @return Полученное число от пользвателя
def get_user_number(msgs):
	while True:
		try:
			value = int(input(msgs[0] + ">> "))
			if value < 1:
				raise ValueError
		except ValueError:
			warning_msg(msgs[1])
		else:
			break

	return value

# @brief Выбрать настройки для используемых криптосистем.
#		 Будут изменены глобальные переменные.
#
# @return True, если операция завершилась успешно,
#         иначе False.
def set_settings():
	print("Для генерации ключей будут использоваться стандартные настройки.")
	print(f"Значение параметра e: {RSA_E_PARAM_DEFAULT}")
	print(f"Размер ключей в битах: {RSA_KEYS_BIT_SIZE_DEFAULT}")
		
	use_default_sett = True
	while True:
		answ = input(f"Хотите изменить настройки? (y/n) >> ")
		
		if answ == 'y':
			use_default_sett = False
			
			# Получаем значение параметра e от польлзователя
			e_param = get_user_number([spec_msgs["ins_e"], warning_msgs["ins_nat"]])
			
			# Получаем значение размера ключа от пользователя
			bit_size_param = get_user_number([spec_msgs["ins_p"], warning_msgs["ins_nat"]])
	
			# Сохраняем настройки пользователя
			changable_rsa_params["e"] = e_param     
			changable_rsa_params["size"] = bit_size_param
			break

		elif answ == 'n':
			changable_rsa_params["e"] = RSA_E_PARAM_DEFAULT     
			changable_rsa_params["size"] = RSA_KEYS_BIT_SIZE_DEFAULT
			break
		else:
			warning_msg([""])

# @brief Получение пароля от приватного ключа RSA
#
# @param msgs Сообщения для вывода при определённых ситуациях.
#
# @return Пароль, переведённый в байты
def get_pswd_for_priv_k(msgs):
	paswd=b""
	while True:
		try:
			paswd = input(msgs[0] + ">> ")
			if len(paswd) > eas_key_size or not re.search(" ", paswd) is None:
				raise ValueError
			break
		except ValueError:
			warning_msg(msgs[1])

	paswd += " "*(eas_key_size - len(paswd))
	
	return paswd.encode(encoding="utf-8")


# @brief Вывод сообщения об ошибке.
#
# @param msg Сообщение для вывода.
# 
# @return void.
def error_msg(msg):
	print("Error: " + msg + warning_msgs["remainder"])

# @brief Вывод предупреждающего сообщения.
#
# @param msg Сообщения для вывода.
# 
# @return void.
def warning_msg(msg):
	print("Warning: " + msg + warning_msgs["remainder"])

# @brief Вывод сообщения об успехе.
#
# @param msg Сообщения для вывода.
# 
# @return void.
def success(msg):
	print("Success: "+msg)