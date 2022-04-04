from extends.crypto import *
from extends.global_vars import *
from extends.io_files import *
from extends.user_inter import *
import os
import stat

if not os.getuid() == 0:
	error_msg(error_msgs['bad_uid'])
	exit()

while True:
	changable_rsa_params = dict()
	cmd = input("Введите команду >> ")

	# Справка с описанием доступных команд
	if cmd == avail_cmds[0]:
		command_info()
	
	# Генерация пары ключей для ассиметриченого шифрования
	elif cmd == avail_cmds[1]:
		print("Проверяем наличие нужной папки.")
		rsa_dir_path = get_abs_path() + "/" + dirs["keys"]
		create_dir(rsa_dir_path, [warning_msgs["alr_exis"]])
		print("Готово.", end="\n\n")

		#=======

		# Настройка конфигурации генерации ключей
		set_settings()

		print("Выбираем имя католога для сохранения сгенерированных ключей.")
		rsa_dir_name = create_dir_name(rsa_dir_path, [warning_msgs["name_exis"]])
		rsa_dir_path += "/" + rsa_dir_name
		print("Готово.", end="\n\n")
		
		#=======

		print("Генерация ключей RSA.")
		pub_k, priv_k = gen_rsa([])
		print("Готово.", end="\n\n")

		if pub_k is None or priv_k is None:
			continue

		#=======

		print("Создаём директорию для сохранения ключей RSA")
		rtn = create_dir(rsa_dir_path, [warning_msgs["alr_exis"]])
		print("Готово.", end="\n\n")

		if not rtn:
			continue

		print("Сохраняем ключи RSA в созданный каталог.")
		rtn = save_file(rsa_dir_path + "/" + file_names["pub_k"], pub_k, error_msgs["ct_sve"])
		rtn2 = save_file(rsa_dir_path + "/" + file_names["pri_k"], priv_k, error_msgs["ct_sve"])
		print("Готово.", end="\n\n")

		if not rtn or not rtn2:
			continue 

		os.chmod(rsa_dir_path + "/" + file_names["pri_k"], stat.S_IRUSR)
		

	# Шифрование данных
	elif cmd == avail_cmds[2]:
		print("Проверяем наличие нужной папки.")
		rsa_dir_path = get_abs_path() + "/" + dirs["keys"]
		create_dir(rsa_dir_path, [warning_msgs["alr_exis"]])
		
		enc_dir_path = get_abs_path() + "/" + dirs["for encrypt"]
		create_dir(enc_dir_path, [warning_msgs["alr_exis"]])
		
		dec_dir_path = get_abs_path() + "/" + dirs["for decrypt"]
		create_dir(dec_dir_path, [warning_msgs["alr_exis"]])
		print("Готово.", end="\n\n")

		#=======

		print("Выбираем директорию с RSA ключами.")
		rsa_dir_path = select_dir(rsa_dir_path, 
			[error_msgs["empty_folder"], warning_msgs["chose_num"]])
		print("Готово.", end="\n\n")

		if rsa_dir_path is None:
			continue

		print("Выбор директории с данными для шифрования")
		enc_dir_path = select_dir(enc_dir_path, 
			[error_msgs["empty_folder"], warning_msgs["chose_num"]])
		print("Готово.", end="\n\n")

		if enc_dir_path is None:
			continue

		print("Создание имени новой директории для сохранения зашифрованных данных.")
		dec_dir_name = create_dir_name(dec_dir_path, [warning_msgs["name_exis"]])
		print("Готово.", end="\n\n")

		#=======

		print("Чтение публичного и приватного ключей RSA")
		rsa_pub_key = read_file(rsa_dir_path + "/" + file_names["pub_k"], [error_msgs["dir_load"]])
		rsa_priv_key = read_file(rsa_dir_path + "/" + file_names["pri_k"], [error_msgs["dir_load"]])
		print("Готово.", end="\n\n")

		if rsa_pub_key is None or rsa_priv_key is None:
			continue

		print("Чтение данных для шифрования")
		data = read_file(enc_dir_path + "/" + file_names["data_en"], [error_msgs["dir_load"]])
		print("Готово.", end="\n\n")
		
		if data is None:
			continue

		print("Чтение полученного публичного ключа для использования при шифровании")
		recvd_rsa_pub_key = read_file(enc_dir_path + "/" + file_names["rec_key"], [error_msgs["dir_load"]])
		print("Готово.", end="\n\n")

		if recvd_rsa_pub_key is None:
			continue

		#=======
		
		print("Генерация цифровой подписи данных для шифрования")
		signature = gen_signature(data, [rsa_priv_key])
		print("Готово.", end="\n\n")

		if signature is None:
			continue

		print("Генерация сессионного ключа алгоритмом AES")
		session_key = gen_eas()
		print("Готово.", end="\n\n")
		
		if session_key is None:
			continue

		print("Шифрование исходного набора данных при помощи AES")
		encrypted_data = encrypt_eas(data,[session_key])
		print("Готово.", end="\n\n")
		
		if encrypted_data is None:
			continue

		print("Шифрование сессионного ключа с помощью RSA")
		encrypted_session_key = encrypt_rsa(session_key, [recvd_rsa_pub_key])
		print("Готово.", end="\n\n")

		if encrypted_session_key is None:
			continue

		#=======

		print("Создание папки для сохранения зашифрованных данных")
		dec_dir_path += "/" + dec_dir_name
		rtn = create_dir(dec_dir_path, warning_msgs["alr_exis"])
		print("Готово.", end="\n\n")

		if not rtn:
			continue

		print("Сохраняем зашифрованные данные")
		rtn = save_file(dec_dir_path+"/"+file_names["data_dec"], encrypted_data, error_msgs["ct_sve"])
		print("Готово.", end="\n\n")

		if not rtn:
			continue
		
		print("Сохраняем цифровую подпись")
		rtn = save_file(dec_dir_path+"/"+file_names["sig"], signature, error_msgs["ct_sve"])
		print("Готово.", end="\n\n")
		
		if not rtn:
			continue

		print("Сохраняем зашифрованный сессионный ключ")
		rtn = save_file(dec_dir_path+"/"+file_names["sess"], encrypted_session_key, error_msgs["ct_sve"])
		print("Готово.", end="\n\n")
		
		if not rtn:
			continue

		print("Сохраняем личный публичный ключ для передачи второй стороне")
		rtn = save_file(dec_dir_path+"/"+file_names["snd_key"], rsa_pub_key, error_msgs["ct_sve"])
		print("Готово.", end="\n\n")
	
		if not rtn:
			continue

	# Расшифровка данных
	elif cmd == avail_cmds[3]:
		print("Проверяем наличие нужной папки.")
		rsa_dir_path = get_abs_path() + "/" + dirs["keys"]
		create_dir(rsa_dir_path, [warning_msgs["alr_exis"]])
		
		dec_dir_path = get_abs_path() + "/" + dirs["for decrypt"]
		create_dir(dec_dir_path, [warning_msgs["alr_exis"]])
		
		res_dir_path = get_abs_path() + "/" + dirs["get encrypted"]
		create_dir(res_dir_path, [warning_msgs["alr_exis"]])		
		print("Готово.", end="\n\n")

		#=======

		print("Выбираем директорию с RSA ключами.")
		rsa_dir_path = select_dir(rsa_dir_path, 
			[error_msgs["empty_folder"], warning_msgs["chose_num"]])
		print("Готово.", end="\n\n")

		if rsa_dir_path is None:
			continue

		print("Выбор директории с данными для расшифрвоания.")
		dec_dir_path = select_dir(dec_dir_path, 
			[error_msgs["empty_folder"], warning_msgs["chose_num"]])
		print("Готово.", end="\n\n")

		if dec_dir_path is None:
			continue

		print("Создание имени новой директории для сохранения расшифрованных данных.")
		res_dir_name = create_dir_name(res_dir_path, [warning_msgs["name_exis"]])
		print("Готово.", end="\n\n")

		#=======

		print("Чтение публичного и приватного ключей RSA")
		rsa_pub_key = read_file(rsa_dir_path + "/" + file_names["pub_k"], [error_msgs["dir_load"]])
		rsa_priv_key = read_file(rsa_dir_path + "/" + file_names["pri_k"], [error_msgs["dir_load"]])
		print("Готово.", end="\n\n")

		if rsa_pub_key is None or rsa_priv_key is None:
			continue

		print("Чтение данных для расшифрования")
		encd_data = read_file(dec_dir_path + "/" + file_names["data_dec"], [error_msgs["dir_load"]])
		print("Готово.", end="\n\n")
		
		if encd_data is None:
			continue

		print("Чтение полученного публиного ключа")
		snd_pub_key = read_file(dec_dir_path + "/" + file_names["snd_key"], [error_msgs["dir_load"]])
		print("Готово.", end="\n\n")
		
		if snd_pub_key is None:
			continue

		print("Чтение зашифрованного сессионного ключа.")
		encd_session_key = read_file(dec_dir_path + "/" + file_names["sess"], [error_msgs["dir_load"]])
		print("Готово.", end="\n\n")
		
		if encd_session_key is None:
			continue

		print("Чтение цифровой подписи шифрованного документа.")
		signature = read_file(dec_dir_path + "/" + file_names["sig"], [error_msgs["dir_load"]])
		print("Готово.", end="\n\n")
		
		if signature is None:
			continue

		#=======

		print("Расшифровываем сессионный ключ с помощью RSA.")
		decd_session_key = decrypt_rsa(encd_session_key, [rsa_priv_key])  
		print("Готово.", end="\n\n")

		if decd_session_key is None:
			continue

		print("Расшифровываем данные с помощью сессионного ключа AES.")
		decd_data = decrypt_eas(encd_data, [decd_session_key])
		print("Готово.", end="\n\n")

		if decd_data is None:
			continue

		print("Веривицируем цифровую подпись.")
		ver_stat = verify_sifnature(signature, [snd_pub_key], decd_data)
		print("Готово.", end="\n\n")

		if not ver_stat:
			continue

		#=======

		print("Создание папки для сохранения расшифрованных данных")
		res_dir_path += "/" + res_dir_name
		rtn = create_dir(res_dir_path, warning_msgs["alr_exis"])
		print("Готово.", end="\n\n")

		if not rtn:
			continue

		print("Сохраняем расшифрованные данные в созданную папку.")
		rtn = save_file(res_dir_path+"/"+file_names["dec_f"], decd_data, error_msgs["ct_sve"])
		print("Готово.", end="\n\n")
	
		if not rtn:
			continue

	# Выход из программы
	elif cmd == avail_cmds[4]:
		print("See you!")
		break

	# Неизвестная команда
	else:
		warning_msg(warning_msgs['n_fnd'])