RSA_E_PARAM_DEFAULT = 65537
RSA_KEYS_BIT_SIZE_DEFAULT = 2048

changable_rsa_params = dict()

eas_key_size = 16
iv_size = 16

dirs = {
	"keys": "rsa_keys", \
	"for encrypt": "encryption", \
	"for decrypt": "decryption", \
	"get encrypted": "results" \
}

read_me_path = "README"

cmd_info = {
	"help" : "Просмотр справки по программе и имеющемся наборе команд. ", \
	"gen keys" : "Сгенерировать ключи RSA для шифрования сессионного ключа. ", \
	"encrypt" : "Шифрование файла с помощью сессионного ключа AES. ", \
	"decrypt" : "Дегифрование файла с помощью сессионного ключа AES. ", \
	"exit" : "Выход из программы. " \
}

file_names = {
	"pub_k":"public_key", "pri_k": "private_key", \
	"data_en": "encrypt", "data_dec" : "decrypt", \
	"sig":"signature", "sess":"session_key", \
	"rec_key": "public_key_recieved", "snd_key":"public_key_sended", \
	"dec_f":"decrypted_file" \
}

avail_cmds = ["help","gen keys","encrypt","decrypt","exit","cancel"]

answers_lst = {"yes":"y","no":"n"}

warning_msgs = {
	"remainder" : "Воспользуйтесь командой \"help\". ",\
	"n_fnd": "Команда не найдена. ",
	"chose_num" : "Введите номер директории из списка выше. ", \
	"ins_nat" : "Введите натуральное число. ", \
	"inv_answ" : "Дан невалидный ответ. Попробуйте ещё раз. ", \
	"alr_exis" : "Директория уже существует. ", \
	"name_exis" : "Такое название уже существует. Попробуйте ещё раз. ", \
	"bad_passw" : "Длина пароля должна быть в диапозоне от 6 до 16 символов включительно и не содержать пробелов. Попробуйте ещё раз"
}

error_msgs = {
	"dir_load" : "У вас нет нужных файлов в выбранной директории. ", \
	"empty_folder" : "Директория пуста. ", \
	"no_pair" : "У вас нет пары для шифрования. ", \
	"sig_sve" : "Не удалось создать цифровую подпсь. ", \
	"ct_sve" : "Не удалось сохранить файл. ", \
	"bad_dec" : "Ошибка при дешифровании. ", \
	"bad_enc" : "Ошибка при шифровании. ", \
	"bad_sign_gen" : "Ошибка при генерации цифровой подписи. ", \
	"bad_rsa_gen" : "Ошибка при генерации ключей RSA. ", \
	"bad_aes_gen" : "Ошибка при генерации сессионного ключа AES. ", \
	"bad_uid" : "Необходимо запустить программу с правами суперпользователя. ", \
	"bad_read_me" : "Не удалось открыть файл с описание программы (Read.me).", \
	"inv_pass" : "Введён неверный пароль для доступа к приватному ключу RSA."
}

success_msgs = {
	"get rsa_keys": "Ключи RSA получены. ", \
}

spec_msgs = {
	"ins_e": "Введите значение параметра e ", \
	"ins_p": "Введите размер ключей в битах ", \
	"dir_nme" : "Введите номер директории с файлом для шифрования ", \
	"crt_psw_priv_k" : "Введите пароль для шифрования приватного ключа ", \
	"ins_pasw_priv_k" : "Введите пароль для дешифровки приватного ключа "
}