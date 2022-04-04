from extends.global_vars import changable_rsa_params
from extends.global_vars import error_msgs
from extends.user_inter import error_msg

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA512


# @brief Генерация публичного и приватного ключей
#        для алгоритма RSA.
#
# @param params Параметры для алгоритма RSA.
#
# @return публичный и приватный ключи, 
#         если операция завершилась успешно,иначе None.
def gen_rsa(params):
	try:
		private_key = RSA.generate(changable_rsa_params['size'], 
			e=changable_rsa_params['e'])

		public_key = private_key.publickey()
	except ValueError:
		error_msg(error_msgs["bad_rsa_gen"])
		return None,None

	else:
		return (bytes(public_key.exportKey('PEM')),
			bytes(private_key.exportKey('PEM')))

# @brief Генерация цифровой подписи набора данных.
#
# @param data Набор данных.
# @param params Параметры для генерации цифровой подписи.
#
# @return цифровая подпись, если операция заврешилась успешно,
#         иначе None
def gen_signature(data, params):
	try:
		signer = PKCS1_v1_5.new(RSA.importKey(params[0]))
		hash_value = SHA512.new(data)

	except ValueError:
		error_msg(error_msgs["bad_sign_gen"])
		return None

	else:
		return signer.sign(hash_value)

	
# @brief Сгенерировать сессионный ключ с помощью алгоритма AES.
#
# @param params Параметры для алгоритма AES.
#
# @return Сессионный ключ, если операция завершилась успешно,
#         иначе None.
def gen_aes(params=[]):
	try:
		session_key = Random.new().read(32)
	except:
		error_msg(error_msgs["bad_aes_gen"])
		return None
	else:
		return session_key

# @brief Зашифровать набор данных при помощи алгоритма AES.
#
# @param data Набор исходных данных.
# @param params Параметры для алгоритма AES.
#
# @return Зашифрованные данные, если операция завершилась успешно,
#         иначе None.
def encrypt_aes(data, params):
	try:
		iv = Random.new().read(16)
		obj = AES.new(params[0], AES.MODE_CFB, iv)
		encrypted_data = iv + obj.encrypt(data)
	except ValueError:
		error_msg(error_msgs["bad_enc"])
		return None
	else:
		return bytes(encrypted_data)

# @brief Расшифровать набор данных при помощи алгоритма AES.
#
# @param data Набор зашифрованных данных.
# @param params Параметры для алгоритма AES.
#
# @return Расшифрованные данные, если операция завершилась успешно,
#         иначе None.
def decrypt_aes(data, params):
	try:
		iv = data[:16]
		obj = AES.new(params[0], AES.MODE_CFB, iv)
		decrypted_data = obj.decrypt(data)
		decrypted_data = decrypted_data[16:]
	except ValueError:
		error_msg(error_msgs["bad_dec"])
		return None
	else:
		return decrypted_data

# @brief Шифрование данных при помощи алгоритма RSA.
#
# @param data Исходные данные.
# @param params Параметры для алгоритма RSA.
#
# @return Зашифрованные данные, если операция завершилась успешно,
#         иначе None
def encrypt_rsa(data, params):
	try:
		cipherrsa = PKCS1_OAEP.new(RSA.importKey(params[0]))
		encrypted_data = cipherrsa.encrypt(data)
	except ValueError:
		error_msg(error_msgs["bad_enc"])
		return None
	else:
		return bytes(encrypted_data)

# @brief Расшифровка данных при помощи алгоритма RSA.
#
# @param data Зашифрованный набор данных.
# @param params Параметры для работы RSA.
#
# @return Расшифрованные данные, если операция завершилась успешно,
#         иначе None.
def decrypt_rsa(data, params):
	try:
		cipherrsa = PKCS1_OAEP.new(RSA.importKey(params[0]))
		decrypted_data = cipherrsa.decrypt(data)
	except ValueError:
		error_msg(error_msgs["bad_dec"])
		return None
	else:
		return bytes(decrypted_data)

# @brief Проверка цифровой подписи набора данных.
#
# @param signature Цифровая подпись.
# @param params Параметры для проверки цифровой подписи.
# @param data Набор данных.
#
# @return True, если цифровая подпись подлинная,
#         иначе False.
def verify_signature(signature, params, data):
	hash_value = SHA512.new(data)
	verifier = PKCS1_v1_5.new(RSA.importKey(params[0]))
	stat = verifier.verify(hash_value, signature)
	
	if stat:
		print("Цифровая подпись верифицирована.")
	else:
		print("Цифровая подпись недействительна.")

	return stat