import cryptography
import os
import json
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from pathlib import PurePosixPath
from os import path
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives import hashes, hmac
import important_details


#this method generate the iv with 16 bytes
def genRandom(numBytes):
	IV = os.urandom(numBytes)
	return IV

#This method encrypt a message using AES-CBC using a key and iv
#message- the message to encrypt
#key- the key to encypt the message with   

def Myencypt(message,key):

	if(len(key) < ENC_key_bytes):
		print("The key is less than 32 byes")
		return

	#first step after we verified that the key is not less than 32 byes is to generate the IV
	iv = genRandom(IV_key_bytes)

	#need to pad the message according to PKCS#7 
	pad = padding.PKCS7(PKCS7_SIZE).padder()
	data_padded = pad.update(message)
	data_padded += pad.finalize()

	#initializing an AES CBC cipher instance in order to encrypt the message
	cipher = Cipher(algorithms.AES(key),modes.CBC(iv),backend=default_backend())

	#initializing the encryptor instance
	encryptor = cipher.encryptor()

	#encrypting the message
	cText = encryptor.update(data_padded) + encryptor.finalize()

	
	print(cText)
	print("the message is encypted")

	return cText,iv

def MyencyptMAC(message,ENCkey,HMACkey):

	if(len(ENCkey) < ENC_key_bytes):
		print("The key is less than 32 byes")
		return

	#first step after we verified that the key is not less than 32 byes is to generate the IV
	iv = genRandom(IV_key_bytes)

	#need to pad the message according to PKCS#7 
	pad = padding.PKCS7(PKCS7_SIZE).padder()
	data_padded = pad.update(message)
	data_padded += pad.finalize()

	#initializing an AES CBC cipher instance in order to encrypt the message
	cipher = Cipher(algorithms.AES(ENCkey),modes.CBC(iv),backend=default_backend())

	#initializing the encryptor instance
	encryptor = cipher.encryptor()

	#encrypting the message
	cText = encryptor.update(data_padded) + encryptor.finalize()

	#creating tag
	tag = hmac.HMAC(HMACkey, hashes.SHA256(), backend=default_backend())
	tag.update(cText)
	tag.finalize()

	print(cText)
	print("the message is encypted")

	return cText,iv, tag

def MyDecrypt(cipherText, iv,ENCkey):

	#initializing an AES CBC cipher instance in order to decrypt the message
	cipher = Cipher(algorithms.AES(ENCkey), modes.CBC(iv),backend = default_backend())

	#initializing the decryptor 
	dr = cipher.decryptor()

	#decrypt the message
	data_enc = dr.update(cipherText) + dr.finalize()

	unpadder = padding.PKCS7(PKCS7_SIZE).unpadder()
	message = unpadder.update(data_enc)
	message += unpadder.finalize()

	print("The message is decrypted")

	return message

def MyfileEncrypt(filepath):
	
	key = genRandom(ENC_key_bytes)

	
	f = open(filepath,"rb")
	message = f.read()
	message = b64encode(message)
	f.close()

	#encrypting the message using the encryption method Myencypt and the generated key
	cText, iv = Myencypt(message,key)

	#extracting only the extension from the file name 
	ext = PurePosixPath(filepath).suffix

	#changing the original file extension 
	thisFile = filepath
	base = os.path.splitext(thisFile)[0]
	os.rename(thisFile, base + ".enc")


	return cText,iv,key,ext

def MyfileEncryptMAC(filepath):
	
	HMACkey = genRandom(ENC_key_bytes)
	ENCkey = genRandom(HMAC_key_bytes)

	
	f = open(filepath,"rb")
	message = f.read()
	message = b64encode(message)
	f.close()

	#encrypting the message using the encryption method Myencypt and the generated key
	cText, iv, tag = MyencyptMAC(message,ENCkey,HMACkey)


	#extracting only the extension from the file name 
	ext = PurePosixPath(filepath).suffix

	#changing the original file extension 
	thisFile = filepath
	base = os.path.splitext(thisFile)[0]
	os.rename(thisFile, base + ".enc")


	return cText,iv,tag, ENCkey,HMACkey,ext

def MyfileDecrypt(cText,iv,key,ext):
	filename = "c:\\Reports\\ToEncrypt\\decryptedFiletxt1" + ext

	messageBytes = MyDecrypt(cText, iv,key)
	message = b64decode(messageBytes)

	fileDec = open(filename,"wb")
	fileDec.write(message)
	fileDec.close()

	return str(path.realpath(filename))

def jasonFile(cText,iv,key,ext):
	fileName = 'C:\\Reports\\ToEncrypt\\encryption.txt'
	#if cText is None and iv is None and key is None and ext is None:
	data = {}
	data[fileName] = []
	
	data[fileName].append({
		'Cipher text ': b64encode(cText).decode("utf-8"),
		'iv' :b64encode(iv).decode("utf-8"),
		'Key' : b64encode(key).decode("utf-8"),
		'Extension' : ext})

	with open(fileName, 'w') as outfile:
		json.dump(data, outfile)

def jasonFileHMAC(cText,iv,tag, ENCkey,HMACkey,ext):
	fileName = 'C:\\Reports\\ToEncrypt\\encryptionMAC.txt'
	#if cText is None and iv is None and key is None and ext is None:
	data = {}
	data[fileName] = []
	
	data[fileName].append({
		'Cipher text ': b64encode(cText).decode("utf-8"),
		'iv' :b64encode(iv).decode("utf-8"),
		'ENCkey' : b64encode(ENCkey).decode("utf-8"),
		'HMACkey' : b64encode(HMACkey).decode("utf-8"),
		'Extension' : ext})

	with open(fileName, 'w') as outfile:
		json.dump(data, outfile)



def main():
#Testing :
	
	cText,iv,tag, ENCkey,HMACkey,ext = MyfileEncryptMAC("C:\\Reports\\ToEncrypt\\encrypt031719.jpg")
	filePath = MyfileDecrypt(cText,iv,ENCkey,ext)
	jasonFileHMAC(cText,iv,tag, ENCkey,HMACkey,ext)
	print(filePath)

	#NO-HMAC encryption
	#cText,iv,key,ext = MyfileEncrypt("C:\\Reports\\ToEncrypt\\bar98.jpg")
	#filePath = MyfileDecrypt(cText,iv,key,ext)
	#jasonFile(cText,iv,key,ext)
	#print(filePath)

if __name__ == "__main__":
  main()

