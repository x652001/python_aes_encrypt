import base64
from Crypto.Cipher import AES
from Crypto.Util.py3compat import bchr, bord

'''
採用AES對稱加密演算法
'''
# str不是16的倍數那就補足為16的倍數
def add_to_16(s):
  s = str.encode(s)
  k = 16
  pad_size = k - len(s) % k
  s += pad_size * bchr(pad_size)
  #print(s)
  return s


# 加密方法
def encrypt_oracle(message,key_pri):
    '''
    加密函式，傳入明文 & 祕鑰，返回密文；
    :param message: 明文
    :param key_pri: 祕鑰
    :return:encrypted  密文
    '''
    # 初始化加密器
    aes = AES.new(add_to_16(key_pri), AES.MODE_ECB)
    # 將明文轉為 bytes
    #message_bytes = message.encode('utf-8')
    # 長度調整
    message_16 = add_to_16(message)
    #先進行aes加密
    encrypt_aes = aes.encrypt(message_16)
    #用base64轉成字串形式
    encrypt_aes_64 = base64.b64encode(encrypt_aes)
    return encrypt_aes_64


# 解密方法
def decrypt_oralce(message,key_pri):
    '''
    解密函式，傳入密文 & 祕鑰，返回明文；
    :param message: 密文
    :param key_pri: 祕鑰
    :return: encrypted 明文
    '''
    # 初始化加密器

    aes = AES.new(add_to_16(key_pri), AES.MODE_ECB)
    #優先逆向解密base64成bytes
    message_de64 = base64.b64decode(message)
    # 解密 aes
    message_de64_deaes = aes.decrypt(message_de64)
    message_de64_deaes_de = message_de64_deaes.decode('utf-8')
    return message_de64_deaes_de


message = '!QAZxsw2'     # 待加密內容
key_pri = 'helloworld!'                              # 密碼

content_en = encrypt_oracle(message,key_pri)    # 加密
print('加密後，密文為：',content_en)            

content = decrypt_oralce(content_en,key_pri)    # 解密
print('解密後，明文為：',content)               
