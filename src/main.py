from rsa import RSA_OAEP
from rsaKeyGenerator import RSAKeyGenerator
from aes import AES
import json


def testAESEncryptionCTR():
    aes = AES()
    key = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0xf2, 0xfa, 0xc5, 0xe6, 0x7c, 0x82])
    
    iv = [0xc4, 0xd9, 0xb8, 0xab, 0xf2, 0x9f, 0xa3, 0xfc, 0x77, 0x9b, 0x2a, 0xb4, 0xa3, 0x2c, 0x5f, 0xfa]
    # aes.encryptECBMode("src/files/test2.txt", key)
    # aes.decryptECBMode("src/files/test2-AESencrypted.txt", key)
    aes.encryptCTRMode("src/files/test2.txt", key, iv)
    aes.decryptCTRMode("src/files/test2-AES_CTR_encrypted.txt", key, iv)

def testAESDecryptionCTR():
    pass

def testRSAKeyGenerator():
    keyGenerator = RSAKeyGenerator()
    keyGenerator.genKeys()


def testRSAEncryption():
    with open("src/files/keys.json", "r", encoding="utf8") as file:
        keys = json.load(file)
    
    publicKey = keys.get("publicKey")
    publicKey = (publicKey['n'], publicKey['e'])
    
    rsa = RSA_OAEP()
    rsa.encrypt("src/files/test2.txt", publicKey)
    

def testRSADecryption():
    with open("src/files/keys.json", "r", encoding="utf8") as file:
        keys = json.load(file)
    
    privateKey = keys.get("privateKey")
    privateKey = (privateKey['n'], privateKey['d'])
    rsa = RSA_OAEP()
    rsa.decrypt("src/files/test2-RSAencrypted.txt", privateKey)

def testRSA():
    keyGenerator = RSAKeyGenerator()
    rsa = RSA_OAEP()
    aes = AES()
    keyGenerator.genKeys()
    
    with open("src/files/keys.json", "r", encoding="utf8") as file:
        keys = json.load(file)
    

    publicKey = keys.get("publicKey")
    publicKey = (publicKey['n'], publicKey['e'])
    privateKey = keys.get("privateKey")
    privateKey = (privateKey['n'], privateKey['d'])
    signature = rsa.genSignature("src/files/test2.txt", privateKey)
    print("Signature = ", signature)
    rsa.signTextDocument("src/files/test2.txt", signature)
    rsa.verifySignature("src/files/test2-signed.txt", publicKey)
    # rsa.encryptTextFile("src/files/test2.txt", publicKey)
    # rsa.decryptTextFile("src/files/test2-RSAencrypted.txt", privateKey)


def main():
    keyGenerator = RSAKeyGenerator()
    aes = AES()
    rsa = RSA_OAEP()
    
    filename = "src/files/test.txt"
    encryptedAES_CTR_filename = "src/files/test-AES_CTR_encrypted.txt"
    encryptedAES_ECB_filename = "src/files/test-AES_ECB_encrypted.txt"
    signedFilename = "src/files/test-AES_CTR_encrypted-singned.txt"
    
    # aesKey = bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0xf2, 0xfa, 0xc5, 0xe6, 0x7c, 0x82])
    # aesIV = [0xc4, 0xd9, 0xb8, 0xab, 0xf2, 0x9f, 0xa3, 0xfc, 0x77, 0x9b, 0x2a, 0xb4, 0xa3, 0x2c, 0x5f, 0xfa]
    
    # aes.encryptECBMode(filename, aesKey)
    # aes.decryptECBMode(encryptedAES_ECB_filename, aesKey)
    
    # aes.encryptCTRMode(filename, aesKey, aesIV)
    # aes.decryptCTRMode(encryptedAES_CTR_filename, aesKey, aesIV)
    keyGenerator.genKeys()
    with open("src/files/keys.json", "r", encoding="utf8") as file:
        keys = json.load(file)
    
    
    publicKey = keys.get("publicKey")
    publicKey = (publicKey['n'], publicKey['e'])
    privateKey = keys.get("privateKey")
    privateKey = (privateKey['n'], privateKey['d'])
    
    signature = rsa.genSignature("src/files/test.txt", privateKey)
    
    rsa.signTextDocument(filename, signature)
    
    
    
if __name__ == "__main__":
    main()