import hashlib
import os

class RSA_OAEP:
    def __init__(self) -> None:
        # modulo do RSA em bytes
        self.k = 128
        # tamanho do output gerado pela funcao de hash em bytes
        self.hLen = 32
        # Label L
        self.L = b""
        # hash de L
        self.lHash = hashlib.sha3_256(self.L).digest()
        # tamanho padrao da mensagem
        self.mLenDefault = self.k - 2*self.hLen - 2
    
    def readTextFile(self, filename):
        with open(filename, 'rb') as file:
            bytes = file.read()
        
        return bytes
    
    
    def mgf1(self, seed, length, hash_func=hashlib.sha3_256) -> bytes:
        hLen = hash_func().digest_size
        if length > (hLen << 32):
            raise ValueError("mask too long")
        
        T = b''
        counter = 0
        while len(T) < length:
            C = int.to_bytes(counter, 4, "big")
            T += hash_func(seed + C).digest()
            counter += 1
        
        return T[:length]
        
    
    def OAEPEncode(self, data):
        PS = b"\x00" * (self.mLenDefault-len(data))
            
        DB = self.lHash + PS + b"\x01" + data
        seed = os.urandom(self.hLen)
        
        dbMask = self.mgf1(seed, self.k - self.hLen - 1)
        maskedDB = bytes([DB[i] ^ dbMask[i] for i in range(len(DB))])
        
        
        seedMask = self.mgf1(maskedDB, self.hLen)
        
        maskedSeed = bytes([seed[i] ^ seedMask[i] for i in range(len(seed))])
        
        EM = b"\x00" + maskedSeed + maskedDB
        
        return EM

    
    def OAEPDecode(self, EM):            
        maskedSeed = EM[:self.hLen]
        maskedDB = EM[self.hLen:]
        
        seedMask = self.mgf1(maskedDB, self.hLen)
        seed = bytes([maskedSeed[i] ^ seedMask[i] for i in range(len(maskedSeed))])
        
        dbMask = self.mgf1(seed, self.k - self.hLen - 1)
        # print(len(maskedDB), len(dbMask))
        DB = bytes([maskedDB[i] ^ dbMask[i] for i in range(len(maskedDB))])
        
        lHash2 = DB[:32]
        if self.lHash != lHash2:
            raise ValueError(f"O lHash' é diferente do lHash.")
        
        index01 = DB[32:].index(b"\x01")
        message = DB[index01+33:]
        
        return message
    
    
    def encrypt(self, data, key):
        encrypted = pow(int.from_bytes(data), key[1], key[0])
        return encrypted.to_bytes((encrypted.bit_length()+ 7) // 8)


    def decrypt(self, data, key):
        decrypted = pow(int.from_bytes(data), key[1], key[0])
        return decrypted.to_bytes((decrypted.bit_length()+ 7) // 8)

    
    def genEncryptedFile(self, filename, data):
        with open(filename, 'wb') as file:
            file.write(data)
    
    
    def genDecryptedFile(self, filename, data):
        with open(filename, 'w', encoding='latin-1', newline="\n") as file:
            file.write(data.decode('latin-1'))
    
    
    def encryptTextFile(self, filename, publicKey):
        encryptedData = b""
        
        # Extrair bytes do arquivo
        data = self.readTextFile(filename)
        newFilename = filename[:filename.index('.')] + '-RSAencrypted.txt'
        
        for i in range(0, len(data), self.mLenDefault):
            # mensagem
            message = data[i:i+self.mLenDefault]
            
            # mensagem codificada com OAEP
            EM = self.OAEPEncode(message)
            
            # mensagem cifrada
            encryptedMessage = self.encrypt(EM, publicKey)
            encryptedData += encryptedMessage
            
        self.genEncryptedFile(newFilename, encryptedData)
        
    
    def decryptTextFile(self, filename, privateKey):
        decryptedData = b""
    
        # Extrair bytes do arquivo
        data = self.readTextFile(filename)
        newFilename = filename[:filename.index('.')] + '-RSAdecrypted.txt'
        
        for i in range(0, len(data), self.k):
            # mensagem cifrada
            encryptedMessage = data[i:i+self.k]
            # mensagem decifrada
            decryptedMessage = self.decrypt(encryptedMessage, privateKey)
            # mensagem decodificada OAEP
            message = self.OAEPDecode(decryptedMessage)
            # print(message1 == message2)
            decryptedData += message
            
        self.genDecryptedFile(newFilename, decryptedData)
    
    
    def genSignature(self, filename, privateKey):
        data = self.readTextFile(filename)
        # print("file = ", data)
        hashed_data = hashlib.sha3_256(data).digest()
        # print("Hashed File = ", hashed_data)
        signature = self.encrypt(data=self.OAEPEncode(hashed_data), key=privateKey)
        
        return signature
    
    
    def signTextDocument(self, filename, signature):
        data = self.readTextFile(filename)
        
        newFilename = filename[:filename.index('.')] + '-signed.txt'
        with open(newFilename, 'w', encoding='latin-1', newline="\n") as file:
            file.write(f'{data.decode("latin-1")}\n\n\n{"#"*20}\n{signature.decode('latin-1')}')
            
            
    def extractSignatureFromTextFile(self, filename):
        data = self.readTextFile(filename)
        data = data.decode("latin-1")
        i = data.index("#"*20)
        
        return data[i+21:].encode("latin-1")
            

    def checkSignature(self, filename, publicKey):
        data = self.readTextFile(filename).decode("latin-1")
        signature = self.extractSignatureFromTextFile(filename)
        i = data.index("\n\n\n"+"#"*20)
        
        data = data[:i].encode("latin-1")
        signature = self.OAEPDecode(self.decrypt(signature, publicKey))
        hashed_data = hashlib.sha3_256(data).digest()
        return signature == hashed_data
        
        