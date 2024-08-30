import random
import math
import sympy
import json

class RSAKeyGenerator:    
    def getRandomNumber512Bits(self):
        return random.getrandbits(512)        
    
    
    def millerRabin(self, num, k):
        # verificar se num = 2 ou num = 3
        if num in [2, 3]:
            return True
        
        # verificar se num % 2 == 0 ou num < 2
        if num % 2 == 0 or num < 2:
            return False
        
        # escrever n-1 no formato 2^r * d
        r = 0
        d = num-1
        while d % 2 == 0:
            r += 1
            d //= 2
            
        for _ in range(k):
            # a = numero aletatorio entre 2 e num-2 
            a = random.randint(2, num-2)
            
            # x = a^d (mod n)
            x = pow(a, d, num)
            
            # se  x ≡ 1 (mod n) ou x ≡ n−1 (mod n), continua
            if x in [1, num-1]:
                continue
            
            # verificar se x^2 (mod n) = n-1
            flag = False
            for _ in range(r-1):
                x = pow(x, 2, num)
                if x == num-1:
                    flag = True
                    break
            # se sim, continua
            if flag:
                continue
            # se nao, num = compostp
            else:
                return False
            
        return True
    

    def genStrongPrimeNumber(self):
        while True:
            rand_num = self.getRandomNumber512Bits()
            if rand_num % 2 == 0:
                continue
            if self.millerRabin(rand_num, 50):
                return rand_num
            
            
    def inverse(self, a, b):
        def extended_gcd(a, b):
          if b == 0:
            return a, 1, 0
          gcd, x1, y1 = extended_gcd(b, a % b)
          x = y1
          y = x1 - (a // b) * y1
          return gcd, x, y

        return extended_gcd(a, b)

    
    def genKeys(self):
        # numeros primos de 512 bits
        p = self.genStrongPrimeNumber()
        q = self.genStrongPrimeNumber()
        # n = pq
        n = p*q
        # funcao totiente de euler em n:  ϕ ( n ) = ( p − 1 ) ( q − 1 )  
        phi_n = (p-1)*(q-1)
        # calcular um numero relativamente primo a ϕ ( n ) tal que 1 < e < ϕ ( n )
        e = 65537
        
        gcd, d, _ = self.inverse(e, phi_n)
        
        data = {
            "publicKey": {
                "n": n,
                "e": e
            },
            "privateKey": {
                "n": n,
                "d": d
            }
        }
        
        with open("src/files/keys.json", 'w', encoding='utf-8') as file:
            json.dump(data, file)