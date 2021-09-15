# -*- coding: utf-8 -*-
"""
Created on Thu Aug  5 16:52:30 2021

@author: lazar
"""
from random import randint

class ElementKP:
    
    def __init__(self,element,red):
        if element>=red or element<0:
            raise ValueError("Broj ne moze biti element ovog polja polja.")
        self.element=element
        self.red=red
        
        
    def __repr__(self):
        return 'Element {} konačnog polja reda veličine {}'.format(self.element,self.red)
    
    def __eq__(self,other):
        if other is None:
            return False
        return self.element==other.element and self.red==other.red
    
    def __ne__(self, other):
        return  not (self == other)
    
    #definisanje operacija tako da one budu zatvorene koriscenjem moduo operacije
    
    def __add__(self, other):
        if self.red != other.red:  
            raise TypeError('Elementi pripadaju poljima različitog reda.')
        element = (self.element + other.element) % self.red  
        return self.__class__(element, self.red)  
    
    def __sub__(self, other):
        if self.red != other.red:
            raise TypeError('Elementi pripadaju poljima različitog reda.')
        element = (self.element - other.element) % self.red
        return self.__class__(element, self.red)
    
    def __mul__(self, other):
        if self.red != other.red:
            raise TypeError('Elementi pripadaju poljima različitog reda.')
        element = (self.element * other.element) % self.red
        return self.__class__(element, self.red)
    
    def __pow__(self, eksp):
        n = eksp % (self.red - 1)  
        element = pow(self.element, n, self.red)
        return self.__class__(element, self.red)
    
    def __truediv__(self, other):
        if self.red != other.red:
            raise TypeError('Elementi pripadaju poljima različitog reda.')
        # Fermaova mala teorema
        # self.element**(p-1) % p == 1
        element = (self.element * pow(other.element, self.red - 2, self.red)) % self.red
        return self.__class__(element, self.red)

    def __rmul__(self, koeficijent):
        element = (self.element * koeficijent) % self.red
        return self.__class__(element, self.red)
    



        

class Tacka:
    
    def __init__(self,x,y,a,b):
        self.a=a
        self.b=b
        self.x=x
        self.y=y
        #uslov za tacku u beskonacnosti
        if self.x is None and self.y is None:  
            return
        if self.y**2 != self.x**3 + a*x+b:
            raise ValueError("Data tačka se ne nalazi na krivoj.")
            
    def __eq__(self,other):
        return self.x==other.x and self.y==other.y and self.a==other.a and self.b==other.b
    
    def __ne__(self,other):
        return not(self==other)
    
    def __repr__(self):
        if self.x is None:
            return 'Tacka(beskonacnost)'
        elif isinstance(self.x, ElementKP):
            return 'Tacka({},{})_{}_{} Red konačnog polja({})'.format(
                self.x.element, self.y.element, self.a.element, self.b.element, self.x.red)
        else:
            return 'Tacka({},{})_{}_{}'.format(self.x, self.y, self.a, self.b)
       

    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError('Date tačke se ne nalaze na istoj krivoj.')
       #slucaj sabiranja kada je jedna tacka tacka u beskonacnosti
        if self.x is None:
            return other
        if other.x is None:
            return self
        
        #dve tacke kroz koje prolazi vertikala kreiraju tacku u beskonacnosti
        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a, self.b)
       
        #racunanje koordinata x i y koriscenjem nagiba
        if self.x != other.x:
            s = (other.y - self.y) / (other.x - self.x)
            x = s**2 - self.x - other.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)
       
        #slucaj kada je tangenta vertikalna
        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.b)
        
        #sabiranje tacke same sa sobom, linija koja prolazi kroz tacku
        #predstavlja tangentu, veoma bitno za kriptografiju
        if self == other:
            s = (3 * self.x**2 + self.a) / (2 * self.y)
            x = s**2 - 2 * self.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)
        
    
    def __rmul__(self, coefficient):
        coef = coefficient
        current = self  
        result = self.__class__(None, None, self.a, self.b)  
        while coef:
            if coef & 1:  
                result += current
            current += current  
            coef >>= 1  
        return result
    
#parametri u secp256k1 kriptografiji
A = 0
B = 7
P = 2**256 - 2**32 - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

class S256Polje(ElementKP):

    def __init__(self, element, red=None):
        super().__init__(element, P)
    
    #da bi adresa uvek bila 256 bita popunjavano ispis nulama
    def __repr__(self):
        return '{:x}'.format(self.element).zfill(64)

class S256Tacka(Tacka):

    def __init__(self, x, y, a=None, b=None):
        a, b = S256Polje(A), S256Polje(B)
        if type(x) == int:
            super().__init__(x=S256Polje(x), y=S256Polje(y), a=a, b=b)
        else:
            #za slucaj tacke u beskonacnosti
            super().__init__(x=x, y=y, a=a, b=b)  
    

    def __repr__(self):
        if self.x is None:
            return 'S256Tacka(beskonactost)'
        else:
            return 'S256Tacka({}, {})'.format(self.x, self.y)


    def verify(self, h, sig):
        c = pow(sig.s, -1, N)  
        u1 = h * c % N  
        u2 = sig.r * c % N  
        total = u1 * G + u2 * self  
        return total.x.element == sig.r  
    

#generator
G = S256Tacka(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)

class Potpis:

    def __init__(self, r, s):
        self.r = r
        self.s = s

    def __repr__(self):
        return 'Potpis({:x},{:x})'.format(self.r, self.s)


class PrivatniKljuc:

    def __init__(self, secret):
        #secret je privatni kljuc, a point je javni kljuc
        self.secret = secret
        self.point = secret * G  

    def hex(self):
        return '{:x}'.format(self.secret).zfill(64)
   

    
    def sign(self, h):
        k = randint(0,N)  
        r = (k * G).x.element
        k_inv = pow(k, -1, N)
        s = (h + r * self.secret) * k_inv % N
        return Potpis(r, s)




red = 223
a = ElementKP(0, red)
b = ElementKP(7, red)
x = ElementKP(47, red)
y = ElementKP(71, red)
p = Tacka(x, y, a, b)
for s in range(1,21):
    rezultat = s*p
    print('{}*(47,71)=({},{})'.format(s,rezultat.x.element,rezultat.y.element))


pk = PrivatniKljuc(randint(0, N))
z = randint(0, 2**256)
sig = pk.sign(z)

print("Privatni kljuc:")
print(pk.secret)
print("Javni kljuc")
print(pk.point)
print("Potpis:")
print(sig)
print("Da li poruka odgovara posiljaocu:")
print(pk.point.verify(z, sig))


import hashlib

privKljuc=PrivatniKljuc(randint(0,N))
poruka=int.from_bytes(hashlib.sha256(hashlib.sha256(b'Poruka koju zelim da potpisem').digest()).digest(),'big')
potpis=privKljuc.sign(poruka)

print("HASH256 poruke:")
print(poruka)
print("Privatni kljuc:")
print(privKljuc.secret)
print("Javni kljuc")
print(privKljuc.point)
print("Potpis:")
print(potpis)
print("Da li poruka odgovara posiljaocu:")
print(privKljuc.point.verify(poruka,potpis))
