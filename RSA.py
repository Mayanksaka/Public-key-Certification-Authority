"""
Following file is a very basic implementation of RSA encryption on string of 
characters. Since size of string can vary, we will encrypt each charater using 
RSA.  This implementation is not safe cryptographically. For instance, one can 
use frequency analysis on this.

Ideally, RSA is not used to encrypt large texts. Ususally its some symmetric key
algorithm like AES which encrypts large data and RSA is used on the AES key. 
But requirements for the assignment was RSA.
"""
from math import sqrt,ceil;
from sys import getdefaultencoding;
import time
def euclidean_gcd(a:int, b:int)->tuple:
    """
    Returns tuple (gcd(a,b),x,y) where x and y are solutions to the diophantine 
    equation ax + by = gcd(a,b).
    """
    if a == 0:
        return b,0,1;
    g,y,x = euclidean_gcd(b%a,a);
    return(g,x-(b//a)*y,y);

def mod_inverse(a:int, m:int)->int:
    """ Finds b such that a*b = 1 (mod m)."""   
    g,x,y = euclidean_gcd(a,m);
    if g != 1:
        raise Exception("Modular inverse does not exist.");
    # Idea is that ax + my = 1
    # ax(mod m) + my(mod m) = 1 (mod m)
    # a*(x mod m) = 1(mod m)
    return x%m;

def generate_keys_RSA(p:int, q:int)->dict:
    """
    Generates the public and private keys given two prime numbers. 
    """
    n = p*q;
    phi_n = (p-1)*(q-1);
    e = 257;
    if e > phi_n:
        raise Exception("Get bigger primes");
    d = mod_inverse(e,phi_n);
    return {'Public':(e,n) , 'Private':(d,n)};

def encrypt(plainText:str, e:int, n:int)->str:
    """ Encrypts each character of plain text using RSA."""
    l = [chr(pow(ord(M),e,n)) for M in plainText];
    return ''.join(l);

def decrypt(cypherText:str, d:int, n:int)->str:
    """Decrypts each character of cypher text which was encrypted using 
    encrypt(...)."""
    l = [chr(pow(ord(C),d,n)) for C in cypherText];
    return ''.join(l);

def is_prime(p:int)->bool:
    if p%2 == 0:
        return False;
    for i in range(3,ceil(sqrt(p)),2):
        if p%i == 0:
            return False;
    return True;

if __name__ == "__main__":
    # Test on 229, 233, 239, 241, 251, 223
    key1 = generate_keys_RSA(229,233); #A
    key2 = generate_keys_RSA(239,241); #B
    key3 = generate_keys_RSA(251,223); #Certification authority

    e1 = key1['Public'][0];
    e2 = key2['Public'][0];
    e3 = key3['Public'][0];

    n1 = key1['Public'][1];
    n2 = key2['Public'][1];
    n3 = key3['Public'][1];

    d1 = key1['Private'][0];
    d2 = key2['Private'][0];
    d3 = key3['Private'][0];

    assert(n1 == key1['Private'][1]);
    assert(n2 == key2['Private'][1]);
    assert(n3 == key3['Private'][1]);

    # Test for simple text message
    test_a = "getCertificate"
    
    # Test for a dictionary in certificate format. 
    # CERT A = ENC PR‐CA (ID A , PU A , T A , DUR A , ID CA )
    d = {'ID':123 , 'PU_A':(65537,5361861) , 'T_A':'321:321:3214:12313' ,
         'DUR':'31231231' , 'CA':31213};

    test_b = str(d);

    plainText = test_a;
    c1 = encrypt(plainText,e1,n1);
    c2 = encrypt(plainText,e2,n2);
    c3 = encrypt(plainText,e3,n3);

    p1 = decrypt(c1,d1,n1);
    p2 = decrypt(c2,d2,n2);
    p3 = decrypt(c3,d3,n3);
    data = bytes(c3.encode('utf-16','surrogatepass'));
    data_o = data.decode('utf-16','surrogatepass');
    assert(p1 == plainText);
    assert(p2 == plainText);
    assert(p3 == plainText);
    print(repr(data_o == c3))
    print("Works :)");
