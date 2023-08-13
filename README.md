# Crypto
using openssl BIGNUMBER</br>
### XEuclid
Extended Euclid Algorithm</br>
### ExpMod
Modular Exponential (Fast Exponential)</br>
### RSA
RSA with fixed prim p, q</br>

## Compile Option
```
CC = gcc
CFLAGS = -I../include/crypto
LDFLAGS = -L.. -lcrypto

$(TARGET): $(SRC)
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)
```


