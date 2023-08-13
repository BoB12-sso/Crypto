# Crypto
using openssl BIGNUMBER
### XEuclid
Extended Euclid Algorithm
### ExpMod
Modular Exponential (Fast Exponential)
</br>

## Compile Option
```
CC = gcc
CFLAGS = -I../include/crypto
LDFLAGS = -L.. -lcrypto

$(TARGET): $(SRC)
	$(CC) -o $@ $< $(CFLAGS) $(LDFLAGS)
```


