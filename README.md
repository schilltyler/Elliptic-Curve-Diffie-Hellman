# Elliptic Curve Diffie Hellman
## Tyler Schill and Megan Judd
### Spring 2026

#### ecdh
Compile by running ```make ecdh``` or make all. ```ecdh``` produces a ```key.txt``` file. This file must exist before running ```test_key.```
ecdh uses the P-256 elliptic curve group parameters for ephemeral DHKE. It uses ```hkdf``` (hash key derivation function), to use the shared secret to derive a key.

#### test key
Compile by running ```make test_key``` or make all. Using the result from running ```ecdh```, pass in ```key.txt``` to ```test_key.``` This uses the ```openssl``` AES-256 framework to test if the derived key can properly be used for symmetric encryption. Users will be expected to input plaintext to observe encryption and decryption. 
