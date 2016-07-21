# RSA Asymmetric Encryption

Requirements
------------

- OpenSSL 
```sh
sudo apt-get install libssl-dev
```

Usage
-----
### int decrypt_message(RSA * rsa, char * msg, int padding, unsigned char ** encoded_message)

decrypts a message with a PRIVATE key and the provided padding, and stores the decrypted message in encoded_message
Returns 1 on success.

### int encrypt_message(RSA * rsa, char * msg, int padding, char ** encoded_message)

encrypts a message with a PUBLIC key and the provided padding, and stores the result in encoded_message
Returns 1 on success.

### int randomize()

generate a random buffer from RAND_bytes().
Returns 1 on success.

### RSA * read_privatekeyfile(char * filename)

reads a PRIVATE keyfile. This implementation is for keyfiles without password.

### RSA * read_publickeyfile (char * filename)

reads a PUBLIC keyfile. This implementation is for keyfiles without password.

### int sign(RSA * rsa, char * msg, char * algorithm, char ** encoded_message)

signs a message with a PRIVATE KEY and algorithm, and stores the result in encoded_message
Returns 1 on success.

### int simpleSHA256(void* input, unsigned long length, unsigned char* md)

compute a hash for the SHA256 algorithm.
Returns 1 on success.

### int verify(RSA * rsa, char * msg, char * signature, char * algorithm)
verifies a message with a PUBLIC key. 
Returns 1 on successful verification.  



Example
-------

In this example we use Alice and Bob.

Alice wants to send a message to Bob, `"IT'S A SECRET TO EVERYBODY."`.

1) She encrypts the message with the public key from Bob.
```c_cpp
char * encrypted_message;
char msg [] = "IT\'S A SECRET TO EVERYBODY.";
RSA * bob_public_key = read_publickeyfile("bob.publickey.pub");
encrypt_message(bob_public_key, msg, RSA_PKCS1_OAEP_PADDING, &encrypted_message);
```
2) Alice signs the message with her private key.
```c_cpp
char * encrypted_signature;
RSA * alice_private_key = read_privatekeyfile("alice.privatekey.pem");
sign(alice_private_key, msg, "SHA256", &encrypted_signature);
```

Bob receives the encrypted message and signature from Alice.

1) Bob decrypts the message using his private key.
```c_cpp
unsigned char * decrypted_message;
RSA * bob_private_key = read_privatekeyfile("bob.privatekey.pem");
decrypt_message(bob_private_key, encrypted_message, RSA_PKCS1_OAEP_PADDING, &decrypted_message);
```
2) Bob verifies the signature with the public key from Alice.
```c_cpp
RSA * alice_public_key = read_publickeyfile("alice.publickey.pub");
verify(alice_public_key, (char *)decrypted_message, encrypted_signature, "SHA256")
```

Key generation using OpenSSL
----------------------------
```sh
# ***** BOBS KEYS
openssl genrsa -out bob.privatekey.pem 2048
openssl rsa -in bob.privatekey.pem -pubout -out bob.publickey.pem

# ***** ALICE KEYS
openssl genrsa -out alice.privatekey.pem 2048
openssl rsa -in alice.privatekey.pem -pubout -out alice.publickey.pem
```

