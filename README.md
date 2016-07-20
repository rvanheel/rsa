# rsa
RSA Asymmetric Encryption

Here is an example of RSA Asymmetric Encryption:

In this example we use Alice and Bob.

Alice wants to send a message to Bob.

1) She encrypts the message with the public key from Bob.
2) Alice signs the message with her private key.
3) Alice sends the encrypted message and the signature to Bob.

Bob receives the encypted message and signature from Alice.

1) Bob decrypts the message using his private key.
2) Bob verifies the signature with the public key from Alice.



/* TO GENERATE THE KEYS USING OPENSSL : /*
	
	***** BOBS KEYS
	openssl genrsa -out bob.privatekey.pem 2048
	openssl rsa -in bob.privatekey.pem -pubout -out bob.publickey.pem
	
	***** ALICE KEYS
	openssl genrsa -out alice.privatekey.pem 2048
	openssl rsa -in alice.privatekey.pem -pubout -out alice.publickey.pem


