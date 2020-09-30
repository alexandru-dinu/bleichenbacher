# Bleichenbacher's PKCS 1.5 Padding Oracle Attack

An implementation of Daniel Bleichenbacher’s Adaptive Chosen Ciphertext Attack on RSA PKCS #1 v1.5 [1].

The attack is particularly interesting due to its real life implications: PKCS #1 was widely deployed, e.g. in HTTPS – SSL/TLS). It exploits an implementation flaw present in numerous servers: reporting whether the encoding of the received message is PKCS1-conforming. This allows one to use the server as an oracle, and based on the reply, one can gain information about the complete decryption of the intercepted ciphertext (hence the *adaptive chosen ciphertext* part).

[1] [Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1](http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf)
