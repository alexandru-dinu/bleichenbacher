# Bleichenbacher's PKCS 1.5 Padding Oracle Attack

Daniel Bleichenbacher’s Adaptive Chosen Ciphertext Attack on RSA PKCS #1 v1.5 [1] implementation for the Introduction to Cryptology class

It is a particularly interesting attack due to real life implications (PKCS #1 was widely deployed, for example, in HTTPS – SSL/TLS) and due to the mathematics behind it.

This specific attack exploits the implementation flaws found in numerous servers, that is, they report whether the encoding of the message they have received is PKCS1-conforming. This allows the attacker to use the server as an oracle to which he sends several queries. Based upon the server’s reply, the attacker can gain information about the complete decryption of an intercepted ciphertext (hence the *adaptive chosen ciphertext* bit).

[1] [Chosen Ciphertext Attacks Against Protocols Based on the RSA Encryption Standard PKCS #1](http://archiv.infsec.ethz.ch/education/fs08/secsem/bleichenbacher98.pdf)
