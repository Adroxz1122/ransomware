# ransomware

A basic ransomware made using C (this is the 1st version, so it only encrypts 1 file at a time, and has been tested on text files only. Will update and add more features to it later).

Used Windows CNG instead of external libraries to improve stealthiness.

Key and IV are stored in the .rsrc section of the PE file to make reverse engineering difficult (the variant uploaded here has the key and IV in the main() for safety concerns).

Outputs the encrypted file with the .ardx extension.

you can change the key and IV files to whatever you like but KEEP THE SIZE SAME.
