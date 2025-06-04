# ransomware

A basic ransomware made using C

Used Windows CNG instead of external libraries to improve stealthiness.

Key and IV are stored in the .rsrc section of the PE file to make reverse engineering difficult (the variant uploaded here has the key and IV in the main() for safety concerns).

Outputs the encrypted file with the .ardx extension.
