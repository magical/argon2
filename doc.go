/*

Package argon implements the Argon2 password hashing function as specified
in the document 

	https://password-hashing.net/submissions/specs/Argon-v3.pdf

Argon2 comes in two flavors:

Argon2i, which uses data-independant memory access, making it suitable for hashing secret information such as passwords.

Argon2d, which uses data-dependant memory access, making it slower than Argon2i (a desirable property), but not suitable for hashing secret information due to potential side-channel attacks.

*/
package argon
