#ifndef AES128E_H
#define AES128E_H
/* Implement the following API.
 * You can add your own functions, but don't modify below this line.
 */

/*
 * Transformation in the Cipher and Inverse Cipher in which a Round Key
 * is added to the State using an XOR operation. The length of a Round Key
 * equals the size of the State (i.e., for Nb = 4, the Round
 * Key length equals 128 bits/16 bytes).
*/

/* Under the 16-byte key at k, encrypt the 16-byte plaintext at p and store it at c. */
void aes128e(unsigned char *c, const unsigned char *p, const unsigned char *k);

#endif			/* AES128E_H */
