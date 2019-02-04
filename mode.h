#ifndef MODE_H
#define MODE_H


void CtrInc(unsigned char *ctr);

/* Implement the following API.
 * You can add your own functions, but don't modify below this line.
 */

/*implement CTR encryption mode with aes128.
The parameters are: 
 c = ciphertext
 m = plaintext
 l = plaintext length in bytes
 ctr = initial counter
 k = key
 */
void CTRaes128e(unsigned char *c,unsigned char *m,unsigned long l, unsigned char *ctr, const unsigned char *k);



/*implement the OFB encryption mode with aes128.
The parameters are: 
 c = ciphertext
 m = plaintext
 l = plaintext length in bytes
 iv = initial value
 k = key
 */

void OFBaes128e(unsigned char *c,unsigned char *m,unsigned long l, unsigned char *iv, const unsigned char *k);


#endif			/* MODE_H */
