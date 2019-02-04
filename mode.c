#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "aes128e.h"
#include "mode.h"

/*function CtrInc that receives the current counter and updates the counter
*/

void CtrInc(unsigned char *ctr)
{	
	unsigned int i=15;
	while((i>7) && (ctr[i]==0xff)){
		ctr[i]=0;
		i--;
	}
	if(i!=7){
		ctr[i]++;
	}
}

/*implement CTR encryption mode with aes128.
The parameters are: 
 c = ciphertext
 m = plaintext
 l = plaintext length in bytes
 ctr = initial counter
 k = key
Description of the CTR mode is given in the specification document: http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
Do not modify this header
 */

void CTRaes128e(unsigned char *c, unsigned char *m, unsigned long l, unsigned char *ctr, const unsigned char *k)
{
	//array z2 will be written with the current output of aes128 encryption (needed to XOR with the block cipher)
	unsigned char z2[16]={0};
	//variable b2 is: 0 if l is multiple of 16 (l(mod16)=0) or 1 otherwise (l(mod16)!=0)
	unsigned int b2=0;
	//variable r2 represents l(mod 16)
	unsigned int r2=l%16;
	if(r2==0){
		b2=0; //last block message is complete
	}
	else {
		b2=1; //last block message is partial
	}
	//n2 is the counter for the 4byte block cipher (starts in the one at position 1 and goes until the last one that is complete (n=(l-r2)/16-1))
	for(unsigned int n2=0; n2<((l-r2)/16); n2++){
		aes128e(z2,ctr,k);
		CtrInc(ctr);
		for(unsigned int j2=0; j2<16; j2++){
			c[n2*16+j2]=z2[j2]^m[n2*16+j2];
		}
	}
	//in case the last bock message is partial here is calculated the last cipher block 
	if(b2==1){
		aes128e(z2,ctr,k);
		for(unsigned int j2=0; j2<r2; j2++){
			c[(l-r2)+j2]=z2[j2]^m[(l-r2)+j2];
		}
	}
}

/*implement the OFB encryption mode with aes128.
The parameters are: 
 c = ciphertext
 m = plaintext
 l = plaintext length in bytes
 iv = initial value
 k = key
Description of the OFB mode is given in the specification document: http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
Do not modify this header
 */
void OFBaes128e(unsigned char *c, unsigned char *m, unsigned long l, unsigned char *iv, const unsigned char *k)
{	
	//array z1 will be written with the current output of aes128 encryption (needed to XOR with the block cipher)
	unsigned char z1[16]={0};
	//array d will keep the value of the previous z1 (last output of aes128 encryption that is needed as input for current block encryption)
	unsigned char d[16]={0};
	//calculation of first block cipher
	aes128e(z1,iv,k);
	for(unsigned int j1=0; j1<16; j1++){
		c[j1]=z1[j1]^m[j1];
		d[j1]=z1[j1];
	}
	//variable b1 is: 0 if l is multiple of 16 (l(mod16)=0) or 1 otherwise (l(mod16)!=0)
	unsigned int b1=0;
	//variable r1 represents l(mod 16)
	unsigned int r1=l%16;
	if(r1==0){
		b1=0; //last block message is complete
	}
	else {
		b1=1; //last block message is partial
	}
	//n1 is the counter for the 4byte block cipher (starts in the one at position 1 and goes until the last one that is complete (n=(l-r1)/16-1))
	for(unsigned int n1=1; n1<((l-r1)/16); n1++){
		aes128e(z1,d,k);
		for(unsigned int j1=0; j1<16; j1++){
			c[n1*16+j1]=z1[j1]^m[n1*16+j1];
			d[j1]=z1[j1];
		}
	}
	//in case the last bock message is partial here is calculated the last cipher block 
	if(b1==1){
		aes128e(z1,d,k);
		for(unsigned int j1=0; j1<r1; j1++){
			c[(l-r1)+j1]=z1[j1]^m[(l-r1)+j1];
		}
	}
}

