#ifndef SHALIB_H_INCLUDED
#define SHALIB_H_INCLUDED
#define ROTL(bits,word) (((word) << (bits)) | ((word) >> (32-(bits))))
typedef unsigned int uint32_t;
void debug_print(char *, uint32_t);
uint32_t padded_length_in_bits(uint32_t len);

struct sha
{
    uint32_t digest[5];
    uint32_t w[80];
    uint32_t a,b,c,d,e,f;
    int err;
};


uint32_t padded_length_in_bits(uint32_t len)
{
    if(len%64 == 56)
    {
        len++;
    }
    while((len%64)!=56)
    {
        len++;
    }
    return len*8;
}


int calculate_sha1(struct sha *sha1, unsigned char *text, uint32_t length)
{
    unsigned int i,j;
    unsigned char *buffer;
    uint32_t bits;
    uint32_t temp,k;
    uint32_t lb = length*8;
    
    bits = padded_length_in_bits(length);
    buffer = (unsigned char *) malloc((bits/8)+8);
    if(buffer == NULL)
    {
    	printf("\nError allocating memory...");
    	return 1;
    }
    
    memcpy(buffer, text, length);


    //add 1 on the last of the message..
    *(buffer+length) = 0x80;
    for(i=length+1; i<(bits/8); i++)
    {
        *(buffer+i) = 0x00;
    }

    /*append the length to the last words... using 32 bit only so the
    limitation will be this function can calculate up to 2^32 bits files SHA1.
	*(buffer +(bits/8)-8) = (length>>56) & 0xFF;
  	*(buffer +(bits/8)-7) = (length>>48) & 0xFF;
    *(buffer +(bits/8)-6) = (length>>40) & 0xFF;
    *(buffer +(bits/8)-5) = (length>>32) & 0xFF;
    */

    *(buffer +(bits/8)+4+0) = (lb>>24) & 0xFF;
    *(buffer +(bits/8)+4+1) = (lb>>16) & 0xFF;
    *(buffer +(bits/8)+4+2) = (lb>>8) & 0xFF;
    *(buffer +(bits/8)+4+3) = (lb>>0) & 0xFF;


    // initialize the default digest values
    sha1->digest[0] = 0x67452301;
    sha1->digest[1] = 0xEFCDAB89;
    sha1->digest[2] = 0x98BADCFE;
    sha1->digest[3] = 0x10325476;
    sha1->digest[4] = 0xC3D2E1F0;

    //main loop
    for(i=0; i<((bits+64)/512); i++)
    {
        //first empty the block for each pass..
        for(j=0; j<80; j++)
        {
            sha1->w[j] = 0x00;
        }


        //fill the first 16 words with the characters read directly from the buffer.
        for(j=0; j<16; j++)
        {
            sha1->w[j] =buffer[j*4+0];
            sha1->w[j] = sha1->w[j]<<8;
            sha1->w[j] |= buffer[j*4+1];
            sha1->w[j] = sha1->w[j]<<8;
            sha1->w[j] |= buffer[j*4+2];
            sha1->w[j] = sha1->w[j]<<8;
            sha1->w[j] |= buffer[j*4+3];
        }

        //fill the rest 64 words using the formula
        for(j=16; j<80; j++)
        {
            sha1->w[j] = (ROTL(1,(sha1->w[j-3] ^ sha1->w[j-8] ^ sha1->w[j-14] ^ sha1->w[j-16])));
        }


        //initialize hash for this chunck reading that has been stored in the structure digest
        sha1->a = sha1->digest[0];
        sha1->b = sha1->digest[1];
        sha1->c = sha1->digest[2];
        sha1->d = sha1->digest[3];
        sha1->e = sha1->digest[4];

		//for all the 80 32bit blocks calculate f and use k accordingly per specification.
        for(j=0; j<80; j++)
        {
            if((j>=0) && (j<20))
            {
                sha1->f = ((sha1->b)&(sha1->c)) | ((~(sha1->b))&(sha1->d));
                k = 0x5A827999;

            }
            else if((j>=20) && (j<40))
            {
                sha1->f = (sha1->b)^(sha1->c)^(sha1->d);
                k = 0x6ED9EBA1;
            }
            else if((j>=40) && (j<60))
            {
                sha1->f = ((sha1->b)&(sha1->c)) | ((sha1->b)&(sha1->d)) | ((sha1->c)&(sha1->d));
                k = 0x8F1BBCDC;
            }
            else if((j>=60) && (j<80))
            {
                sha1->f = (sha1->b)^(sha1->c)^(sha1->d);
                k = 0xCA62C1D6;
            }

            temp = ROTL(5,(sha1->a)) + (sha1->f) + (sha1->e) + k + sha1->w[j];
            sha1->e = (sha1->d);
            sha1->d = (sha1->c);
            sha1->c = ROTL(30,(sha1->b));
            sha1->b = (sha1->a);
            sha1->a = temp;

            //reset temp to 0 to be in safe side only, not mandatory.
            temp =0x00;


        }

        // append to total hash.
        sha1->digest[0] += sha1->a;
        sha1->digest[1] += sha1->b;
        sha1->digest[2] += sha1->c;
        sha1->digest[3] += sha1->d;
        sha1->digest[4] += sha1->e;


		//since we used 512bit size block per each pass, let us update the buffer pointer accordingly.
        buffer = buffer+64;

    }

    return 0;
}

#endif // SHALIB_H_INCLUDED
