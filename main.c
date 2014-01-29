#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include "shalib.h"


void debug_print(char *mss, uint32_t l)
{
    int i;
    printf("\nDEBUG PRINT START");
    for(i=0; i<l/8; i++)
    {
        printf("\n%c", *(mss+i));
    }
    printf("\nDEBUG PRINT END\n");
}

uint32_t padded_length_in_bits(uint32_t len)
{

    while((len%64)!=0)
    {
        len++;
    }
    return len*8;
}

int main()
{
    struct sha *sha1;
    int i,j;
    char text[] = "The quick brown fox jumps over the lazy dog";
    char *buffer;
    uint32_t length = strlen(text);
    uint32_t bits;
    uint32_t temp,k;

    sha1 = (struct sha *) malloc(sizeof(struct sha));
    bits = padded_length_in_bits(length);


    printf("%u", bits);


    buffer = (char *) malloc(bits/8);
    memcpy(buffer, text, length);


    printf("\ninitial length = %u", length);


    //add 1 on the last of the message..
    *(buffer+length) = 0x80;
    for(i=length+1; i<(bits/8); i++)
    {
        *(buffer+i) = 0x00;
    }

    //append the length to the last words... using 32 bit only so the
    //limitation will be this function can calculate up to 4GB files SHA1.
//    *(buffer +(bits/8)-8) = (length>>56) & 0xFF;
  //  *(buffer +(bits/8)-7) = (length>>48) & 0xFF;
    //*(buffer +(bits/8)-6) = (length>>40) & 0xFF;
    //*(buffer +(bits/8)-5) = (length>>32) & 0xFF;
    *(buffer +(bits/8)-4) = (length>>24) & 0xFF;
    *(buffer +(bits/8)-3) = (length>>16) & 0xFF;
    *(buffer +(bits/8)-2) = (length>>8) & 0xFF;
    *(buffer +(bits/8)-1) = (length>>0) & 0xFF;


    printf("length =  %u\n",length);
    printf("\n%u",bits);
    debug_print(buffer, bits);

    // initialize the default digest values
    sha1->digest[0] = 0x67452301;
    sha1->digest[1] = 0xEFCDAB89;
    sha1->digest[2] = 0x98BADCFE;
    sha1->digest[3] = 0x10325476;
    sha1->digest[4] = 0xC3D2E1F0;

    //main loop
    for(i=0; i<(bits/512); i++)
    {
        //first empty the block for each pass..
        for(j=0; j<80; j++)
        {
            sha1->w[j] = 0x00;
        }

        //fill the first 16 words with the characters read directly from the buffer.
        for(j=0; j<16; j++)
        {
            sha1->w[j] = (uint32_t) (buffer[j*4+0]<<24);
            sha1->w[j] |= (uint32_t) (buffer[j*4+1]<<16);
            sha1->w[j] |= (uint32_t) (buffer[j*4+2]<<8);
            sha1->w[j] |= (uint32_t) (buffer[j*4+3]);
        }

        //fill the rest 64 words using the formula
        for(j=16; j<80; j++)
        {
            sha1->w[j] = (ROTL(1,(sha1->w[j-3] ^ sha1->w[j-8] ^ sha1->w[j-14] ^ sha1->w[j-16])));
        }

        //initialize hash for this chunck reading the has stored in the structure digest
        sha1->a = sha1->digest[0];
        sha1->b = sha1->digest[1];
        sha1->c = sha1->digest[2];
        sha1->d = sha1->digest[4];
        sha1->e = sha1->digest[5];

        for(j=0; j<80; j++)
        {
            if((i>=0) && (i<20))
            {
                sha1->f = ((sha1->b)&(sha1->c)) | ((~(sha1->b))&(sha1->d));
                k = 0x5A827999;

            }
            else if((i>=20) && (i<40))
            {
                sha1->f = (sha1->b)^(sha1->c)^(sha1->d);
                k = 0x6ED9EBA1;
            }
            else if((i>=40) && (i<60))
            {
                sha1->f = ((sha1->b)&(sha1->c)) | ((sha1->b)&(sha1->d)) | ((sha1->c)&(sha1->d));
                k = 0x8F1BBCDC;
            }
            else if((i>=60) && (i<79))
            {
                sha1->f = (sha1->b)^(sha1->c)^(sha1->d);
                k = 0xCA62C1D6;
            }

            temp = ROTL(5,(sha1->a)) + (sha1->f) + (sha1->e) + k + sha1->w[i];
            (sha1->e) = (sha1->d);
            (sha1->d) = (sha1->c);
            (sha1->c) = ROTL(30,(sha1->b));
            (sha1->b) = (sha1->a);
            (sha1->a) = temp;


        }

        // append to total hash.
        sha1->digest[0] += sha1->a;
        sha1->digest[1] += sha1->b;
        sha1->digest[2] += sha1->c;
        sha1->digest[3] += sha1->d;
        sha1->digest[4] += sha1->e;



    }


    printf("\n\nSHA1 HASH IS:\n");
    //printf("%d\n", sizeof(unsigned int));
    for(i=0; i<5; i++)
    {
        printf("%X ",sha1->digest[i]);
    }



    free(buffer);
    return 1;
}
