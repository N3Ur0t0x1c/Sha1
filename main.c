#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include "sha1.h"


int sha_pad_message(char *message, uint32_t len, char *trgt)
{

    int i=0;
    char *orgtrgt;
    uint32_t orglen = len;
    uint32_t orgbits = len*8;
    uint32_t bits = orgbits;
    while((bits%512) != 0)
    {
        bits++;
    }

    realloc(trgt, (bits/8));
    orgtrgt = trgt;
    memcpy(trgt, message, len);
    //DEBUG printf("\n ORGLEN = %u\n", len);

    /* DEBUG
    for(i=0; i<len; i++)
    {
        printf("%c\n",*(trgt+i));
    }
    */

    //DEBUG printf("%u", bits);
    //DEBUG printf("\n");

    /* DEBUG
    for(i=0; i<len; i++)
    {
        printf("%c", *(trgt+i));
    }
    */

    //DEBUG printf("%c\n", *(trgt+len-1));
    *(trgt+len) = 0x80;

    //DEBUG printf("%c\n", *(trgt+len));

    len++;
    trgt = trgt+len;

    i=1;
    while((orgbits%512)!=0)
    {
        len++;
        orgbits = orgbits+8;
        //DEBUG  printf("\nORGBITS = %u", orgbits);
        ++i;
        *(trgt+i) = 0x00;


    }
    trgt = orgtrgt;
    // DEBUG printf("\n After while loop length = %u bytes and %u bits\n", orgbits/8, orgbits);

    *(trgt +(orgbits/8)-8) = (orglen>>56) & 0xFF;
    *(trgt +(orgbits/8)-7) = (orglen>>48) & 0xFF;
    *(trgt +(orgbits/8)-6) = (orglen>>40) & 0xFF;
    *(trgt +(orgbits/8)-5) = (orglen>>32) & 0xFF;
    *(trgt +(orgbits/8)-4) = (orglen>>24) & 0xFF;
    *(trgt +(orgbits/8)-3) = (orglen>>16) & 0xFF;
    *(trgt +(orgbits/8)-2) = (orglen>>8) & 0xFF;
    *(trgt +(orgbits/8)-1) = (orglen>>0) & 0xFF;

    /*
    DEBUG  printf("\nfinal length = %u\n", orgbits);

    len = orgbits/8;
    for(i=0; i<len; i++)
    {
        printf("%c\n",*(trgt+i));
    }
    */

    return orgbits/8;

}


int parse_sha1_block(struct sha *sha1, char *message)
{
    uint32_t i,j;
    printf("\n%c %c %c %c\n",message[56], message[57], message[58], message[59]);

    //Emptying the sha1->msg[i] block.

    for(i=0; i<80; i++)
    {
        sha1->msg[i] = 0x00;
    }

    for(j=0; j<16; j++)
    {
        printf("\n%c %c %c %c",message[j*4], message[j*4+1], message[j*4+2], message[j*4+3]);

        /* ek chin lai matra comment gareko kehi mili rako chaina.
        sha1->msg[i] = (uint32_t) (message[i*4+0]<<24);
        sha1->msg[i] |= (uint32_t) (message[i*4+1]<<16);
        sha1->msg[i] |= (uint32_t) (message[i*4+2]<<8);
        sha1->msg[i] |= (uint32_t) (message[i*4+3]);
        */
    }
    for(i=16; i<80; i++)
    {
        sha1->msg[i] = (ROTL(1,(sha1->msg[i-3] ^ sha1->msg[i-8] ^ sha1->msg[i-14] ^ sha1->msg[i-16])));
    }
    return 1;
}


int main()
{
    struct sha *ssha;
    char *target;
    target = (char *) malloc (sizeof(char));
    ssha = (struct sha *) malloc(sizeof(struct sha));
    int i,x;
    char nam[] = "Nirajkhadkaisagoodboy.Heissogentlethatheisveryprofoundofdoingthings.Letusseewhathappensifweincreasethesizeoftext.";
    int number = sha_pad_message(nam, strlen(nam), target);


    for(i=0; i<64; i++)
    {
        printf("%c\n", target[i]);
    }

    printf("\n\n\n\n");


    x = parse_sha1_block(ssha, target);

    printf("\n\n\n");
    for(i=0; i<80;i++)
    {
        printf("message[%d] = %lu\n", i, ssha->msg[i]);
    }


    return 0;
}
