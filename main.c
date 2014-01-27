#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include "sha1.h"


int sha_pad_message(char *message, size_t len, char *trgt)
{

    int i=0,j;
    int orgbits = len*8;
    int bits = orgbits;
    while((bits%512) != 0)
    {
        bits++;
    }

    printf("%d", bits);

    trgt = (char *)malloc(bits/8);
    memcpy(trgt, message, len);
    printf("\n");

    for(i=0; i<len; i++)
    {
        printf("%c", *(trgt+i));
    }

    *(message+len) = 0x80;
    len++;
    while((orgbits%512)!=448)
    {
        ++i;
        *(message+i) = 0x00;
        orgbits = orgbits+8;
    }
    for(j=0; j<4; j++)
    {
        *(message+(++i)) = 0x00;
    }
    *(message +(++i)) = (len>>24) & 0xFF;
    *(message +(++i)) = (len>>16) & 0xFF;
    *(message +(++i)) = (len>>8) & 0xFF;
    *(message +(++i)) = (len>>0) & 0xFF;

    return 1;

}


int parse_sha1_block(struct sha *sha1, char *message)
{
    int i;
    for(i=0; i<16; i++)
    {
        sha1->msg[i] = (*(message+0)<<24) | (*(message+1)<<16) | (*(message+2)<<8) | (*(message+3)<<0);
        message=message+4;
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
    ssha = (struct sha *) malloc(sizeof(struct sha));
    int i;
    char nam[] = "Niraj Khadka is a good boy. He is so gentle that he is very profound of doing things on his very own. wish he is a very good.";
    int x = sha_pad_message(nam, strlen(nam), target);

    for(i=0; i<strlen(nam); i++)
    {
        printf("\t%c", target[i]);
    }

    printf("\n\n\n\n");
    x = parse_sha1_block(ssha, nam);
    for(i=0; i<80;i++)
    {
        printf("message[%d] = %lu", i, ssha->msg[i]);
    }
    return 0;
}
