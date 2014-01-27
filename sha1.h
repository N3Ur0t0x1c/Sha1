#ifndef SHA1_H_INCLUDED
#define SHA1_H_INCLUDED
#define ROTL(bits,word) (((word) << (bits)) | ((word) >> (32-(bits))))

typedef unsigned long uint32_t;


struct sha
{
    uint32_t digest[5];
    uint32_t msg[80];
    unsigned int error;
};

int parse_sha1_block(struct sha*, char *);



#endif // SHA1_H_INCLUDED
