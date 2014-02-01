#ifndef SHALIB_H_INCLUDED
#define SHALIB_H_INCLUDED

#define ROTL(bits,word) (((word) << (bits)) | ((word) >> (32-(bits))))
typedef unsigned int uint32_t;
void debug_print(char *, uint32_t);
uint32_t padded_length_in_bits(uint32_t);
//int calculate_sha1(struct sha *, unsigned char *);

struct sha
{
    uint32_t digest[5];
    uint32_t w[80];
    uint32_t a,b,c,d,e,f;
    int err;
};


#endif // SHALIB_H_INCLUDED
