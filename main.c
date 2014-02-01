#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include "shalib.h"





int main(int argc, char*argv[])
{
    char option;
    int er,i;
    uint32_t file_len;
    struct sha *shaa;
    unsigned char *buff;
    FILE *fp;

    shaa = (struct sha *) malloc(sizeof(struct sha));
    printf("\n SHA1 GENERATOR V0.1b \n (C) 2014 Niraj Khadka (N3Ur0t0x1c)");
    if(argc<3)
    {
        printf("\nusage: %s option content", argv[0]);
        printf("\noption may be f for file and t for text");
        printf("\ncontent may be filename for f option and text for t option\n");
        free(shaa);
        exit(0);
    }
    else
    {
        option = *argv[1];
        switch(option)
        {
        case 't':
            {
                file_len = strlen((char *) argv[2]);
                printf("\nstrlen is %u", file_len);
                er = calculate_sha1(shaa,(unsigned char*)argv[2],file_len);
                break;
            }
        case 'f':
            {
                if((fp =fopen(argv[2],"rb")) == NULL)
                {
                    printf("\nError opening file..\nExiting....");
                    free(shaa);
                    exit(0);
                }

                //Get file length
                fseek(fp, 0, SEEK_END);
                file_len=ftell(fp);
                fseek(fp, 0, SEEK_SET);

                //printf("\n File length = %ul",file_len);

                //allocate memeory to read the whole file into  a buffer.
                buff = (unsigned char *) malloc(file_len);

                //If buffer is null then exit.
                if(!buff)
                {
                    printf("\nError allocating memory..");
                    free(shaa);
                    fclose(fp);
                    exit(0);
                }

                //Reading the total file on a memeory in one shot.
                fread(buff, file_len, 1, fp);
                fclose(fp);

                //call function
                er = calculate_sha1(shaa, buff, file_len);

                if(er != 0)
                {
                    printf("\n Error calculating SHA1 hash.. \n");
                    exit (0);
                }



            }
        }
    }

    //print hash
    printf("\n\nSHA1 HASH IS:\n");
    for(i=0; i<5; i++)
    {
        printf("%X ",shaa->digest[i]);
    }
    printf("\n");
    free(buff);
    free(shaa);
    return 0;
}

