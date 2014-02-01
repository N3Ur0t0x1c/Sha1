Sha1
====

SHA1 implementation in C

<<<<<<< HEAD
Implementing the SHA-1 Algorithm designed and standarized by the NIST.
SHA-1 Detail:
http://en.wikipedia.org/wiki/SHA-1

Refer to documentation;
The SHA-1 DIARIES.PDF
https://drive.google.com/file/d/0B-LQ4Q7BwGggY0l2MVhhLXBvLUE/edit?usp=sharing
=======
Implemented the calculate_sha1() function on the header, so you can just include the file shalib.h into your project and create a structure pointer and call the function using the following prototype.
int calculate_sha1(struct sha* , char *, uint32_t length);
where struct sha* is a pointer of type structure sha and char * is a pointer to message stream, and uint32_t is a length in bytes.

The hash is stored in the sha pointers digest[] array.

>>>>>>> pr/1
