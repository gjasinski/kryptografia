#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
 
bool generate_key()
{
    int             ret = 0;
    RSA             *r = NULL;
    BIGNUM          *bne = NULL;
    BIO             *bp_public = NULL, *bp_private = NULL;
 
    int             bits = 2048;
    unsigned long   e = RSA_F4;
 
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        goto free_all;
    }
 
    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if(ret != 1){
        goto free_all;
    }
 
   bp_public = BIO_new_file("public.pem", "w+");
    ret = PEM_write_bio_RSA_PUBKEY(bp_public, r);
    if(ret != 1){
        goto free_all;
    }
    //printf("%s", bp_public);
 
    bp_private = BIO_new_file("private.pem", "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

 
    // 4. free
free_all:
 
    BIO_free_all(bp_public);
    BIO_free_all(bp_private);
    RSA_free(r);
    BN_free(bne);
 
    return (ret == 1);
}

void print_pub(){
    char ch;
    char* file_name = "public.pem";
   FILE *fp;
 
   
 
   fp = fopen(file_name, "r"); // read mode
 
   if (fp == NULL)
   {
      perror("Error while opening the file.\n");
      exit(EXIT_FAILURE);
   }
 
   printf("The contents of %s file are:\n", file_name);
 
   while((ch = fgetc(fp)) != EOF)
      printf("%c", ch);
 
   fclose(fp);
}


void print_priv(){
    char ch;
    char* file_name = "private.pem";
   FILE *fp;
 
   
 
   fp = fopen(file_name, "r"); // read mode
 
   if (fp == NULL)
   {
      perror("Error while opening the file.\n");
      exit(EXIT_FAILURE);
   }
 
   printf("The contents of %s file are:\n", file_name);
 
   while((ch = fgetc(fp)) != EOF)
      printf("%c", ch);
 
   fclose(fp);
}


int main(int argc, char* argv[]) 
{
    generate_key();
    print_pub();
    print_priv();
        return 0;
}