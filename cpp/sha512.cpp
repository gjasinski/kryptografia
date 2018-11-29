#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
 
//wygenerowac kluczem prywatnym podpis
//zweryfikowac kluczem publicznym
int main(int argc, char *argv[])
{
    if (argc == 2){
      unsigned char buffer[1000000];
      FILE *ptr;

      ptr = fopen(argv[1],"rb");  // r for read, b for binary

      int size = fread(buffer,1000000,1,ptr);
      

      unsigned char digest[SHA512_DIGEST_LENGTH];
    
      SHA512(buffer, size, (unsigned char*)&digest);    
      char mdString[SHA512_DIGEST_LENGTH*2+1];
  
      for(int i = 0; i < SHA512_DIGEST_LENGTH; i++)
          sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
  
      printf("SHA512 digest: %s\n", mdString);
      
      FILE *f = fopen("signature", "w");
      
      /* print some text */
      const char *text = "Write this to the file";
      fprintf(f, "%s\n", mdString);
      
    }
    else{
      unsigned char buffer[1000000];
      FILE *ptr;

      ptr = fopen(argv[1],"rb");  // r for read, b for binary

      int size = fread(buffer,sizeof(buffer),1,ptr);

      unsigned char digest[SHA512_DIGEST_LENGTH];
    
      SHA512(buffer, size, (unsigned char*)&digest);    
      char mdString[SHA512_DIGEST_LENGTH*2+1];
  
      for(int i = 0; i < SHA512_DIGEST_LENGTH; i++)
          sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
  
      printf("SHA512 digest: %s\n", mdString);
      

      unsigned char toVerify[600];
      FILE *ptrVrf;

      ptrVrf = fopen("signature","rb");  // r for read, b for binary

      int readSize = fread(toVerify,sizeof(toVerify),1,ptrVrf);
      printf("SHA512 digest: %s\n", toVerify);
  

    }
    
    return 0;
}