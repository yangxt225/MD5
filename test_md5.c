 
#include "md5.h"  
  
int main(int argc, char *argv[])  
{  
    MD5_CTX md5;  
    MD5Init(&md5);           
    int i;  
    unsigned char encrypt[] ="12345678901234567890123456789012345678901234567890123456789012345678901234567890";//MD5(admin) = 21232f297a57a5a743894a0e4a801fc3  
    unsigned char decrypt[16];      
    MD5Update(&md5,encrypt,strlen((char *)encrypt));  
    MD5Final(&md5,decrypt);   
    printf("加密前:%s\n加密后16位:",encrypt);  
    for(i=4;i<12;i++)  
    {  
		// X表示以十六进制形式输出,02表示不足两位,前面补0输出;出过两位,不影响.
        printf("%02x",decrypt[i]);  //02x前需要加上 % , 
    }  
       
    printf("\n加密前:%s\n加密后32位:",encrypt);  
    for(i=0;i<16;i++)  
    {  
        printf("%02x",decrypt[i]);  //02x前需要加上 %  
    }  
  
    getchar();  
  
    return 0;  
}  
