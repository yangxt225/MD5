#ifndef MD5_H  
#define MD5_H  

#include "string.h"
#include "stdio.h"
  
typedef struct  
{  
	// 存放输入信息长度
    unsigned int count[2];  
	// 存放4个初始标准幻数，并用来存放最后的MD5计算结果
    unsigned int state[4];  
	// 存放每一组64Bytes数据
    unsigned char buffer[64];     
}MD5_CTX;  
    
/*
* 	初始化MD5计算所需的4个初始标准幻数
*/
void MD5Init(MD5_CTX *context); 

/*
*	函数功能：MD5计算函数；
*	param1：MD5_CTX数据结构指针；
*	param2：输入信息；
*	param3：输入信息长度；
*/ 
void MD5Update(MD5_CTX *context, unsigned char *input, unsigned int inputlen);  

/*
*	函数功能：处理输入信息中最后不足64Bytes的数据内容；
*	param1：MD5_CTX数据结构指针；
*	param2：MD5结果最后存放数组；
*/
void MD5Final(MD5_CTX *context, unsigned char digest[16]);  

/*
*	函数功能：计算MD5的值的接口函数
*	内部仅仅转调用：
*	MD5Init 
*	MD5Update  
*   MD5Final 
*/
void CalcMD5(unsigned char *input, unsigned int inputlen, unsigned char digest[16]);

void _MD5Transform(unsigned int state[4],unsigned char block[64]);  
void _MD5Encode(unsigned char *output,unsigned int *input,unsigned int len);  
void _MD5Decode(unsigned int *output,unsigned char *input,unsigned int len);  
  
#endif  
