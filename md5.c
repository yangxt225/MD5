/*
	MD5 算法将输入的信息进行分组，每组512 位（64个 字节），顺序处理完所有分组后输出128 位结果。
将这128 位用十六进制表示便是常见的32 字符的MD5 码，而所谓的16 字符的MD5 码，其实是这32 字符
中间的16 个字符。
	在每一组消息的处理中，都要进行4 轮、每轮16 步、总计64 步的处理。
*/

#include "md5.h"  

/*
数据填充采用PADDING数组(64Bytes)，填充数据：
	填充的第一个字节为128，其余字节全为0，128的 二进制数为1000 0000 (0x80)
*/
unsigned char PADDING[]={ 
	0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  // 16字节 
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};  
  
// 实现功能：初始化
void MD5Init(MD5_CTX *context)  
{  
    context->count[0] = 0;  
    context->count[1] = 0;  
	/* 4个32位的链接变量，最后存放MD5运算结果：将4个32位的state级联成128位输出
	
		数据这样设置之后，存在内存中就按小端规则排列：01 23 45 67 89 ab cd ef …32 10
	*/
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;  
    context->state[2] = 0x98BADCFE;  
    context->state[3] = 0x10325476;  
} 

/* 实现功能：
	对每一组消息数据，进入（4*16轮）分组处理计算MD5码
	
@param：
	context：md5结构体
	input：输入信息，字符
	inputlen：字符个数
*/
void MD5Update(MD5_CTX *context, unsigned char *input, unsigned int inputlen)  
{  
    unsigned int i = 0,index = 0,partlen = 0;  
	// 对64取余得到index，字节表示
    index = (context->count[0] >> 3) & 0x3F;  
    partlen = 64 - index;  
    context->count[0] += inputlen << 3;   // 转换成bit的长度存放
	
	/*
	只有当count[0]溢出的时候，才会出现if判断为true，此时count[1]存放高位
	*/
    if(context->count[0] < (inputlen << 3)) 
        context->count[1]++;  
	/* 存放inputlen的高3位，因为count[0]存放的是长度（byte）的二进制位（bit），乘以8（左移3位）.
	故而，inputlen的高3位永远不会被存放到count[0]中。将其存放在count[1]中。
	*/
    context->count[1] += inputlen >> 29;  
	
	// 首次进入，partlen=64，如果inputlen信息比64Bytes大
    if(inputlen >= partlen)  
    {  
		// partlen最开始为64，执行一次MD5。
        memcpy(&context->buffer[index],input,partlen);  
        MD5Transform(context->state,context->buffer);  
		
        for(i = partlen;i+64 <= inputlen;i+=64) 
			// 如果有剩余字节，在最后拷贝进buffer中。
            MD5Transform(context->state,&input[i]);  
        index = 0;          
    }    
    else  
    {
		// i = 0, 拷贝填充字符到输入数组buffer。 
        i = 0;  
    }  
	// i != 0, 将输入信息input的剩余字节（不足64Bytes）拷贝到buffer中，进入最后一轮MD5操作。
    memcpy(&context->buffer[index],&input[i],inputlen-i);  
}  

/* 实现功能：
	处理最后一次读取的消息数据：需要进行相应的数据填充
*/
void MD5Final(MD5_CTX *context, unsigned char digest[16])  
{  
    unsigned int index = 0,padlen = 0;  
    unsigned char bits[8];  
	/* 除以8，取后6个bit（意义：对64取余得到index，字节表示）
		和“0x3F（十进制为63）”进行“位与”运算，获取不满64的数值大小
	*/
	// 假设我们的输入信息的长度为80Bytes，则index=16Bytes。
    index = (context->count[0] >> 3) & 0x3F;  
	/*
	对信息进行填充，使其字节数除以64 时余数为56
		比如在处理一个文件时：
			(1) 最后一次读取为70 字节，70％64＝6 小于56，则需在尾部填充56－6＝50 个字节，得（70＋50）％64＝56。
				注：若消息为64n 倍数字节，则最后一次读取0 字节，据本规则将填充56 字节。
			(2) 最后一次读取为124 字节，124％64＝60 大于56 了，则先将这一组填满（此处为4 字节）再
				在下一组空间上填56 个字节，得（124＋4＋56）％64＝56。
			(3) 最后一次读取为120 字节，120％64＝56 等于56，此时仍需填充，填充字节总数为64，即一组，得（120＋64）％64＝56
	*/
    padlen = (index < 56)?(56-index):(120-index); 
	// 计算数据填充前的 信息数据长度，并存放在bits中
    MD5Encode(bits,context->count,8);  
	/* 最后一次读取,进行数据填充，假设我们的输入信息的长度为80Bytes，
		此时，在MD5Update中，padlen为40Bytes，即inputlen（= padlen = 40Bytes） >= partlen（= 64 - index = 48Bytes）不成立
	*/
    MD5Update(context,PADDING,padlen);  
	/* 将8字节的信息数据长度bits加入到context中，
		此时,在MD5Update函数中，满足inputlen（8Bytes） >= partlen（8Bytes），进入一次MD5操作。
	*/
    MD5Update(context,bits,8);  
	
	// 将最后的md5结果级联起来，存放到目标数组中以便输出
    MD5Encode(digest,context->state,16);  
}  

/*
实现功能：
	将input中的内容，逐字节 存放到output中。
*/ 
void MD5Encode(unsigned char *output,unsigned int *input,unsigned int len)  
{  
    unsigned int i = 0,j = 0;  
    while(j < len)  
    {  
        output[j] = input[i] & 0xFF;    
        output[j+1] = (input[i] >> 8) & 0xFF;  
        output[j+2] = (input[i] >> 16) & 0xFF;  
        output[j+3] = (input[i] >> 24) & 0xFF;  
        i++;  
        j+=4;  
    }  
}  

/*
实现功能：
	将char类型数组input中的内容，按每4字节组合成一个int类型的数据a，并将a存放在int类型数组output中。
*/
void MD5Decode(unsigned int *output,unsigned char *input,unsigned int len)  
{  
    unsigned int i = 0,j = 0;  
    while(j < len)  
    {  
        output[i] = (input[j]) |  
            (input[j+1] << 8) |  
            (input[j+2] << 16) |  
            (input[j+3] << 24);  
        i++;  
        j+=4;   
    }  
}  

/* 实现功能：
	对每一块block数据（每一个分组），进行4*16轮的MD5运算。

设Mj表示消息的第j个子分组（从0到15），<<< s表示循环左移s位，则四种操作为：
	FF(a,b,c,d,Mj,s,ti)表示a=b+((a+(F(b,c,d)+Mj+ti)<<< s) 
	GG(a,b,c,d,Mj,s,ti)表示a=b+((a+(G(b,c,d)+Mj+ti)<<< s) 
	HH(a,b,c,d,Mj,s,ti)表示a=b+((a+(H(b,c,d)+Mj+ti)<<< s) 
	II(a,b,c,d,Mj,s,ti)表示a=b+((a+(I(b,c,d)+Mj+ti)<<< s) 
	
在第i步中，ti是4294967296*abs(sin(i))的整数部分,i的单位是弧度,i的取值从1到64。
*/
void MD5Transform(unsigned int state[4],unsigned char block[64])   // 64Bytes = 64*8 = 512bits
{  
    unsigned int a = state[0];  
    unsigned int b = state[1];  
    unsigned int c = state[2];  
    unsigned int d = state[3];
	// char类型的block中的数据经过组织之后存放到int类型的x数组，x只有0~15号索引的空间被使用到
    unsigned int x[64];  
    MD5Decode(x,block,64);  
	
    FF(a, b, c, d, x[ 0], 7, 0xd76aa478);   
    FF(d, a, b, c, x[ 1], 12, 0xe8c7b756);   
    FF(c, d, a, b, x[ 2], 17, 0x242070db);   
    FF(b, c, d, a, x[ 3], 22, 0xc1bdceee);   
    FF(a, b, c, d, x[ 4], 7, 0xf57c0faf);   
    FF(d, a, b, c, x[ 5], 12, 0x4787c62a);   
    FF(c, d, a, b, x[ 6], 17, 0xa8304613);   
    FF(b, c, d, a, x[ 7], 22, 0xfd469501);   
    FF(a, b, c, d, x[ 8], 7, 0x698098d8);   
    FF(d, a, b, c, x[ 9], 12, 0x8b44f7af);   
    FF(c, d, a, b, x[10], 17, 0xffff5bb1);   
    FF(b, c, d, a, x[11], 22, 0x895cd7be);   
    FF(a, b, c, d, x[12], 7, 0x6b901122);   
    FF(d, a, b, c, x[13], 12, 0xfd987193);   
    FF(c, d, a, b, x[14], 17, 0xa679438e);   
    FF(b, c, d, a, x[15], 22, 0x49b40821);   
  
      
    GG(a, b, c, d, x[ 1], 5, 0xf61e2562);   
    GG(d, a, b, c, x[ 6], 9, 0xc040b340);   
    GG(c, d, a, b, x[11], 14, 0x265e5a51);   
    GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);   
    GG(a, b, c, d, x[ 5], 5, 0xd62f105d);   
    GG(d, a, b, c, x[10], 9,  0x2441453);   
    GG(c, d, a, b, x[15], 14, 0xd8a1e681);   
    GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);   
    GG(a, b, c, d, x[ 9], 5, 0x21e1cde6);   
    GG(d, a, b, c, x[14], 9, 0xc33707d6);   
    GG(c, d, a, b, x[ 3], 14, 0xf4d50d87);   
    GG(b, c, d, a, x[ 8], 20, 0x455a14ed);   
    GG(a, b, c, d, x[13], 5, 0xa9e3e905);   
    GG(d, a, b, c, x[ 2], 9, 0xfcefa3f8);   
    GG(c, d, a, b, x[ 7], 14, 0x676f02d9);   
    GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);   
  
      
    HH(a, b, c, d, x[ 5], 4, 0xfffa3942);   
    HH(d, a, b, c, x[ 8], 11, 0x8771f681);   
    HH(c, d, a, b, x[11], 16, 0x6d9d6122);   
    HH(b, c, d, a, x[14], 23, 0xfde5380c);   
    HH(a, b, c, d, x[ 1], 4, 0xa4beea44);   
    HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9);   
    HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60);   
    HH(b, c, d, a, x[10], 23, 0xbebfbc70);   
    HH(a, b, c, d, x[13], 4, 0x289b7ec6);   
    HH(d, a, b, c, x[ 0], 11, 0xeaa127fa);   
    HH(c, d, a, b, x[ 3], 16, 0xd4ef3085);   
    HH(b, c, d, a, x[ 6], 23,  0x4881d05);   
    HH(a, b, c, d, x[ 9], 4, 0xd9d4d039);   
    HH(d, a, b, c, x[12], 11, 0xe6db99e5);   
    HH(c, d, a, b, x[15], 16, 0x1fa27cf8);   
    HH(b, c, d, a, x[ 2], 23, 0xc4ac5665);   
  
      
    II(a, b, c, d, x[ 0], 6, 0xf4292244);   
    II(d, a, b, c, x[ 7], 10, 0x432aff97);   
    II(c, d, a, b, x[14], 15, 0xab9423a7);   
    II(b, c, d, a, x[ 5], 21, 0xfc93a039);   
    II(a, b, c, d, x[12], 6, 0x655b59c3);   
    II(d, a, b, c, x[ 3], 10, 0x8f0ccc92);   
    II(c, d, a, b, x[10], 15, 0xffeff47d);   
    II(b, c, d, a, x[ 1], 21, 0x85845dd1);   
    II(a, b, c, d, x[ 8], 6, 0x6fa87e4f);   
    II(d, a, b, c, x[15], 10, 0xfe2ce6e0);   
    II(c, d, a, b, x[ 6], 15, 0xa3014314);   
    II(b, c, d, a, x[13], 21, 0x4e0811a1);   
    II(a, b, c, d, x[ 4], 6, 0xf7537e82);   
    II(d, a, b, c, x[11], 10, 0xbd3af235);   
    II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb);   
    II(b, c, d, a, x[ 9], 21, 0xeb86d391);   
    state[0] += a;  
    state[1] += b;  
    state[2] += c;  
    state[3] += d;  
}  
