#include "DES.h"
#include<stdio.h>
#include <string.h>
//将位扩展成字节
void Bit2Byte(unsigned char *input, unsigned char *output,unsigned int length)
{
	for (int i = 0; i < length; i++)
	{
		output[i] = (input[i / 8] >> ( i % 8 )) & 1;
		//printf("output[%d]:%d\n",i,output[i]);
	}
}
//将字节转换成位
void Byte2Bit(unsigned char *input,unsigned char *output,unsigned int length)
{
	memset(output, 0, 8);
	for (int i = 0; i < length; i++)
	{
		output[i / 8] |=  input[i] << (i % 8);
	//	printf("output[%d]:%d\n", i, output[i]);
	}
}
//初始IP置换
void InitProcess(unsigned char *input,unsigned char *output)
{
	for (int i = 0; i < 64; i++)
	{
		output[i] = input[IP_Table[i]];
	}
}
//逆IP置换
void InvInitProcess(unsigned char *input, unsigned char *output)
{
	for (int i = 0; i < 64; i++)
	{
		output[i] = input[IP_Inv_Table[i]];
	}
}
//16轮加密函数
void EncryptFun(unsigned char *data, unsigned char key[][48])
{
	unsigned char *left = data;//输入数据的左32位
	unsigned char *right = data + 32;//输入数据的右32位
	unsigned char output[32];
	unsigned char temp[32] = { 0 };
	int i = 0;
	for (; i < 15; i++)
	{
		BytesCopy(temp, right, 32);//字节拷贝
		F_Function(right, output, key[i]);//F函数
		XOR(left, output, right, 32);//异或操作，同时交换
		BytesCopy(left, temp, 32);//字节拷贝
	}
	//最后一轮不交换
	F_Function(right, output, key[i]);
	XOR(left, output, left,32);
}
//F函数
void F_Function(unsigned char *right, unsigned char * output,unsigned char *key)
{
	unsigned char temp1[48] = { 0 };
	unsigned char temp2[32] = { 0 };
	ExpandBit(right, temp1);//位扩展，32位扩展成48位
	XOR(temp1, key, temp1, 48);
	SBox_Function(temp1,temp2);//S盒函数
	P_Function(temp2, output);//置换，32-32
}
//位扩展函数
void ExpandBit(unsigned char *right,unsigned char *expand)
{
	for (int i = 0; i < 48; i++)
	{
		expand[i] = right[E_Table[i]];
	}
}
//S盒函数
void SBox_Function(unsigned char *input, unsigned char *output)
{
	unsigned char row = 0, col = 0;
	unsigned char val = 0;
	for (int i = 0; i < 8; i++)
	{
		row = 2 * input[i * 6] + input[i * 6 + 5];//计算行
		col = 0;
		//计算列
		for (int j = 1; j < 5; j++)
		{
			col = col << 1;
			col += input[i * 6 + j];
		}
		val = S[i][row][col];
		Bit2Byte(&val,output + i * 4,4);//将对应的值转换成4字节
	}
}
//P操作
void P_Function(unsigned char *input, unsigned char *output)
{
	for (int i = 0; i < 32; i++)
	{
		output[i] = input[P_Table[i]];
	}
}
//PC操作1
void PermutdChoice_1(unsigned char *input,unsigned char *output)
{
	for (int i = 0; i < 56; i++)
	{
		output[i] = input[PC_1[i]];
	}
}
//逆序
void Reverse(unsigned char *data, int start, int end)
{
	int i = start, j = end;
	unsigned char temp;
	while (i < j)
	{
		temp = data[i];
		data[i] = data[j];
		data[j] = temp;
		i++;
		j--;
	}
}
//循环左移
void LeftShift(unsigned char *data, unsigned index)
{
		Reverse(data,0,index-1);
		Reverse(data, index, 27);
		Reverse(data, 0, 27);
}
//PC操作2
void PermutdChoice_2(unsigned char *input, unsigned char *output)
{
	for (int i = 0; i < 48; i++)
	{
		output[i] = input[PC_2[i]];
	}
}
//异或
void XOR(unsigned char *data1, unsigned char *data2, unsigned char *output,int length)
{
	for (int i = 0; i < length; i++)
	{
		output[i] = data1[i] ^ data2[i];
	}
}
//计算16轮子密钥
void CaculateKey(unsigned char *Key, unsigned char  output[][48])
{
	unsigned char temp[56] = { 0 };
	unsigned char key_Byte[64] = { 0 };
	Bit2Byte(Key, key_Byte, 64);
	PermutdChoice_1(key_Byte, temp);
	for (int i = 0; i < 16; i++)
	{

		LeftShift(temp, MOVE_TIMES[i]);
		LeftShift(temp + 28, MOVE_TIMES[i]);
		PermutdChoice_2(temp, output[i]);
	}
}
//加密
void DESEncrypt(unsigned char *data,unsigned char keys[][48],unsigned char *output)
{
	unsigned char input[64] = { 0 };
	unsigned char temp1[64] = { 0 };
	unsigned char temp2[64] = { 0 };
	Bit2Byte(data, input, 64);
	InitProcess(input, temp1);
	EncryptFun(temp1, keys);
	InvInitProcess(temp1,temp2 );
	Byte2Bit(temp2, output, 64);
}
//解密
void DESDecrypt(unsigned char *data, unsigned char keys[][48], unsigned char *output)
{
	unsigned char input[64] = { 0 };
	unsigned char temp1[64] = { 0 };
	unsigned char temp2[64] = { 0 };
	Bit2Byte(data, input, 64);
	InitProcess(input, temp1);
	DecryptFun(temp1, keys);
	InvInitProcess(temp1, temp2);
	Byte2Bit(temp2, output, 64);
}
//16轮解密函数
void DecryptFun(unsigned char *data, unsigned char key[][48])
{
	unsigned char *left = data;
	unsigned char *right = data + 32;
	unsigned char output[32];
	unsigned char temp[32] = { 0 };
	int i = 0;
	for (; i < 15; i++)
	{
		BytesCopy(temp, right, 32);
		F_Function(right, output, key[15-i]);
		XOR(left, output, right, 32);
		BytesCopy(left, temp, 32);
	}
	F_Function(right, output, key[15-i]);
	XOR(left, output, left, 32);
}
//字节复制
void BytesCopy(unsigned char *dest,unsigned char *src,unsigned num)
{
	for (int i = 0; i < num; i++)
	{
		dest[i] = src[i];
	}
}
bool StreamEncypt(unsigned char *data, unsigned char keys[][48], unsigned char *output, unsigned int length)
{
	if (length % 8 != 0)
		return false;
	for (unsigned int i = 0; i <length; i = i + 8)
	{
		DESEncrypt(data + i, keys, output + i);
	}
	return true;
}
bool StreamDecypt(unsigned char *data, unsigned char keys[][48], unsigned char *output, unsigned int length)
{
	if (length % 8 != 0)
		return false;
	for (unsigned int i = 0; i < length; i = i + 8)
	{
		DESDecrypt(data + i, keys, output + i);
	}
	return true;
}
