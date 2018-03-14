#include "DES.h"
#include<stdio.h>
#include <string.h>
//��λ��չ���ֽ�
void Bit2Byte(unsigned char *input, unsigned char *output,unsigned int length)
{
	for (int i = 0; i < length; i++)
	{
		output[i] = (input[i / 8] >> ( i % 8 )) & 1;
		//printf("output[%d]:%d\n",i,output[i]);
	}
}
//���ֽ�ת����λ
void Byte2Bit(unsigned char *input,unsigned char *output,unsigned int length)
{
	memset(output, 0, 8);
	for (int i = 0; i < length; i++)
	{
		output[i / 8] |=  input[i] << (i % 8);
	//	printf("output[%d]:%d\n", i, output[i]);
	}
}
//��ʼIP�û�
void InitProcess(unsigned char *input,unsigned char *output)
{
	for (int i = 0; i < 64; i++)
	{
		output[i] = input[IP_Table[i]];
	}
}
//��IP�û�
void InvInitProcess(unsigned char *input, unsigned char *output)
{
	for (int i = 0; i < 64; i++)
	{
		output[i] = input[IP_Inv_Table[i]];
	}
}
//16�ּ��ܺ���
void EncryptFun(unsigned char *data, unsigned char key[][48])
{
	unsigned char *left = data;//�������ݵ���32λ
	unsigned char *right = data + 32;//�������ݵ���32λ
	unsigned char output[32];
	unsigned char temp[32] = { 0 };
	int i = 0;
	for (; i < 15; i++)
	{
		BytesCopy(temp, right, 32);//�ֽڿ���
		F_Function(right, output, key[i]);//F����
		XOR(left, output, right, 32);//��������ͬʱ����
		BytesCopy(left, temp, 32);//�ֽڿ���
	}
	//���һ�ֲ�����
	F_Function(right, output, key[i]);
	XOR(left, output, left,32);
}
//F����
void F_Function(unsigned char *right, unsigned char * output,unsigned char *key)
{
	unsigned char temp1[48] = { 0 };
	unsigned char temp2[32] = { 0 };
	ExpandBit(right, temp1);//λ��չ��32λ��չ��48λ
	XOR(temp1, key, temp1, 48);
	SBox_Function(temp1,temp2);//S�к���
	P_Function(temp2, output);//�û���32-32
}
//λ��չ����
void ExpandBit(unsigned char *right,unsigned char *expand)
{
	for (int i = 0; i < 48; i++)
	{
		expand[i] = right[E_Table[i]];
	}
}
//S�к���
void SBox_Function(unsigned char *input, unsigned char *output)
{
	unsigned char row = 0, col = 0;
	unsigned char val = 0;
	for (int i = 0; i < 8; i++)
	{
		row = 2 * input[i * 6] + input[i * 6 + 5];//������
		col = 0;
		//������
		for (int j = 1; j < 5; j++)
		{
			col = col << 1;
			col += input[i * 6 + j];
		}
		val = S[i][row][col];
		Bit2Byte(&val,output + i * 4,4);//����Ӧ��ֵת����4�ֽ�
	}
}
//P����
void P_Function(unsigned char *input, unsigned char *output)
{
	for (int i = 0; i < 32; i++)
	{
		output[i] = input[P_Table[i]];
	}
}
//PC����1
void PermutdChoice_1(unsigned char *input,unsigned char *output)
{
	for (int i = 0; i < 56; i++)
	{
		output[i] = input[PC_1[i]];
	}
}
//����
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
//ѭ������
void LeftShift(unsigned char *data, unsigned index)
{
		Reverse(data,0,index-1);
		Reverse(data, index, 27);
		Reverse(data, 0, 27);
}
//PC����2
void PermutdChoice_2(unsigned char *input, unsigned char *output)
{
	for (int i = 0; i < 48; i++)
	{
		output[i] = input[PC_2[i]];
	}
}
//���
void XOR(unsigned char *data1, unsigned char *data2, unsigned char *output,int length)
{
	for (int i = 0; i < length; i++)
	{
		output[i] = data1[i] ^ data2[i];
	}
}
//����16������Կ
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
//����
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
//����
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
//16�ֽ��ܺ���
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
//�ֽڸ���
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
