#include "DES.h"
#include<stdio.h>
#include <memory.h>
#include<string.h>
//加密文件
void EncyptFile(char * file1,char *file2,unsigned char *key)
{
	unsigned char keys[16][48] = { 0 };
	CaculateKey(key, keys);
	FILE * fp1, *fp2;
	fp1 = fopen(file1, "rb+");
	if (fp1 == NULL)
	{
		printf("open file %s failed!\n", file1);
		return;
	}
	fp2 = fopen(file2, "wb+");
	if (fp2 == NULL)
	{
		printf("open file %s failed!\n", file2);
		return;
	}
	unsigned char buffer[1024];
	unsigned char outbuffer[1024];
	long readnum = 0, writenum = 0;
	fseek(fp1, 0, SEEK_END);
	long length = ftell(fp1);
	fseek(fp1, 0, SEEK_SET);
	while (length != ftell(fp1))
	{
		readnum = fread(buffer, sizeof(unsigned char), 1024, fp1);
		unsigned char offset = readnum % 8;
		if (offset != 0)
		{
			memset(buffer + readnum, 0, 8 - offset);
			StreamEncypt(buffer, keys, outbuffer, 8 - offset + readnum);
			writenum = fwrite(outbuffer, sizeof(unsigned char), 8 - offset + readnum, fp2);
			break;
		}
		StreamEncypt(buffer, keys, outbuffer, readnum);
		writenum = fwrite(outbuffer, sizeof(unsigned char), readnum, fp2);
	}
	fclose(fp1);
	fclose(fp2);
}
//解密文件
void DecyptFile(char * file1, char *file2, unsigned char *key)
{
	unsigned char keys[16][48] = { 0 };
	CaculateKey(key, keys);
	FILE * fp1, *fp2;
	fp1 = fopen(file1, "rb+");
	if (fp1 == NULL)
	{
		printf("open file %s failed!\n", file1);
		return;
	}
	fp2 = fopen(file2, "wb+");
	if (fp2 == NULL)
	{
		printf("open file %s failed!\n", file2);
		return;
	}
	unsigned char buffer[1024];
	unsigned char outbuffer[1024];
	long readnum = 0,writenum=0;
	fseek(fp1, 0, SEEK_END);
	long length = ftell(fp1);
	fseek(fp1, 0, SEEK_SET);
	while (length != ftell(fp1))
	{
		readnum = fread(buffer, sizeof(unsigned char), 1024, fp1);
		StreamDecypt(buffer, keys, outbuffer, readnum);
		writenum = fwrite(outbuffer, sizeof(unsigned char), readnum, fp2);
	}
	fclose(fp1);
	fclose(fp2);
}
int main(int argc, char *argv[])
{
	unsigned char key[9] = { 0 };
	char file1[512] = { 0 };
	char file2[512] = { 0 };
	char file3[512] = { 0 };
	printf("输入密钥（8个字节）：\n");
	scanf("%s",key);
	if (strlen((const char *)key) != 8)
		printf("密钥长度必须为8个字节!\n");
	printf("输入明文文件路径：\n");
	scanf("%s",file1);
	printf("输入密文文件路径：：\n");
	scanf("%s", file2);
	printf("输入解密后文件路径：\n");
	scanf("%s", file3);
	EncyptFile(file1, file2, key);
	DecyptFile(file2, file3, key);
	return 0;
}