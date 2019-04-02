/*********************************************************************************
  *Copyright(C),中国国家密码管理局
  *FileName:祖冲之序列密码算法的机密性算法
  *Author:TFflyer
  *Version:V1.0
  *Date:2019-03-28
  *Description: demo and without main()，主要完成消息序列的加密
  *Others: my email:myownflyer@foxmail.com
  *Function List:
	 1.
	 2.
  *History:
	 1.Date:2019-03-29
	   Author:TFflyer
	   Modification:重构了主算法的头文件，使得主算法可以被加密算法顺利调用
**********************************************************************************/

#include"ZUC_main.h"
#include<malloc.h>
#include<iostream>
#include<stdio.h>



typedef unsigned char u8; 
typedef unsigned int u32;

void ZUC(u8* k, u8* iv, u32* ks, int len) {
	Initialization(k, iv);
	GenerateKeystream(ks, len);
}
void EEA3(u8* CK, u32 COUNT, u32 BEARER, u32 DIRECTION, u32 LENGTH, u32* M, u32* C) {
	u32 *z, L, i;
	u8 IV[16];
	L = (LENGTH + 31) / 32;
	z = (u32 *)malloc(L * sizeof(u32));

	IV[0] = (COUNT >> 24) & 0xFF;
	IV[1] = (COUNT >> 16) & 0xFF;
	IV[2] = (COUNT >> 8) & 0xFF;
	IV[3] = COUNT & 0xFF;
	IV[4] = ((BEARER << 3) | ((DIRECTION & 1) << 2)) & 0xFC;
	IV[5] = 0;
	IV[6] = 0;
	IV[7] = 0;
	IV[8] = IV[0];
	IV[9] = IV[1];
	IV[10] = IV[2];
	IV[11] = IV[3];

	IV[12] = IV[4];
	IV[13] = IV[5];
	IV[14] = IV[6];
	IV[15] = IV[7];

	ZUC(CK, IV, z, L);
	for (i = 0; i < L; i++)
	{
		//printf("%X\n", z[i]);
		C[i] = M[i] ^ z[i];
	}

	free(z);
}

/*EEA3_Test1 :测试EEA3算法 :
 Key = (hex) 17 3d 14 ba 50 03 73 1d 7a 60 04 94 70 f0 0a 29
 Count =(hex)66035492
 Bearer = (hex) f
Direction = (hex) 0 
Direction = (bin) 0
Length = 193 bits
Plaintext:(hex) 6cf65340 735552ab 0c9752fa 6f9025fe 0bd675d9 005875b2 00000000
Ciphertext:
(hex) a6c85fc6 6afb8533 aafc2518 dfe78494 0ee1e4b0 30238cc8 00000000
*/

int main() {
	int i;
	printf("EE3A?\n");
	u8 CK[16] = {0x17,0x3d,0x14,0xba,0x50,0x03,0x73,0x1d,0x7a,0x60,0x04,0x94,0x70,0xf0,0x0a,0x29};
	u32 COUNT = 0x66035492;
	u32 BEARER = 0xf;
	u32 DIRECTION = 0x0;
	u32 LENGTH = 193;
	u32 M[] = {0x6cf65340,0x735552ab,0x0c9752fa,0x6f9025fe,0x0bd675d9,0x005875b2,0x00000000};
	u32 C_real[]= {0xa6c85fc6,0x6afb8533,0xaafc2518,0xdfe78494,0x0ee1e4b0,0x30238cc8,0x00000000};
	u32 C[8];
	u32 D[8];
	EEA3(CK, COUNT, BEARER, DIRECTION, LENGTH, M, C);
	printf("密文\n");
		for(i = 0; i < 6; i++) {
			printf("%08x，", C[i]);

	}
	printf("\n");

	EEA3(CK, COUNT, BEARER, DIRECTION, LENGTH, C, D);
	printf("明文\n");
	for (i = 0; i < 6; i++) {
		printf("%08x，", D[i]);

	}

}

