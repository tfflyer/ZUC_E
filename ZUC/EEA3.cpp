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

#include"ZUC_mian.h"
#include<malloc.h>
#include<iostream>



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
		C[i] = M[i] ^ z[i];
	}

	free(z);
}

int main() {

}