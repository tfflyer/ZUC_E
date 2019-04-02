/*********************************************************************************
  *Copyright(C),中国国家密码管理局
  *FileName:祖冲之序列密码算法_主算法
  *Author:TFflyer
  *Version:V1.0
  *Date:2019-03-28
  *Description: demo and without main()，主要完成密钥流的生成
  *Others: my email:myownflyer@foxmail.com
  *Function List:
	 1.模 2^31-1加法
	 2.线性反馈移位寄存器的初始化
	 3.线性反馈移位寄存器工作模式
	 4.比特重组
	 5.F—非线性函数变换
	 6.初始化
	 7.生成密钥流的主函数
  *History:
	 1.Date:2019-03-29
	   Author:TFflyer
	   Modification:重构了主算法的头文件，使得主算法可以被顺利调用
**********************************************************************************/
#pragma once
typedef unsigned char u8;
typedef unsigned int u32;
u32 AddM(u32 a, u32 b);
void LFSRWithInitialisationMode(u32 u);
void LFSRWithWorkMode();
void BitReorganization();
u32 F();
void Initialization(u8* k, u8* iv);
void GenerateKeystream(u32* pKeystream, int KeystreamLen);
