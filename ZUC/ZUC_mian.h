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
