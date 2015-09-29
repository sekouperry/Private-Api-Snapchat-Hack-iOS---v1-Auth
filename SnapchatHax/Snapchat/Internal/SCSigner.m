//
//  SCSigner.m
//  SnapchatHax
//
//  Copyright (c) 2015 Alex Nichol. All rights reserved.
//

#import "SCSigner.h"
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>

@implementation SCSigner


static UInt8 pData[320] =
{
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xe3, 0xb0, 0xce, 0x37, 0xed, 0x76, 0x18, 0xa4, 0x15, 0xe3, 0xe6, 0x6e, 0x25, 0x8f, 0x8f, 0x76,
    0xcd, 0x64, 0x00, 0x5e, 0x83, 0x12, 0x3c, 0xdf, 0xcd, 0x2a, 0x33, 0x4c, 0x83, 0xdb, 0x20, 0x1e,
    0xd7, 0x13, 0xe7, 0x4e, 0x33, 0xfd, 0x46, 0x7e, 0xbf, 0x38, 0x49, 0xcb, 0x11, 0x8d, 0x46, 0xcd,
    0xa5, 0x71, 0x69, 0x3f, 0x20, 0xe4, 0x62, 0x46, 0x28, 0xd4, 0xbf, 0xfa, 0xad, 0x31, 0xb9, 0x01,
    0x46, 0x45, 0x64, 0xdb, 0xe0, 0x21, 0x12, 0x02, 0x7c, 0x9d, 0xb6, 0x22, 0x34, 0xde, 0x24, 0x65,
    0xf1, 0xa9, 0xe6, 0x4e, 0xe2, 0xd6, 0xb4, 0x1b, 0x63, 0xba, 0xcf, 0x3d, 0x43, 0x1c, 0x48, 0x52,
    0x8b, 0xfd, 0xcb, 0x0a, 0x66, 0x6b, 0x31, 0xb3, 0xa7, 0xa3, 0x5f, 0x40, 0xfa, 0xca, 0x44, 0x3b,
    0x30, 0x96, 0x98, 0x4c, 0xf1, 0xdc, 0x0a, 0x06, 0x85, 0x40, 0xec, 0x75, 0x8b, 0x61, 0x74, 0x5e,
    0x46, 0x96, 0xfd, 0x88, 0x1a, 0x14, 0x59, 0xce, 0x8c, 0xd4, 0x9f, 0xef, 0xd5, 0xfd, 0x34, 0xef,
    0x6b, 0xb4, 0x49, 0xd0, 0xbe, 0xff, 0xca, 0x89, 0x78, 0x98, 0x5e, 0x2d, 0x54, 0x8a, 0xb1, 0x74,
    0xae, 0xa3, 0x11, 0x12, 0x0c, 0xd1, 0xf1, 0xbf, 0x06, 0x03, 0x11, 0x74, 0xaa, 0x77, 0x31, 0x3f,
    0x5f, 0xe1, 0x21, 0x1a, 0x99, 0x8f, 0x0f, 0x66, 0xd2, 0x3a, 0xd9, 0xbb, 0x17, 0x5c, 0xfb, 0x73,
    0x5b, 0xcb, 0x79, 0x03, 0x40, 0x5e, 0xaf, 0x70, 0x82, 0x7a, 0x9b, 0xa4, 0xf3, 0x5e, 0x91, 0x2c,
    0xdf, 0xa5, 0x32, 0x42, 0x93, 0xb0, 0x7c, 0x6b, 0xad, 0xdf, 0x93, 0xe7, 0x59, 0x26, 0x17, 0xee,
    0xdd, 0xea, 0xd0, 0xb7, 0x0d, 0x55, 0xca, 0x9a, 0x68, 0x88, 0x40, 0xb2, 0x7e, 0x1c, 0x96, 0x96,
    0xde, 0x6d, 0x38, 0x49, 0x09, 0xd4, 0x86, 0x0e, 0xe1, 0x90, 0xd4, 0xa1, 0xf6, 0xe6, 0x39, 0x33,
    0x10, 0xda, 0xa1, 0x9d, 0x02, 0xac, 0x5d, 0xe2, 0xc5, 0x2d, 0xe5, 0xbb, 0x3f, 0xf6, 0x37, 0xee,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/*
static UInt8 byteFromAddress(void* base, UInt32 offset)
{
    void *adr = base + offset;
    return (UInt8)(adr);
};

static UInt32 dwordFromAddress(void* base, UInt32 offset)
{
    void *adr = base + offset;
    return (UInt32)(adr);
};
*/
 
static void encryptHash(UInt8* hash, const UInt8* privateData, const void* cryptData, UInt8* encryptedHash)
{
#ifdef __arm64
#define MyUInt32 UInt64
#else
#define MyUInt32 UInt32
#endif

    MyUInt32 R0, R1, R2, R3, R4, R5, R6, R8, R9, R10, R11, R12, LR;
    MyUInt32 temp1, temp2, temp3, temp4, temp5, temp6;
    
    R11 = (MyUInt32)(hash);
    R2 = (MyUInt32)(privateData);
    R12 = R2;
    
    R0 = ((UInt8*)((void*)R11))[5];                               // 0000: 	LDRB.W	R0, [R11,#5]
    R1 = (MyUInt32)(cryptData + 0x0000350C);                      // 0001: 	MOV	R1, #(CD_1024_0000350C - 2480346)
    // 0002: 	ADD	R1, PC
    R3 = *(UInt32*)(R1 + (R0 << 2));                            // 0003: 	LDR.W	R3, [R1,R0,LSL#2]
    R0 = ((UInt8*)((void*)R11))[4];                               // 0004: 	LDRB.W	R0, [R11,#4]
    R1 = (MyUInt32)(cryptData + 0x000081DC);                      // 0005: 	MOV	R1, #(CD_1024_000081DC - 2480374)
    R5 = *(UInt32*)(R2 + 20);                                   // 0006: 	LDR	R5, [R2,#20]
    R10 = *(UInt32*)(R2 + 24);                                  // 0007: 	LDR.W	R10, [R2,#24]
    R8 = *(UInt32*)(R2 + 28);                                   // 0008: 	LDR.W	R8, [R2,#28]
    // 0009: 	ADD	R1, PC
    R6 = *(UInt32*)(R1 + (R0 << 2));                            // 0010: 	LDR.W	R6, [R1,R0,LSL#2]
    R0 = *(UInt32*)(R2 + 16);                                   // 0011: 	LDR	R0, [R2,#16]
    R6 = R6 ^ R5;                                                 // 0012: 	EORS	R6, R5
    R3 = R3 ^ R6;                                                 // 0013: 	EORS	R3, R6
    R6 = ((UInt8*)((void*)R11))[6];                               // 0014: 	LDRB.W	R6, [R11,#6]
    R5 = (MyUInt32)(cryptData + 0x00002CF8);                      // 0015: 	MOV	R5, #(CD_1024_00002CF8 - 2480398)
    // 0016: 	ADD	R5, PC
    R6 = *(UInt32*)(R5 + (R6 << 2));                            // 0017: 	LDR.W	R6, [R5,R6,LSL#2]
    R3 = R3 ^ R6;                                                 // 0018: 	EORS	R3, R6
    R6 = ((UInt8*)((void*)R11))[7];                               // 0019: 	LDRB.W	R6, [R11,#7]
    R5 = (MyUInt32)(cryptData + 0x0000392C);                      // 0020: 	MOV	R5, #(CD_1024_0000392C - 2480418)
    // 0021: 	ADD	R5, PC
    R6 = *(UInt32*)(R5 + (R6 << 2));                            // 0022: 	LDR.W	R6, [R5,R6,LSL#2]
    R3 = R3 ^ R6;                                                 // 0023: 	EORS	R3, R6
    R6 = (R3 >> 8) & ((1 << 8) - 1);                              // 0024: 	UBFX.W	R6, R3, #8, #8
    R5 = (MyUInt32)(cryptData + 0x00010899);                      // 0025: 	MOV	R5, #(CD_1024_00010899 - 2480446)
    R4 = (MyUInt32)(cryptData + 0x00011499);                      // 0026: 	MOV	R4, #(CD_1024_00011499 - 2480454)
    // 0027: 	ADD	R5, PC
    R6 = *(UInt32*)(R5 + (R6 << 2));                            // 0028: 	LDR.W	R6, [R5,R6,LSL#2]
    R5 = R3 & 0x000000FF;                                         // 0029: 	UXTB	R5, R3
    // 0030: 	ADD	R4, PC
    R5 = *(UInt32*)(R4 + (R5 << 2));                            // 0031: 	LDR.W	R5, [R4,R5,LSL#2]
    R4 = *(UInt32*)(R2 + 36);                                   // 0032: 	LDR	R4, [R2,#36]
    R5 = R5 ^ R4;                                                 // 0033: 	EORS	R5, R4
    R6 = R6 ^ R5;                                                 // 0034: 	EORS	R6, R5
    R5 = (R3 >> 16) & ((1 << 8) - 1);                             // 0035: 	UBFX.W	R5, R3, #16, #8
    R4 = (MyUInt32)(cryptData + 0x000079DC);                      // 0036: 	MOV	R4, #(CD_1024_000079DC - 2480480)
    R3 = R3 >> 24;                                                // 0037: 	LSRS	R3, R3, #24
    // 0038: 	ADD	R4, PC
    R5 = *(UInt32*)(R4 + (R5 << 2));                            // 0039: 	LDR.W	R5, [R4,R5,LSL#2]
    R6 = R6 ^ R5;                                                 // 0040: 	EORS	R6, R5
    R5 = (MyUInt32)(cryptData + 0x00013535);                      // 0041: 	MOV	R5, #(CD_1024_00013535 - 2480496)
    // 0042: 	ADD	R5, PC
    R3 = *(UInt32*)(R5 + (R3 << 2));                            // 0043: 	LDR.W	R3, [R5,R3,LSL#2]
    R1 = R3 ^ R6;                                                 // 0044: 	EOR.W	R1, R3, R6
    R3 = R1 & 0x000000FF;                                         // 0045: 	UXTB	R3, R1
    R9 = R1;                                                      // 0046: 	MOV	R9, R1
    R1 = (MyUInt32)(cryptData + 0x0000BAA4);                      // 0047: 	MOV	R1, #(CD_1024_0000BAA4 - 2480534)
    R5 = ((UInt8*)((void*)R11))[1];                               // 0048: 	LDRB.W	R5, [R11,#1]
    R6 = ((UInt8*)((void*)R11))[0];                               // 0049: 	LDRB.W	R6, [R11]
    R4 = ((UInt8*)((void*)R11))[2];                               // 0050: 	LDRB.W	R4, [R11,#2]
    R2 = ((UInt8*)((void*)R11))[3];                               // 0051: 	LDRB.W	R2, [R11,#3]
    // 0052: 	ADD	R1, PC
    R3 = *(UInt32*)(R1 + (R3 << 2));                            // 0053: 	LDR.W	R3, [R1,R3,LSL#2]
    R1 = (MyUInt32)(cryptData + 0x00010C99);                      // 0054: 	MOV	R1, #(CD_1024_00010C99 - 2480548)
    // 0055: 	ADD	R1, PC
    R1 = *(UInt32*)(R1 + (R5 << 2));                            // 0056: 	LDR.W	R1, [R1,R5,LSL#2]
    R5 = (MyUInt32)(cryptData + 0x00004D38);                      // 0057: 	MOV	R5, #(CD_1024_00004D38 - 2480562)
    // 0058: 	ADD	R5, PC
    R5 = *(UInt32*)(R5 + (R6 << 2));                            // 0059: 	LDR.W	R5, [R5,R6,LSL#2]
    R0 = R0 ^ R5;                                                 // 0060: 	EORS	R0, R5
    R0 = R0 ^ R1;                                                 // 0061: 	EORS	R0, R1
    R1 = (MyUInt32)(cryptData + 0x00001884);                      // 0062: 	MOV	R1, #(CD_1024_00001884 - 2480580)
    // 0063: 	ADD	R1, PC
    R1 = *(UInt32*)(R1 + (R4 << 2));                            // 0064: 	LDR.W	R1, [R1,R4,LSL#2]
    R0 = R0 ^ R1;                                                 // 0065: 	EORS	R0, R1
    R1 = (MyUInt32)(cryptData + 0x0000F044);                      // 0066: 	MOV	R1, #(CD_1024_0000F044 - 2480596)
    // 0067: 	ADD	R1, PC
    R1 = *(UInt32*)(R1 + (R2 << 2));                            // 0068: 	LDR.W	R1, [R1,R2,LSL#2]
    R0 = R0 ^ R1;                                                 // 0069: 	EORS	R0, R1
    R1 = (R0 >> 8) & ((1 << 8) - 1);                              // 0070: 	UBFX.W	R1, R0, #8, #8
    R2 = (MyUInt32)(cryptData + 0x00012D2C);                      // 0071: 	MOV	R2, #(CD_1024_00012D2C - 2480624)
    R4 = (MyUInt32)(cryptData + 0x00009248);                      // 0072: 	MOV	R4, #(CD_1024_00009248 - 2480632)
    // 0073: 	ADD	R2, PC
    R1 = *(UInt32*)(R2 + (R1 << 2));                            // 0074: 	LDR.W	R1, [R2,R1,LSL#2]
    R2 = R0 & 0x000000FF;                                         // 0075: 	UXTB	R2, R0
    // 0076: 	ADD	R4, PC
    R2 = *(UInt32*)(R4 + (R2 << 2));                            // 0077: 	LDR.W	R2, [R4,R2,LSL#2]
    R4 = *(UInt32*)(R12 + 32);                                  // 0078: 	LDR.W	R4, [R12,#32]
    R2 = R2 ^ R4;                                                 // 0079: 	EORS	R2, R4
    R1 = R1 ^ R2;                                                 // 0080: 	EORS	R1, R2
    R2 = (R0 >> 16) & ((1 << 8) - 1);                             // 0081: 	UBFX.W	R2, R0, #16, #8
    R4 = (MyUInt32)(cryptData + 0x00009A48);                      // 0082: 	MOV	R4, #(CD_1024_00009A48 - 2480660)
    R0 = R0 >> 24;                                                // 0083: 	LSRS	R0, R0, #24
    // 0084: 	ADD	R4, PC
    R2 = *(UInt32*)(R4 + (R2 << 2));                            // 0085: 	LDR.W	R2, [R4,R2,LSL#2]
    R1 = R1 ^ R2;                                                 // 0086: 	EORS	R1, R2
    R2 = (MyUInt32)(cryptData + 0x00010448);                      // 0087: 	MOV	R2, #(CD_1024_00010448 - 2480676)
    // 0088: 	ADD	R2, PC
    R0 = *(UInt32*)(R2 + (R0 << 2));                            // 0089: 	LDR.W	R0, [R2,R0,LSL#2]
    LR = R0 ^ R1;                                                 // 0090: 	EOR.W	LR, R0, R1
    R1 = (MyUInt32)(cryptData + 0x0000D01C);                      // 0091: 	MOV	R1, #(CD_1024_0000D01C - 2480698)
    R0 = LR >> 24;                                                // 0092: 	MOV.W	R0, LR,LSR#24
    // 0093: 	ADD	R1, PC
    R0 = *(UInt32*)(R1 + (R0 << 2));                            // 0094: 	LDR.W	R0, [R1,R0,LSL#2]
    R1 = *(UInt32*)(R12 + 52);                                  // 0095: 	LDR.W	R1, [R12,#52]
    R0 = R0 ^ R1;                                                 // 0096: 	EORS	R0, R1
    R3 = R3 ^ R0;                                                 // 0097: 	EORS	R3, R0
    R0 = ((UInt8*)((void*)R11))[9];                               // 0098: 	LDRB.W	R0, [R11,#9]
    R1 = (MyUInt32)(cryptData + 0x00014DF4);                      // 0099: 	MOV	R1, #(CD_1024_00014DF4 - 2480724)
    // 0100: 	ADD	R1, PC
    R0 = *(UInt32*)(R1 + (R0 << 2));                            // 0101: 	LDR.W	R0, [R1,R0,LSL#2]
    R1 = ((UInt8*)((void*)R11))[8];                               // 0102: 	LDRB.W	R1, [R11,#8]
    R2 = (MyUInt32)(cryptData + 0x0000C7EC);                      // 0103: 	MOV	R2, #(CD_1024_0000C7EC - 2480742)
    // 0104: 	ADD	R2, PC
    R1 = *(UInt32*)(R2 + (R1 << 2));                            // 0105: 	LDR.W	R1, [R2,R1,LSL#2]
    R1 = R1 ^ R10;                                                // 0106: 	EOR.W	R1, R1, R10
    R0 = R0 ^ R1;                                                 // 0107: 	EORS	R0, R1
    R1 = ((UInt8*)((void*)R11))[10];                              // 0108: 	LDRB.W	R1, [R11,#10]
    R2 = (MyUInt32)(cryptData + 0x000120D8);                      // 0109: 	MOV	R2, #(CD_1024_000120D8 - 2480766)
    // 0110: 	ADD	R2, PC
    R1 = *(UInt32*)(R2 + (R1 << 2));                            // 0111: 	LDR.W	R1, [R2,R1,LSL#2]
    R0 = R0 ^ R1;                                                 // 0112: 	EORS	R0, R1
    R1 = ((UInt8*)((void*)R11))[11];                              // 0113: 	LDRB.W	R1, [R11,#11]
    R2 = (MyUInt32)(cryptData + 0x00000424);                      // 0114: 	MOV	R2, #(CD_1024_00000424 - 2480786)
    // 0115: 	ADD	R2, PC
    R1 = *(UInt32*)(R2 + (R1 << 2));                            // 0116: 	LDR.W	R1, [R2,R1,LSL#2]
    R0 = R0 ^ R1;                                                 // 0117: 	EORS	R0, R1
    R1 = (R0 >> 8) & ((1 << 8) - 1);                              // 0118: 	UBFX.W	R1, R0, #8, #8
    R2 = (MyUInt32)(cryptData + 0x0000310C);                      // 0119: 	MOV	R2, #(CD_1024_0000310C - 2480814)
    R6 = (MyUInt32)(cryptData + 0x000141E0);                      // 0120: 	MOV	R6, #(CD_1024_000141E0 - 2480822)
    // 0121: 	ADD	R2, PC
    R1 = *(UInt32*)(R2 + (R1 << 2));                            // 0122: 	LDR.W	R1, [R2,R1,LSL#2]
    R2 = R0 & 0x000000FF;                                         // 0123: 	UXTB	R2, R0
    // 0124: 	ADD	R6, PC
    R2 = *(UInt32*)(R6 + (R2 << 2));                            // 0125: 	LDR.W	R2, [R6,R2,LSL#2]
    R6 = *(UInt32*)(R12 + 40);                                  // 0126: 	LDR.W	R6, [R12,#40]
    R2 = R2 ^ R6;                                                 // 0127: 	EORS	R2, R6
    R1 = R1 ^ R2;                                                 // 0128: 	EORS	R1, R2
    R2 = (R0 >> 16) & ((1 << 8) - 1);                             // 0129: 	UBFX.W	R2, R0, #16, #8
    R6 = (MyUInt32)(cryptData + 0x00006DA0);                      // 0130: 	MOV	R6, #(CD_1024_00006DA0 - 2480850)
    R0 = R0 >> 24;                                                // 0131: 	LSRS	R0, R0, #24
    // 0132: 	ADD	R6, PC
    R2 = *(UInt32*)(R6 + (R2 << 2));                            // 0133: 	LDR.W	R2, [R6,R2,LSL#2]
    R1 = R1 ^ R2;                                                 // 0134: 	EORS	R1, R2
    R2 = (MyUInt32)(cryptData + 0x00003D38);                      // 0135: 	MOV	R2, #(CD_1024_00003D38 - 2480866)
    // 0136: 	ADD	R2, PC
    R0 = *(UInt32*)(R2 + (R0 << 2));                            // 0137: 	LDR.W	R0, [R2,R0,LSL#2]
    R4 = R0 ^ R1;                                                 // 0138: 	EOR.W	R4, R0, R1
    R1 = (R4 >> 8) & ((1 << 8) - 1);                              // 0139: 	UBFX.W	R1, R4, #8, #8
    R0 = (MyUInt32)(cryptData + 0x00013135);                      // 0140: 	MOV	R0, #(CD_1024_00013135 - 2480892)
    R2 = ((UInt8*)((void*)R11))[13];                              // 0141: 	LDRB.W	R2, [R11,#13]
    // 0142: 	ADD	R0, PC
    R1 = *(UInt32*)(R0 + (R1 << 2));                            // 0143: 	LDR.W	R1, [R0,R1,LSL#2]
    R1 = R1 ^ R3;                                                 // 0144: 	EORS	R1, R3
    R3 = (MyUInt32)(cryptData + 0x00004538);                      // 0145: 	MOV	R3, #(CD_1024_00004538 - 2480908)
    // 0146: 	ADD	R3, PC
    R2 = *(UInt32*)(R3 + (R2 << 2));                            // 0147: 	LDR.W	R2, [R3,R2,LSL#2]
    R3 = ((UInt8*)((void*)R11))[12];                              // 0148: 	LDRB.W	R3, [R11,#12]
    R6 = (MyUInt32)(cryptData + 0x00012504);                      // 0149: 	MOV	R6, #(CD_1024_00012504 - 2480926)
    // 0150: 	ADD	R6, PC
    R3 = *(UInt32*)(R6 + (R3 << 2));                            // 0151: 	LDR.W	R3, [R6,R3,LSL#2]
    R3 = R3 ^ R8;                                                 // 0152: 	EOR.W	R3, R3, R8
    R2 = R2 ^ R3;                                                 // 0153: 	EORS	R2, R3
    R3 = ((UInt8*)((void*)R11))[14];                              // 0154: 	LDRB.W	R3, [R11,#14]
    R6 = (MyUInt32)(cryptData + 0x00005140);                      // 0155: 	MOV	R6, #(CD_1024_00005140 - 2480950)
    // 0156: 	ADD	R6, PC
    R3 = *(UInt32*)(R6 + (R3 << 2));                            // 0157: 	LDR.W	R3, [R6,R3,LSL#2]
    R2 = R2 ^ R3;                                                 // 0158: 	EORS	R2, R3
    R3 = ((UInt8*)((void*)R11))[15];                              // 0159: 	LDRB.W	R3, [R11,#15]
    R6 = (MyUInt32)(cryptData + 0x00009648);                      // 0160: 	MOV	R6, #(CD_1024_00009648 - 2480970)
    // 0161: 	ADD	R6, PC
    R3 = *(UInt32*)(R6 + (R3 << 2));                            // 0162: 	LDR.W	R3, [R6,R3,LSL#2]
    R2 = R2 ^ R3;                                                 // 0163: 	EORS	R2, R3
    R3 = (R2 >> 8) & ((1 << 8) - 1);                              // 0164: 	UBFX.W	R3, R2, #8, #8
    R6 = (MyUInt32)(cryptData + 0x00004138);                      // 0165: 	MOV	R6, #(CD_1024_00004138 - 2480998)
    R5 = (MyUInt32)(cryptData + 0x00006568);                      // 0166: 	MOV	R5, #(CD_1024_00006568 - 2481006)
    // 0167: 	ADD	R6, PC
    R3 = *(UInt32*)(R6 + (R3 << 2));                            // 0168: 	LDR.W	R3, [R6,R3,LSL#2]
    R6 = R2 & 0x000000FF;                                         // 0169: 	UXTB	R6, R2
    // 0170: 	ADD	R5, PC
    R6 = *(UInt32*)(R5 + (R6 << 2));                            // 0171: 	LDR.W	R6, [R5,R6,LSL#2]
    R5 = *(UInt32*)(R12 + 44);                                  // 0172: 	LDR.W	R5, [R12,#44]
    R6 = R6 ^ R5;                                                 // 0173: 	EORS	R6, R5
    R3 = R3 ^ R6;                                                 // 0174: 	EORS	R3, R6
    R6 = (R2 >> 16) & ((1 << 8) - 1);                             // 0175: 	UBFX.W	R6, R2, #16, #8
    R5 = (MyUInt32)(cryptData + 0x000151F4);                      // 0176: 	MOV	R5, #(CD_1024_000151F4 - 2481034)
    R2 = R2 >> 24;                                                // 0177: 	LSRS	R2, R2, #24
    // 0178: 	ADD	R5, PC
    R6 = *(UInt32*)(R5 + (R6 << 2));                            // 0179: 	LDR.W	R6, [R5,R6,LSL#2]
    R3 = R3 ^ R6;                                                 // 0180: 	EORS	R3, R6
    R6 = (MyUInt32)(cryptData + 0x00015604);                      // 0181: 	MOV	R6, #(CD_1024_00015604 - 2481050)
    // 0182: 	ADD	R6, PC
    R2 = *(UInt32*)(R6 + (R2 << 2));                            // 0183: 	LDR.W	R2, [R6,R2,LSL#2]
    R11 = R2 ^ R3;                                                // 0184: 	EOR.W	R11, R2, R3
    R2 = LR;                                                      // 0185: 	MOV	R2, LR
    R3 = (R11 >> 16) & ((1 << 8) - 1);                            // 0186: 	UBFX.W	R3, R11, #16, #8
    R0 = (MyUInt32)(cryptData + 0x0000FC48);                      // 0187: 	MOV	R0, #(CD_1024_0000FC48 - 2481076)
    R5 = R2 & 0x000000FF;                                         // 0188: 	UXTB	R5, R2
    // 0189: 	ADD	R0, PC
    R3 = *(UInt32*)(R0 + (R3 << 2));                            // 0190: 	LDR.W	R3, [R0,R3,LSL#2]
    R0 = R3 ^ R1;                                                 // 0191: 	EOR.W	R0, R3, R1
    temp1 = R0;                                                   // 0192: 	STR	R0, [SP,#960+temp1]
    R1 = R0 & 0x000000FF;                                         // 0193: 	UXTB	R1, R0
    R0 = (MyUInt32)(cryptData + 0x00000834);                      // 0194: 	MOV	R0, #(CD_1024_00000834 - 2481102)
    R3 = (R9 >> 8) & ((1 << 8) - 1);                              // 0195: 	UBFX.W	R3, R9, #8, #8
    // 0196: 	ADD	R0, PC
    R1 = *(UInt32*)(R0 + (R1 << 2));                            // 0197: 	LDR.W	R1, [R0,R1,LSL#2]
    R0 = (MyUInt32)(cryptData + 0x000075D8);                      // 0198: 	MOV	R0, #(CD_1024_000075D8 - 2481116)
    // 0199: 	ADD	R0, PC
    R3 = *(UInt32*)(R0 + (R3 << 2));                            // 0200: 	LDR.W	R3, [R0,R3,LSL#2]
    R0 = (MyUInt32)(cryptData + 0x0000EC44);                      // 0201: 	MOV	R0, #(CD_1024_0000EC44 - 2481134)
    R6 = *(UInt32*)(R12 + 48);                                  // 0202: 	LDR.W	R6, [R12,#48]
    // 0203: 	ADD	R0, PC
    R5 = *(UInt32*)(R0 + (R5 << 2));                            // 0204: 	LDR.W	R5, [R0,R5,LSL#2]
    R6 = R6 ^ R5;                                                 // 0205: 	EORS	R6, R5
    R3 = R3 ^ R6;                                                 // 0206: 	EORS	R3, R6
    R6 = (R4 >> 16) & ((1 << 8) - 1);                             // 0207: 	UBFX.W	R6, R4, #16, #8
    R0 = (MyUInt32)(cryptData + 0x00005540);                      // 0208: 	MOV	R0, #(CD_1024_00005540 - 2481156)
    // 0209: 	ADD	R0, PC
    R6 = *(UInt32*)(R0 + (R6 << 2));                            // 0210: 	LDR.W	R6, [R0,R6,LSL#2]
    R0 = (MyUInt32)(cryptData + 0x00005D40);                      // 0211: 	MOV	R0, #(CD_1024_00005D40 - 2481170)
    // 0212: 	ADD	R0, PC
    R3 = R3 ^ R6;                                                 // 0213: 	EORS	R3, R6
    R6 = R11 >> 24;                                               // 0214: 	MOV.W	R6, R11,LSR#24
    R6 = *(UInt32*)(R0 + (R6 << 2));                            // 0215: 	LDR.W	R6, [R0,R6,LSL#2]
    R0 = R6 ^ R3;                                                 // 0216: 	EOR.W	R0, R6, R3
    temp2 = R0;                                                   // 0217: 	STR	R0, [SP,#960+temp2]
    R3 = R0 >> 24;                                                // 0218: 	LSRS	R3, R0, #24
    R0 = (MyUInt32)(cryptData + 0x0000A258);                      // 0219: 	MOV	R0, #(CD_1024_0000A258 - 2481202)
    R5 = *(UInt32*)(R12 + 68);                                  // 0220: 	LDR.W	R5, [R12,#68]
    // 0221: 	ADD	R0, PC
    R3 = *(UInt32*)(R0 + (R3 << 2));                            // 0222: 	LDR.W	R3, [R0,R3,LSL#2]
    R0 = (MyUInt32)(cryptData + 0x000028F8);                      // 0223: 	MOV	R0, #(CD_1024_000028F8 - 2481216)
    // 0224: 	ADD	R0, PC
    R10 = R0;                                                     // 0225: 	MOV	R10, R0
    R3 = R3 ^ R5;                                                 // 0226: 	EORS	R3, R5
    R5 = (R2 >> 16) & ((1 << 8) - 1);                             // 0227: 	UBFX.W	R5, R2, #16, #8
    LR = R1 ^ R3;                                                 // 0228: 	EOR.W	LR, R1, R3
    R1 = R9 >> 24;                                                // 0229: 	MOV.W	R1, R9,LSR#24
    R3 = R9;                                                      // 0230: 	MOV	R3, R9
    R1 = *(UInt32*)(R0 + (R1 << 2));                            // 0231: 	LDR.W	R1, [R0,R1,LSL#2]
    R0 = (MyUInt32)(cryptData + 0x000149EC);                      // 0232: 	MOV	R0, #(CD_1024_000149EC - 2481252)
    R6 = *(UInt32*)(R12 + 56);                                  // 0233: 	LDR.W	R6, [R12,#56]
    // 0234: 	ADD	R0, PC
    R5 = *(UInt32*)(R0 + (R5 << 2));                            // 0235: 	LDR.W	R5, [R0,R5,LSL#2]
    R0 = (MyUInt32)(cryptData + 0x000071B0);                      // 0236: 	MOV	R0, #(CD_1024_000071B0 - 2481266)
    // 0237: 	ADD	R0, PC
    R5 = R5 ^ R6;                                                 // 0238: 	EORS	R5, R6
    R1 = R1 ^ R5;                                                 // 0239: 	EORS	R1, R5
    R5 = R4 & 0x000000FF;                                         // 0240: 	UXTB	R5, R4
    R5 = *(UInt32*)(R0 + (R5 << 2));                            // 0241: 	LDR.W	R5, [R0,R5,LSL#2]
    R1 = R1 ^ R5;                                                 // 0242: 	EORS	R1, R5
    R5 = (R11 >> 8) & ((1 << 8) - 1);                             // 0243: 	UBFX.W	R5, R11, #8, #8
    R0 = (MyUInt32)(cryptData + 0x00005940);                      // 0244: 	MOV	R0, #(CD_1024_00005940 - 2481292)
    // 0245: 	ADD	R0, PC
    R5 = *(UInt32*)(R0 + (R5 << 2));                            // 0246: 	LDR.W	R5, [R0,R5,LSL#2]
    R0 = R5 ^ R1;                                                 // 0247: 	EOR.W	R0, R5, R1
    R5 = (R0 >> 8) & ((1 << 8) - 1);                              // 0248: 	UBFX.W	R5, R0, #8, #8
    R8 = R0;                                                      // 0249: 	MOV	R8, R0
    R0 = (MyUInt32)(cryptData + 0x0000E030);                      // 0250: 	MOV	R0, #(CD_1024_0000E030 - 2481324)
    R3 = (R3 >> 16) & ((1 << 8) - 1);                             // 0251: 	UBFX.W	R3, R3, #16, #8
    R6 = (MyUInt32)(cryptData + 0x00015E08);                      // 0252: 	MOV	R6, #(CD_1024_00015E08 - 2481336)
    // 0253: 	ADD	R0, PC
    R5 = *(UInt32*)(R0 + (R5 << 2));                            // 0254: 	LDR.W	R5, [R0,R5,LSL#2]
    R9 = R0;                                                      // 0255: 	MOV	R9, R0
    // 0256: 	ADD	R6, PC
    R3 = *(UInt32*)(R6 + (R3 << 2));                            // 0257: 	LDR.W	R3, [R6,R3,LSL#2]
    R0 = R5 ^ LR;                                                 // 0258: 	EOR.W	R0, R5, LR
    R5 = (R2 >> 8) & ((1 << 8) - 1);                              // 0259: 	UBFX.W	R5, R2, #8, #8
    R1 = (MyUInt32)(cryptData + 0x0000CC1C);                      // 0260: 	MOV	R1, #(CD_1024_0000CC1C - 2481366)
    R2 = R11 & 0x000000FF;                                        // 0261: 	UXTB.W	R2, R11
    R6 = *(UInt32*)(R12 + 60);                                  // 0262: 	LDR.W	R6, [R12,#60]
    // 0263: 	ADD	R1, PC
    R5 = *(UInt32*)(R1 + (R5 << 2));                            // 0264: 	LDR.W	R5, [R1,R5,LSL#2]
    R1 = (MyUInt32)(cryptData + 0x00000C34);                      // 0265: 	MOV	R1, #(CD_1024_00000C34 - 2481380)
    // 0266: 	ADD	R1, PC
    R6 = R6 ^ R5;                                                 // 0267: 	EORS	R6, R5
    R3 = R3 ^ R6;                                                 // 0268: 	EORS	R3, R6
    R6 = R4 >> 24;                                                // 0269: 	LSRS	R6, R4, #24
    R4 = (MyUInt32)(cryptData + 0x0000C3E0);                      // 0270: 	MOV	R4, #(CD_1024_0000C3E0 - 2481400)
    R6 = *(UInt32*)(R1 + (R6 << 2));                            // 0271: 	LDR.W	R6, [R1,R6,LSL#2]
    // 0272: 	ADD	R4, PC
    R2 = *(UInt32*)(R4 + (R2 << 2));                            // 0273: 	LDR.W	R2, [R4,R2,LSL#2]
    R3 = R3 ^ R6;                                                 // 0274: 	EORS	R3, R6
    R11 = R2 ^ R3;                                                // 0275: 	EOR.W	R11, R2, R3
    R2 = (R11 >> 16) & ((1 << 8) - 1);                            // 0276: 	UBFX.W	R2, R11, #16, #8
    R6 = (MyUInt32)(cryptData + 0x0000E844);                      // 0277: 	MOV	R6, #(CD_1024_0000E844 - 2481424)
    // 0278: 	ADD	R6, PC
    R2 = *(UInt32*)(R6 + (R2 << 2));                            // 0279: 	LDR.W	R2, [R6,R2,LSL#2]
    R4 = R6;                                                      // 0280: 	MOV	R4, R6
    R0 = R0 ^ R2;                                                 // 0281: 	EORS	R0, R2
    temp3 = R0;                                                   // 0282: 	STR	R0, [SP,#960+temp3]
    R2 = (MyUInt32)(cryptData + 0x0000BAA4);                      // 0283: 	MOV	R2, #(CD_1024_0000BAA4 - 2481448)
    R0 = R0 & 0x000000FF;                                         // 0284: 	UXTB	R0, R0
    R1 = temp1;                                                   // 0285: 	LDR	R1, [SP,#960+temp1]
    // 0286: 	ADD	R2, PC
    R0 = *(UInt32*)(R2 + (R0 << 2));                            // 0287: 	LDR.W	R0, [R2,R0,LSL#2]
    R2 = (R1 >> 8) & ((1 << 8) - 1);                              // 0288: 	UBFX.W	R2, R1, #8, #8
    R2 = *(UInt32*)(R9 + (R2 << 2));                            // 0289: 	LDR.W	R2, [R9,R2,LSL#2]
    R9 = temp2;                                                   // 0290: 	LDR.W	R9, [SP,#960+temp2]
    LR = (MyUInt32)(cryptData + 0x00000834);                      // 0291: 	MOV	LR, #(CD_1024_00000834 - 2481478)
    R5 = *(UInt32*)(R12 + 64);                                  // 0292: 	LDR.W	R5, [R12,#64]
    // 0293: 	ADD	LR, PC
    R6 = R9 & 0x000000FF;                                         // 0294: 	UXTB.W	R6, R9
    R6 = *(UInt32*)(LR + (R6 << 2));                            // 0295: 	LDR.W	R6, [LR,R6,LSL#2]
    R6 = R6 ^ R5;                                                 // 0296: 	EORS	R6, R5
    R2 = R2 ^ R6;                                                 // 0297: 	EORS	R2, R6
    R6 = (R8 >> 16) & ((1 << 8) - 1);                             // 0298: 	UBFX.W	R6, R8, #16, #8
    R3 = (MyUInt32)(cryptData + 0x00005540);                      // 0299: 	MOV	R3, #(CD_1024_00005540 - 2481504)
    // 0300: 	ADD	R3, PC
    R6 = *(UInt32*)(R3 + (R6 << 2));                            // 0301: 	LDR.W	R6, [R3,R6,LSL#2]
    R3 = (MyUInt32)(cryptData + 0x00005D40);                      // 0302: 	MOV	R3, #(CD_1024_00005D40 - 2481518)
    // 0303: 	ADD	R3, PC
    R2 = R2 ^ R6;                                                 // 0304: 	EORS	R2, R6
    R6 = R11 >> 24;                                               // 0305: 	MOV.W	R6, R11,LSR#24
    R6 = *(UInt32*)(R3 + (R6 << 2));                            // 0306: 	LDR.W	R6, [R3,R6,LSL#2]
    R2 = R2 ^ R6;                                                 // 0307: 	EORS	R2, R6
    temp4 = R2;                                                   // 0308: 	STR	R2, [SP,#960+temp4]
    R6 = R2 >> 24;                                                // 0309: 	LSRS	R6, R2, #24
    R2 = (MyUInt32)(cryptData + 0x0000A258);                      // 0310: 	MOV	R2, #(CD_1024_0000A258 - 2481548)
    R5 = *(UInt32*)(R12 + 84);                                  // 0311: 	LDR.W	R5, [R12,#84]
    // 0312: 	ADD	R2, PC
    R6 = *(UInt32*)(R2 + (R6 << 2));                            // 0313: 	LDR.W	R6, [R2,R6,LSL#2]
    R2 = R9;                                                      // 0314: 	MOV	R2, R9
    R6 = R6 ^ R5;                                                 // 0315: 	EORS	R6, R5
    R5 = (R2 >> 16) & ((1 << 8) - 1);                             // 0316: 	UBFX.W	R5, R2, #16, #8
    R6 = R6 ^ R0;                                                 // 0317: 	EORS	R6, R0
    R0 = R1 >> 24;                                                // 0318: 	LSRS	R0, R1, #24
    R5 = *(UInt32*)(R4 + (R5 << 2));                            // 0319: 	LDR.W	R5, [R4,R5,LSL#2]
    R4 = *(UInt32*)(R12 + 72);                                  // 0320: 	LDR.W	R4, [R12,#72]
    R0 = *(UInt32*)(R10 + (R0 << 2));                           // 0321: 	LDR.W	R0, [R10,R0,LSL#2]
    R10 = (MyUInt32)(cryptData + 0x000071B0);                     // 0322: 	MOV	R10, #(CD_1024_000071B0 - 2481586)
    // 0323: 	ADD	R10, PC
    R5 = R5 ^ R4;                                                 // 0324: 	EORS	R5, R4
    R4 = R0 ^ R5;                                                 // 0325: 	EOR.W	R4, R0, R5
    R0 = R8;                                                      // 0326: 	MOV	R0, R8
    R5 = R0 & 0x000000FF;                                         // 0327: 	UXTB	R5, R0
    R5 = *(UInt32*)(R10 + (R5 << 2));                           // 0328: 	LDR.W	R5, [R10,R5,LSL#2]
    R4 = R4 ^ R5;                                                 // 0329: 	EORS	R4, R5
    R5 = (R11 >> 8) & ((1 << 8) - 1);                             // 0330: 	UBFX.W	R5, R11, #8, #8
    R8 = (MyUInt32)(cryptData + 0x0000E030);                      // 0331: 	MOV	R8, #(CD_1024_0000E030 - 2481616)
    // 0332: 	ADD	R8, PC
    R5 = *(UInt32*)(R8 + (R5 << 2));                            // 0333: 	LDR.W	R5, [R8,R5,LSL#2]
    R5 = R5 ^ R4;                                                 // 0334: 	EORS	R5, R4
    temp5 = R5;                                                   // 0335: 	STR	R5, [SP,#960+temp5]
    R5 = (R5 >> 8) & ((1 << 8) - 1);                              // 0336: 	UBFX.W	R5, R5, #8, #8
    R4 = (MyUInt32)(cryptData + 0x00013135);                      // 0337: 	MOV	R4, #(CD_1024_00013135 - 2481638)
    // 0338: 	ADD	R4, PC
    R5 = *(UInt32*)(R4 + (R5 << 2));                            // 0339: 	LDR.W	R5, [R4,R5,LSL#2]
    R9 = R5 ^ R6;                                                 // 0340: 	EOR.W	R9, R5, R6
    R5 = (R1 >> 16) & ((1 << 8) - 1);                             // 0341: 	UBFX.W	R5, R1, #16, #8
    R1 = (MyUInt32)(cryptData + 0x00005540);                      // 0342: 	MOV	R1, #(CD_1024_00005540 - 2481668)
    R4 = (R2 >> 8) & ((1 << 8) - 1);                              // 0343: 	UBFX.W	R4, R2, #8, #8
    R6 = *(UInt32*)(R12 + 76);                                  // 0344: 	LDR.W	R6, [R12,#76]
    // 0345: 	ADD	R1, PC
    R4 = *(UInt32*)(R8 + (R4 << 2));                            // 0346: 	LDR.W	R4, [R8,R4,LSL#2]
    R5 = *(UInt32*)(R1 + (R5 << 2));                            // 0347: 	LDR.W	R5, [R1,R5,LSL#2]
    R1 = R0 >> 24;                                                // 0348: 	LSRS	R1, R0, #24
    R1 = *(UInt32*)(R3 + (R1 << 2));                            // 0349: 	LDR.W	R1, [R3,R1,LSL#2]
    R3 = R11 & 0x000000FF;                                        // 0350: 	UXTB.W	R3, R11
    R3 = *(UInt32*)(LR + (R3 << 2));                            // 0351: 	LDR.W	R3, [LR,R3,LSL#2]
    R6 = R6 ^ R4;                                                 // 0352: 	EORS	R6, R4
    R6 = R6 ^ R5;                                                 // 0353: 	EORS	R6, R5
    R1 = R1 ^ R6;                                                 // 0354: 	EORS	R1, R6
    LR = R3 ^ R1;                                                 // 0355: 	EOR.W	LR, R3, R1
    R1 = (LR >> 16) & ((1 << 8) - 1);                             // 0356: 	UBFX.W	R1, LR, #16, #8
    R6 = (MyUInt32)(cryptData + 0x0000FC48);                      // 0357: 	MOV	R6, #(CD_1024_0000FC48 - 2481714)
    // 0358: 	ADD	R6, PC
    R1 = *(UInt32*)(R6 + (R1 << 2));                            // 0359: 	LDR.W	R1, [R6,R1,LSL#2]
    R0 = R1 ^ R9;                                                 // 0360: 	EOR.W	R0, R1, R9
    R1 = R0 & 0x000000FF;                                         // 0361: 	UXTB	R1, R0
    temp1 = R0;                                                   // 0362: 	STR	R0, [SP,#960+temp1]
    R1 = *(UInt32*)(R10 + (R1 << 2));                           // 0363: 	LDR.W	R1, [R10,R1,LSL#2]
    R10 = temp3;                                                  // 0364: 	LDR.W	R10, [SP,#960+temp3]
    R6 = (R10 >> 8) & ((1 << 8) - 1);                             // 0365: 	UBFX.W	R6, R10, #8, #8
    R9 = (MyUInt32)(cryptData + 0x000075D8);                      // 0366: 	MOV	R9, #(CD_1024_000075D8 - 2481758)
    R3 = temp4;                                                   // 0367: 	LDR	R3, [SP,#960+temp4]
    R8 = (MyUInt32)(cryptData + 0x0000BAA4);                      // 0368: 	MOV	R8, #(CD_1024_0000BAA4 - 2481768)
    // 0369: 	ADD	R9, PC
    R4 = *(UInt32*)(R12 + 80);                                  // 0370: 	LDR.W	R4, [R12,#80]
    R11 = temp5;                                                  // 0371: 	LDR.W	R11, [SP,#960+temp5]
    // 0372: 	ADD	R8, PC
    R6 = *(UInt32*)(R9 + (R6 << 2));                            // 0373: 	LDR.W	R6, [R9,R6,LSL#2]
    R5 = R3 & 0x000000FF;                                         // 0374: 	UXTB	R5, R3
    R5 = *(UInt32*)(R8 + (R5 << 2));                            // 0375: 	LDR.W	R5, [R8,R5,LSL#2]
    R5 = R5 ^ R4;                                                 // 0376: 	EORS	R5, R4
    R6 = R6 ^ R5;                                                 // 0377: 	EORS	R6, R5
    R5 = (R11 >> 16) & ((1 << 8) - 1);                            // 0378: 	UBFX.W	R5, R11, #16, #8
    R0 = (MyUInt32)(cryptData + 0x00005540);                      // 0379: 	MOV	R0, #(CD_1024_00005540 - 2481800)
    R4 = (MyUInt32)(cryptData + 0x0000D01C);                      // 0380: 	MOV	R4, #(CD_1024_0000D01C - 2481810)
    // 0381: 	ADD	R0, PC
    R5 = *(UInt32*)(R0 + (R5 << 2));                            // 0382: 	LDR.W	R5, [R0,R5,LSL#2]
    // 0383: 	ADD	R4, PC
    R6 = R6 ^ R5;                                                 // 0384: 	EORS	R6, R5
    R5 = LR >> 24;                                                // 0385: 	MOV.W	R5, LR,LSR#24
    R5 = *(UInt32*)(R4 + (R5 << 2));                            // 0386: 	LDR.W	R5, [R4,R5,LSL#2]
    R2 = R5 ^ R6;                                                 // 0387: 	EOR.W	R2, R5, R6
    temp2 = R2;                                                   // 0388: 	STR	R2, [SP,#960+temp2]
    R6 = (MyUInt32)(cryptData + 0x00000C34);                      // 0389: 	MOV	R6, #(CD_1024_00000C34 - 2481844)
    R4 = R2 >> 24;                                                // 0390: 	LSRS	R4, R2, #24
    R2 = R10;                                                     // 0391: 	MOV	R2, R10
    R5 = *(UInt32*)(R12 + 100);                                 // 0392: 	LDR.W	R5, [R12,#100]
    // 0393: 	ADD	R6, PC
    R4 = *(UInt32*)(R6 + (R4 << 2));                            // 0394: 	LDR.W	R4, [R6,R4,LSL#2]
    R4 = R4 ^ R5;                                                 // 0395: 	EORS	R4, R5
    R1 = R1 ^ R4;                                                 // 0396: 	EORS	R1, R4
    temp6 = R1;                                                   // 0397: 	STR	R1, [SP,#960+temp6]
    R1 = R10 >> 24;                                               // 0398: 	MOV.W	R1, R10,LSR#24
    R5 = (R3 >> 16) & ((1 << 8) - 1);                             // 0399: 	UBFX.W	R5, R3, #16, #8
    R1 = *(UInt32*)(R6 + (R1 << 2));                            // 0400: 	LDR.W	R1, [R6,R1,LSL#2]
    R5 = *(UInt32*)(R0 + (R5 << 2));                            // 0401: 	LDR.W	R5, [R0,R5,LSL#2]
    R6 = *(UInt32*)(R12 + 88);                                  // 0402: 	LDR.W	R6, [R12,#88]
    R5 = R5 ^ R6;                                                 // 0403: 	EORS	R5, R6
    R1 = R1 ^ R5;                                                 // 0404: 	EORS	R1, R5
    R5 = R11 & 0x000000FF;                                        // 0405: 	UXTB.W	R5, R11
    R5 = *(UInt32*)(R8 + (R5 << 2));                            // 0406: 	LDR.W	R5, [R8,R5,LSL#2]
    R1 = R1 ^ R5;                                                 // 0407: 	EORS	R1, R5
    R5 = (LR >> 8) & ((1 << 8) - 1);                              // 0408: 	UBFX.W	R5, LR, #8, #8
    R4 = (MyUInt32)(cryptData + 0x0000CC1C);                      // 0409: 	MOV	R4, #(CD_1024_0000CC1C - 2481902)
    // 0410: 	ADD	R4, PC
    R5 = *(UInt32*)(R4 + (R5 << 2));                            // 0411: 	LDR.W	R5, [R4,R5,LSL#2]
    R8 = R5 ^ R1;                                                 // 0412: 	EOR.W	R8, R5, R1
    R5 = (R8 >> 8) & ((1 << 8) - 1);                              // 0413: 	UBFX.W	R5, R8, #8, #8
    R10 = (MyUInt32)(cryptData + 0x00005940);                     // 0414: 	MOV	R10, #(CD_1024_00005940 - 2481930)
    R0 = temp6;                                                   // 0415: 	LDR	R0, [SP,#960+temp6]
    R6 = (R2 >> 16) & ((1 << 8) - 1);                             // 0416: 	UBFX.W	R6, R2, #16, #8
    // 0417: 	ADD	R10, PC
    R5 = *(UInt32*)(R10 + (R5 << 2));                           // 0418: 	LDR.W	R5, [R10,R5,LSL#2]
    R10 = R4;                                                     // 0419: 	MOV	R10, R4
    R1 = R5 ^ R0;                                                 // 0420: 	EOR.W	R1, R5, R0
    R0 = (MyUInt32)(cryptData + 0x000149EC);                      // 0421: 	MOV	R0, #(CD_1024_000149EC - 2481962)
    R2 = (R3 >> 8) & ((1 << 8) - 1);                              // 0422: 	UBFX.W	R2, R3, #8, #8
    R5 = *(UInt32*)(R12 + 92);                                  // 0423: 	LDR.W	R5, [R12,#92]
    R2 = *(UInt32*)(R9 + (R2 << 2));                            // 0424: 	LDR.W	R2, [R9,R2,LSL#2]
    // 0425: 	ADD	R0, PC
    R6 = *(UInt32*)(R0 + (R6 << 2));                            // 0426: 	LDR.W	R6, [R0,R6,LSL#2]
    R0 = R11 >> 24;                                               // 0427: 	MOV.W	R0, R11,LSR#24
    R2 = R2 ^ R5;                                                 // 0428: 	EORS	R2, R5
    R2 = R2 ^ R6;                                                 // 0429: 	EORS	R2, R6
    R6 = (MyUInt32)(cryptData + 0x00005D40);                      // 0430: 	MOV	R6, #(CD_1024_00005D40 - 2481988)
    R3 = (MyUInt32)(cryptData + 0x00000834);                      // 0431: 	MOV	R3, #(CD_1024_00000834 - 2481998)
    // 0432: 	ADD	R6, PC
    R0 = *(UInt32*)(R6 + (R0 << 2));                            // 0433: 	LDR.W	R0, [R6,R0,LSL#2]
    // 0434: 	ADD	R3, PC
    R0 = R0 ^ R2;                                                 // 0435: 	EORS	R0, R2
    R2 = LR & 0x000000FF;                                         // 0436: 	UXTB.W	R2, LR
    R2 = *(UInt32*)(R3 + (R2 << 2));                            // 0437: 	LDR.W	R2, [R3,R2,LSL#2]
    R2 = R2 ^ R0;                                                 // 0438: 	EORS	R2, R0
    R0 = (R2 >> 16) & ((1 << 8) - 1);                             // 0439: 	UBFX.W	R0, R2, #16, #8
    R6 = (MyUInt32)(cryptData + 0x0000FC48);                      // 0440: 	MOV	R6, #(CD_1024_0000FC48 - 2482028)
    R9 = temp1;                                                   // 0441: 	LDR.W	R9, [SP,#960+temp1]
    // 0442: 	ADD	R6, PC
    R0 = *(UInt32*)(R6 + (R0 << 2));                            // 0443: 	LDR.W	R0, [R6,R0,LSL#2]
    R0 = R0 ^ R1;                                                 // 0444: 	EORS	R0, R1
    temp3 = R0;                                                   // 0445: 	STR	R0, [SP,#960+temp3]
    R0 = R0 & 0x000000FF;                                         // 0446: 	UXTB	R0, R0
    R0 = *(UInt32*)(R3 + (R0 << 2));                            // 0447: 	LDR.W	R0, [R3,R0,LSL#2]
    R3 = (R9 >> 8) & ((1 << 8) - 1);                              // 0448: 	UBFX.W	R3, R9, #8, #8
    R1 = temp2;                                                   // 0449: 	LDR	R1, [SP,#960+temp2]
    R5 = (MyUInt32)(cryptData + 0x0000C3E0);                      // 0450: 	MOV	R5, #(CD_1024_0000C3E0 - 2482062)
    R3 = *(UInt32*)(R4 + (R3 << 2));                            // 0451: 	LDR.W	R3, [R4,R3,LSL#2]
    // 0452: 	ADD	R5, PC
    R4 = R1 & 0x000000FF;                                         // 0453: 	UXTB	R4, R1
    R4 = *(UInt32*)(R5 + (R4 << 2));                            // 0454: 	LDR.W	R4, [R5,R4,LSL#2]
    R5 = *(UInt32*)(R12 + 96);                                  // 0455: 	LDR.W	R5, [R12,#96]
    R4 = R4 ^ R5;                                                 // 0456: 	EORS	R4, R5
    R3 = R3 ^ R4;                                                 // 0457: 	EORS	R3, R4
    R4 = (R8 >> 16) & ((1 << 8) - 1);                             // 0458: 	UBFX.W	R4, R8, #16, #8
    LR = (MyUInt32)(cryptData + 0x00000C34);                      // 0459: 	MOV	LR, #(CD_1024_00000C34 - 2482094)
    R4 = *(UInt32*)(R6 + (R4 << 2));                            // 0460: 	LDR.W	R4, [R6,R4,LSL#2]
    // 0461: 	ADD	LR, PC
    R3 = R3 ^ R4;                                                 // 0462: 	EORS	R3, R4
    R4 = R2 >> 24;                                                // 0463: 	LSRS	R4, R2, #24
    R4 = *(UInt32*)(LR + (R4 << 2));                            // 0464: 	LDR.W	R4, [LR,R4,LSL#2]
    R11 = R4 ^ R3;                                                // 0465: 	EOR.W	R11, R4, R3
    R3 = (MyUInt32)(cryptData + 0x0000A258);                      // 0466: 	MOV	R3, #(CD_1024_0000A258 - 2482124)
    R4 = R11 >> 24;                                               // 0467: 	MOV.W	R4, R11,LSR#24
    R5 = *(UInt32*)(R12 + 116);                                 // 0468: 	LDR.W	R5, [R12,#116]
    // 0469: 	ADD	R3, PC
    R4 = *(UInt32*)(R3 + (R4 << 2));                            // 0470: 	LDR.W	R4, [R3,R4,LSL#2]
    R4 = R4 ^ R5;                                                 // 0471: 	EORS	R4, R5
    R0 = R0 ^ R4;                                                 // 0472: 	EORS	R0, R4
    R4 = R9;                                                      // 0473: 	MOV	R4, R9
    temp4 = R0;                                                   // 0474: 	STR	R0, [SP,#960+temp4]
    R5 = (R1 >> 16) & ((1 << 8) - 1);                             // 0475: 	UBFX.W	R5, R1, #16, #8
    R0 = R9 >> 24;                                                // 0476: 	MOV.W	R0, R9,LSR#24
    R9 = LR;                                                      // 0477: 	MOV	R9, LR
    R5 = *(UInt32*)(R6 + (R5 << 2));                            // 0478: 	LDR.W	R5, [R6,R5,LSL#2]
    R6 = *(UInt32*)(R12 + 104);                                 // 0479: 	LDR.W	R6, [R12,#104]
    R0 = *(UInt32*)(LR + (R0 << 2));                            // 0480: 	LDR.W	R0, [LR,R0,LSL#2]
    R3 = (MyUInt32)(cryptData + 0x000071B0);                      // 0481: 	MOV	R3, #(CD_1024_000071B0 - 2482168)
    // 0482: 	ADD	R3, PC
    R5 = R5 ^ R6;                                                 // 0483: 	EORS	R5, R6
    R0 = R0 ^ R5;                                                 // 0484: 	EORS	R0, R5
    R5 = R8 & 0x000000FF;                                         // 0485: 	UXTB.W	R5, R8
    R5 = *(UInt32*)(R3 + (R5 << 2));                            // 0486: 	LDR.W	R5, [R3,R5,LSL#2]
    R0 = R0 ^ R5;                                                 // 0487: 	EORS	R0, R5
    R5 = (R2 >> 8) & ((1 << 8) - 1);                              // 0488: 	UBFX.W	R5, R2, #8, #8
    R3 = (MyUInt32)(cryptData + 0x00005940);                      // 0489: 	MOV	R3, #(CD_1024_00005940 - 2482198)
    R2 = R2 & 0x000000FF;                                         // 0490: 	UXTB	R2, R2
    // 0491: 	ADD	R3, PC
    R5 = *(UInt32*)(R3 + (R5 << 2));                            // 0492: 	LDR.W	R5, [R3,R5,LSL#2]
    R0 = R0 ^ R5;                                                 // 0493: 	EORS	R0, R5
    R5 = (R0 >> 8) & ((1 << 8) - 1);                              // 0494: 	UBFX.W	R5, R0, #8, #8
    R6 = temp4;                                                   // 0495: 	LDR	R6, [SP,#960+temp4]
    R5 = *(UInt32*)(R10 + (R5 << 2));                           // 0496: 	LDR.W	R5, [R10,R5,LSL#2]
    R6 = R6 ^ R5;                                                 // 0497: 	EORS	R6, R5
    temp4 = R6;                                                   // 0498: 	STR	R6, [SP,#960+temp4]
    R6 = (R4 >> 16) & ((1 << 8) - 1);                             // 0499: 	UBFX.W	R6, R4, #16, #8
    LR = (MyUInt32)(cryptData + 0x0000E844);                      // 0500: 	MOV	LR, #(CD_1024_0000E844 - 2482244)
    R5 = (R1 >> 8) & ((1 << 8) - 1);                              // 0501: 	UBFX.W	R5, R1, #8, #8
    R1 = (MyUInt32)(cryptData + 0x000075D8);                      // 0502: 	MOV	R1, #(CD_1024_000075D8 - 2482250)
    // 0503: 	ADD	LR, PC
    R4 = *(UInt32*)(R12 + 108);                                 // 0504: 	LDR.W	R4, [R12,#108]
    // 0505: 	ADD	R1, PC
    R6 = *(UInt32*)(LR + (R6 << 2));                            // 0506: 	LDR.W	R6, [LR,R6,LSL#2]
    R5 = *(UInt32*)(R1 + (R5 << 2));                            // 0507: 	LDR.W	R5, [R1,R5,LSL#2]
    R1 = R8 >> 24;                                                // 0508: 	MOV.W	R1, R8,LSR#24
    R8 = (MyUInt32)(cryptData + 0x0000BAA4);                      // 0509: 	MOV	R8, #(CD_1024_0000BAA4 - 2482276)
    R1 = *(UInt32*)(R9 + (R1 << 2));                            // 0510: 	LDR.W	R1, [R9,R1,LSL#2]
    // 0511: 	ADD	R8, PC
    R2 = *(UInt32*)(R8 + (R2 << 2));                            // 0512: 	LDR.W	R2, [R8,R2,LSL#2]
    R5 = R5 ^ R4;                                                 // 0513: 	EORS	R5, R4
    R6 = R6 ^ R5;                                                 // 0514: 	EORS	R6, R5
    R5 = R11 & 0x000000FF;                                        // 0515: 	UXTB.W	R5, R11
    R1 = R1 ^ R6;                                                 // 0516: 	EORS	R1, R6
    R10 = R2 ^ R1;                                                // 0517: 	EOR.W	R10, R2, R1
    R2 = (R10 >> 16) & ((1 << 8) - 1);                            // 0518: 	UBFX.W	R2, R10, #16, #8
    R1 = temp4;                                                   // 0519: 	LDR	R1, [SP,#960+temp4]
    R2 = *(UInt32*)(LR + (R2 << 2));                            // 0520: 	LDR.W	R2, [LR,R2,LSL#2]
    R1 = R1 ^ R2;                                                 // 0521: 	EORS	R1, R2
    temp2 = R1;                                                   // 0522: 	STR	R1, [SP,#960+temp2]
    R2 = R1 & 0x000000FF;                                         // 0523: 	UXTB	R2, R1
    R1 = (MyUInt32)(cryptData + 0x0000EC44);                      // 0524: 	MOV	R1, #(CD_1024_0000EC44 - 2482320)
    // 0525: 	ADD	R1, PC
    R2 = *(UInt32*)(R1 + (R2 << 2));                            // 0526: 	LDR.W	R2, [R1,R2,LSL#2]
    R1 = temp3;                                                   // 0527: 	LDR	R1, [SP,#960+temp3]
    R6 = (R1 >> 8) & ((1 << 8) - 1);                              // 0528: 	UBFX.W	R6, R1, #8, #8
    R9 = (MyUInt32)(cryptData + 0x00000834);                      // 0529: 	MOV	R9, #(CD_1024_00000834 - 2482348)
    R4 = *(UInt32*)(R12 + 112);                                 // 0530: 	LDR.W	R4, [R12,#112]
    R6 = *(UInt32*)(R3 + (R6 << 2));                            // 0531: 	LDR.W	R6, [R3,R6,LSL#2]
    // 0532: 	ADD	R9, PC
    R5 = *(UInt32*)(R9 + (R5 << 2));                            // 0533: 	LDR.W	R5, [R9,R5,LSL#2]
    R5 = R5 ^ R4;                                                 // 0534: 	EORS	R5, R4
    R6 = R6 ^ R5;                                                 // 0535: 	EORS	R6, R5
    R5 = (R0 >> 16) & ((1 << 8) - 1);                             // 0536: 	UBFX.W	R5, R0, #16, #8
    R4 = (MyUInt32)(cryptData + 0x0000D01C);                      // 0537: 	MOV	R4, #(CD_1024_0000D01C - 2482376)
    R5 = *(UInt32*)(LR + (R5 << 2));                            // 0538: 	LDR.W	R5, [LR,R5,LSL#2]
    LR = R1;                                                      // 0539: 	MOV	LR, R1
    // 0540: 	ADD	R4, PC
    R6 = R6 ^ R5;                                                 // 0541: 	EORS	R6, R5
    R5 = R10 >> 24;                                               // 0542: 	MOV.W	R5, R10,LSR#24
    R5 = *(UInt32*)(R4 + (R5 << 2));                            // 0543: 	LDR.W	R5, [R4,R5,LSL#2]
    R6 = R6 ^ R5;                                                 // 0544: 	EORS	R6, R5
    temp1 = R6;                                                   // 0545: 	STR	R6, [SP,#960+temp1]
    R4 = R6 >> 24;                                                // 0546: 	LSRS	R4, R6, #24
    R6 = (MyUInt32)(cryptData + 0x00005D40);                      // 0547: 	MOV	R6, #(CD_1024_00005D40 - 2482406)
    R5 = *(UInt32*)(R12 + 132);                                 // 0548: 	LDR.W	R5, [R12,#132]
    // 0549: 	ADD	R6, PC
    R4 = *(UInt32*)(R6 + (R4 << 2));                            // 0550: 	LDR.W	R4, [R6,R4,LSL#2]
    R4 = R4 ^ R5;                                                 // 0551: 	EORS	R4, R5
    R2 = R2 ^ R4;                                                 // 0552: 	EORS	R2, R4
    temp4 = R2;                                                   // 0553: 	STR	R2, [SP,#960+temp4]
    R5 = (R11 >> 16) & ((1 << 8) - 1);                            // 0554: 	UBFX.W	R5, R11, #16, #8
    R4 = (MyUInt32)(cryptData + 0x00015E08);                      // 0555: 	MOV	R4, #(CD_1024_00015E08 - 2482440)
    R2 = R1 >> 24;                                                // 0556: 	LSRS	R2, R1, #24
    R2 = *(UInt32*)(R6 + (R2 << 2));                            // 0557: 	LDR.W	R2, [R6,R2,LSL#2]
    R6 = *(UInt32*)(R12 + 120);                                 // 0558: 	LDR.W	R6, [R12,#120]
    // 0559: 	ADD	R4, PC
    R5 = *(UInt32*)(R4 + (R5 << 2));                            // 0560: 	LDR.W	R5, [R4,R5,LSL#2]
    R5 = R5 ^ R6;                                                 // 0561: 	EORS	R5, R6
    R2 = R2 ^ R5;                                                 // 0562: 	EORS	R2, R5
    R5 = R0 & 0x000000FF;                                         // 0563: 	UXTB	R5, R0
    R0 = R0 >> 24;                                                // 0564: 	LSRS	R0, R0, #24
    R5 = *(UInt32*)(R9 + (R5 << 2));                            // 0565: 	LDR.W	R5, [R9,R5,LSL#2]
    R2 = R2 ^ R5;                                                 // 0566: 	EORS	R2, R5
    R5 = (R10 >> 8) & ((1 << 8) - 1);                             // 0567: 	UBFX.W	R5, R10, #8, #8
    R1 = (MyUInt32)(cryptData + 0x0000CC1C);                      // 0568: 	MOV	R1, #(CD_1024_0000CC1C - 2482472)
    // 0569: 	ADD	R1, PC
    R5 = *(UInt32*)(R1 + (R5 << 2));                            // 0570: 	LDR.W	R5, [R1,R5,LSL#2]
    R2 = R2 ^ R5;                                                 // 0571: 	EORS	R2, R5
    R5 = (R2 >> 8) & ((1 << 8) - 1);                              // 0572: 	UBFX.W	R5, R2, #8, #8
    R1 = temp4;                                                   // 0573: 	LDR	R1, [SP,#960+temp4]
    R5 = *(UInt32*)(R3 + (R5 << 2));                            // 0574: 	LDR.W	R5, [R3,R5,LSL#2]
    R1 = R1 ^ R5;                                                 // 0575: 	EORS	R1, R5
    temp4 = R1;                                                   // 0576: 	STR	R1, [SP,#960+temp4]
    R6 = (LR >> 16) & ((1 << 8) - 1);                             // 0577: 	UBFX.W	R6, LR, #16, #8
    R3 = (R11 >> 8) & ((1 << 8) - 1);                             // 0578: 	UBFX.W	R3, R11, #8, #8
    R1 = (MyUInt32)(cryptData + 0x0000E030);                      // 0579: 	MOV	R1, #(CD_1024_0000E030 - 2482522)
    R5 = *(UInt32*)(R12 + 124);                                 // 0580: 	LDR.W	R5, [R12,#124]
    LR = (MyUInt32)(cryptData + 0x000028F8);                      // 0581: 	MOV	LR, #(CD_1024_000028F8 - 2482532)
    R6 = *(UInt32*)(R4 + (R6 << 2));                            // 0582: 	LDR.W	R6, [R4,R6,LSL#2]
    // 0583: 	ADD	R1, PC
    R3 = *(UInt32*)(R1 + (R3 << 2));                            // 0584: 	LDR.W	R3, [R1,R3,LSL#2]
    // 0585: 	ADD	LR, PC
    R1 = R10 & 0x000000FF;                                        // 0586: 	UXTB.W	R1, R10
    R0 = *(UInt32*)(LR + (R0 << 2));                            // 0587: 	LDR.W	R0, [LR,R0,LSL#2]
    R1 = *(UInt32*)(R8 + (R1 << 2));                            // 0588: 	LDR.W	R1, [R8,R1,LSL#2]
    R3 = R3 ^ R5;                                                 // 0589: 	EORS	R3, R5
    R3 = R3 ^ R6;                                                 // 0590: 	EORS	R3, R6
    R0 = R0 ^ R3;                                                 // 0591: 	EORS	R0, R3
    R1 = R1 ^ R0;                                                 // 0592: 	EORS	R1, R0
    R0 = (R1 >> 16) & ((1 << 8) - 1);                             // 0593: 	UBFX.W	R0, R1, #16, #8
    R3 = (MyUInt32)(cryptData + 0x0000E844);                      // 0594: 	MOV	R3, #(CD_1024_0000E844 - 2482566)
    // 0595: 	ADD	R3, PC
    R0 = *(UInt32*)(R3 + (R0 << 2));                            // 0596: 	LDR.W	R0, [R3,R0,LSL#2]
    R3 = temp4;                                                   // 0597: 	LDR	R3, [SP,#960+temp4]
    R0 = R0 ^ R3;                                                 // 0598: 	EORS	R0, R3
    temp3 = R0;                                                   // 0599: 	STR	R0, [SP,#960+temp3]
    R0 = R0 & 0x000000FF;                                         // 0600: 	UXTB	R0, R0
    R0 = *(UInt32*)(R9 + (R0 << 2));                            // 0601: 	LDR.W	R0, [R9,R0,LSL#2]
    R9 = temp2;                                                   // 0602: 	LDR.W	R9, [SP,#960+temp2]
    R3 = (R9 >> 8) & ((1 << 8) - 1);                              // 0603: 	UBFX.W	R3, R9, #8, #8
    R6 = (MyUInt32)(cryptData + 0x000075D8);                      // 0604: 	MOV	R6, #(CD_1024_000075D8 - 2482606)
    R11 = R9;                                                     // 0605: 	MOV	R11, R9
    R10 = temp1;                                                  // 0606: 	LDR.W	R10, [SP,#960+temp1]
    // 0607: 	ADD	R6, PC
    R3 = *(UInt32*)(R6 + (R3 << 2));                            // 0608: 	LDR.W	R3, [R6,R3,LSL#2]
    R6 = (MyUInt32)(cryptData + 0x000071B0);                      // 0609: 	MOV	R6, #(CD_1024_000071B0 - 2482628)
    R5 = *(UInt32*)(R12 + 128);                                 // 0610: 	LDR.W	R5, [R12,#128]
    R4 = R10 & 0x000000FF;                                        // 0611: 	UXTB.W	R4, R10
    // 0612: 	ADD	R6, PC
    R4 = *(UInt32*)(R6 + (R4 << 2));                            // 0613: 	LDR.W	R4, [R6,R4,LSL#2]
    R4 = R4 ^ R5;                                                 // 0614: 	EORS	R4, R5
    R3 = R3 ^ R4;                                                 // 0615: 	EORS	R3, R4
    R4 = (R2 >> 16) & ((1 << 8) - 1);                             // 0616: 	UBFX.W	R4, R2, #16, #8
    R8 = (MyUInt32)(cryptData + 0x00015E08);                      // 0617: 	MOV	R8, #(CD_1024_00015E08 - 2482654)
    R6 = (MyUInt32)(cryptData + 0x00005D40);                      // 0618: 	MOV	R6, #(CD_1024_00005D40 - 2482664)
    // 0619: 	ADD	R8, PC
    R4 = *(UInt32*)(R8 + (R4 << 2));                            // 0620: 	LDR.W	R4, [R8,R4,LSL#2]
    // 0621: 	ADD	R6, PC
    R3 = R3 ^ R4;                                                 // 0622: 	EORS	R3, R4
    R4 = R1 >> 24;                                                // 0623: 	LSRS	R4, R1, #24
    R4 = *(UInt32*)(R6 + (R4 << 2));                            // 0624: 	LDR.W	R4, [R6,R4,LSL#2]
    R3 = R3 ^ R4;                                                 // 0625: 	EORS	R3, R4
    temp4 = R3;                                                   // 0626: 	STR	R3, [SP,#960+temp4]
    R4 = R3 >> 24;                                                // 0627: 	LSRS	R4, R3, #24
    R3 = (MyUInt32)(cryptData + 0x00000C34);                      // 0628: 	MOV	R3, #(CD_1024_00000C34 - 2482692)
    R5 = *(UInt32*)(R12 + 148);                                 // 0629: 	LDR.W	R5, [R12,#148]
    // 0630: 	ADD	R3, PC
    R4 = *(UInt32*)(R3 + (R4 << 2));                            // 0631: 	LDR.W	R4, [R3,R4,LSL#2]
    R4 = R4 ^ R5;                                                 // 0632: 	EORS	R4, R5
    R0 = R0 ^ R4;                                                 // 0633: 	EORS	R0, R4
    temp5 = R0;                                                   // 0634: 	STR	R0, [SP,#960+temp5]
    R5 = (R10 >> 16) & ((1 << 8) - 1);                            // 0635: 	UBFX.W	R5, R10, #16, #8
    R4 = (MyUInt32)(cryptData + 0x000149EC);                      // 0636: 	MOV	R4, #(CD_1024_000149EC - 2482732)
    R0 = R9 >> 24;                                                // 0637: 	MOV.W	R0, R9,LSR#24
    R0 = *(UInt32*)(R6 + (R0 << 2));                            // 0638: 	LDR.W	R0, [R6,R0,LSL#2]
    R6 = *(UInt32*)(R12 + 136);                                 // 0639: 	LDR.W	R6, [R12,#136]
    R9 = (MyUInt32)(cryptData + 0x0000C3E0);                      // 0640: 	MOV	R9, #(CD_1024_0000C3E0 - 2482742)
    // 0641: 	ADD	R4, PC
    R5 = *(UInt32*)(R4 + (R5 << 2));                            // 0642: 	LDR.W	R5, [R4,R5,LSL#2]
    // 0643: 	ADD	R9, PC
    R5 = R5 ^ R6;                                                 // 0644: 	EORS	R5, R6
    R6 = R0 ^ R5;                                                 // 0645: 	EOR.W	R6, R0, R5
    R5 = R2 & 0x000000FF;                                         // 0646: 	UXTB	R5, R2
    R2 = R2 >> 24;                                                // 0647: 	LSRS	R2, R2, #24
    R5 = *(UInt32*)(R9 + (R5 << 2));                            // 0648: 	LDR.W	R5, [R9,R5,LSL#2]
    R2 = *(UInt32*)(LR + (R2 << 2));                            // 0649: 	LDR.W	R2, [LR,R2,LSL#2]
    R6 = R6 ^ R5;                                                 // 0650: 	EORS	R6, R5
    R5 = (R1 >> 8) & ((1 << 8) - 1);                              // 0651: 	UBFX.W	R5, R1, #8, #8
    R0 = (MyUInt32)(cryptData + 0x0000CC1C);                      // 0652: 	MOV	R0, #(CD_1024_0000CC1C - 2482778)
    R1 = R1 & 0x000000FF;                                         // 0653: 	UXTB	R1, R1
    // 0654: 	ADD	R0, PC
    R5 = *(UInt32*)(R0 + (R5 << 2));                            // 0655: 	LDR.W	R5, [R0,R5,LSL#2]
    R10 = R5 ^ R6;                                                // 0656: 	EOR.W	R10, R5, R6
    R5 = (R10 >> 8) & ((1 << 8) - 1);                             // 0657: 	UBFX.W	R5, R10, #8, #8
    R3 = (MyUInt32)(cryptData + 0x00005940);                      // 0658: 	MOV	R3, #(CD_1024_00005940 - 2482802)
    R6 = temp5;                                                   // 0659: 	LDR	R6, [SP,#960+temp5]
    // 0660: 	ADD	R3, PC
    R5 = *(UInt32*)(R3 + (R5 << 2));                            // 0661: 	LDR.W	R5, [R3,R5,LSL#2]
    R5 = R5 ^ R6;                                                 // 0662: 	EORS	R5, R6
    temp5 = R5;                                                   // 0663: 	STR	R5, [SP,#960+temp5]
    R6 = (R11 >> 16) & ((1 << 8) - 1);                            // 0664: 	UBFX.W	R6, R11, #16, #8
    R6 = *(UInt32*)(R4 + (R6 << 2));                            // 0665: 	LDR.W	R6, [R4,R6,LSL#2]
    R4 = temp1;                                                   // 0666: 	LDR	R4, [SP,#960+temp1]
    R5 = (R4 >> 8) & ((1 << 8) - 1);                              // 0667: 	UBFX.W	R5, R4, #8, #8
    R4 = *(UInt32*)(R12 + 140);                                 // 0668: 	LDR.W	R4, [R12,#140]
    R5 = *(UInt32*)(R0 + (R5 << 2));                            // 0669: 	LDR.W	R5, [R0,R5,LSL#2]
    R0 = (MyUInt32)(cryptData + 0x0000EC44);                      // 0670: 	MOV	R0, #(CD_1024_0000EC44 - 2482842)
    // 0671: 	ADD	R0, PC
    R1 = *(UInt32*)(R0 + (R1 << 2));                            // 0672: 	LDR.W	R1, [R0,R1,LSL#2]
    R5 = R5 ^ R4;                                                 // 0673: 	EORS	R5, R4
    R6 = R6 ^ R5;                                                 // 0674: 	EORS	R6, R5
    R2 = R2 ^ R6;                                                 // 0675: 	EORS	R2, R6
    R11 = R1 ^ R2;                                                // 0676: 	EOR.W	R11, R1, R2
    R2 = (R11 >> 16) & ((1 << 8) - 1);                            // 0677: 	UBFX.W	R2, R11, #16, #8
    R0 = temp5;                                                   // 0678: 	LDR	R0, [SP,#960+temp5]
    R1 = temp3;                                                   // 0679: 	LDR	R1, [SP,#960+temp3]
    R2 = *(UInt32*)(R8 + (R2 << 2));                            // 0680: 	LDR.W	R2, [R8,R2,LSL#2]
    R0 = R0 ^ R2;                                                 // 0681: 	EORS	R0, R2
    temp1 = R0;                                                   // 0682: 	STR	R0, [SP,#960+temp1]
    R6 = (R1 >> 8) & ((1 << 8) - 1);                              // 0683: 	UBFX.W	R6, R1, #8, #8
    R2 = R0 & 0x000000FF;                                         // 0684: 	UXTB	R2, R0
    R0 = *(UInt32*)(R3 + (R6 << 2));                            // 0685: 	LDR.W	R0, [R3,R6,LSL#2]
    R6 = temp4;                                                   // 0686: 	LDR	R6, [SP,#960+temp4]
    LR = (MyUInt32)(cryptData + 0x0000BAA4);                      // 0687: 	MOV	LR, #(CD_1024_0000BAA4 - 2482902)
    R2 = *(UInt32*)(R9 + (R2 << 2));                            // 0688: 	LDR.W	R2, [R9,R2,LSL#2]
    R4 = *(UInt32*)(R12 + 144);                                 // 0689: 	LDR.W	R4, [R12,#144]
    // 0690: 	ADD	LR, PC
    R5 = R6 & 0x000000FF;                                         // 0691: 	UXTB	R5, R6
    R8 = R6;                                                      // 0692: 	MOV	R8, R6
    R5 = *(UInt32*)(LR + (R5 << 2));                            // 0693: 	LDR.W	R5, [LR,R5,LSL#2]
    R5 = R5 ^ R4;                                                 // 0694: 	EORS	R5, R4
    R3 = R0 ^ R5;                                                 // 0695: 	EOR.W	R3, R0, R5
    R5 = (R10 >> 16) & ((1 << 8) - 1);                            // 0696: 	UBFX.W	R5, R10, #16, #8
    R0 = (MyUInt32)(cryptData + 0x0000E844);                      // 0697: 	MOV	R0, #(CD_1024_0000E844 - 2482930)
    // 0698: 	ADD	R0, PC
    R5 = *(UInt32*)(R0 + (R5 << 2));                            // 0699: 	LDR.W	R5, [R0,R5,LSL#2]
    R0 = (MyUInt32)(cryptData + 0x00000C34);                      // 0700: 	MOV	R0, #(CD_1024_00000C34 - 2482944)
    // 0701: 	ADD	R0, PC
    R3 = R3 ^ R5;                                                 // 0702: 	EORS	R3, R5
    R5 = R11 >> 24;                                               // 0703: 	MOV.W	R5, R11,LSR#24
    R5 = *(UInt32*)(R0 + (R5 << 2));                            // 0704: 	LDR.W	R5, [R0,R5,LSL#2]
    R3 = R3 ^ R5;                                                 // 0705: 	EORS	R3, R5
    R5 = *(UInt32*)(R12 + 164);                                 // 0706: 	LDR.W	R5, [R12,#164]
    R4 = R3 >> 24;                                                // 0707: 	LSRS	R4, R3, #24
    temp5 = R3;                                                   // 0708: 	STR	R3, [SP,#960+temp5]
    R4 = *(UInt32*)(R0 + (R4 << 2));                            // 0709: 	LDR.W	R4, [R0,R4,LSL#2]
    R0 = (MyUInt32)(cryptData + 0x00005D40);                      // 0710: 	MOV	R0, #(CD_1024_00005D40 - 2482978)
    // 0711: 	ADD	R0, PC
    R4 = R4 ^ R5;                                                 // 0712: 	EORS	R4, R5
    R5 = (R6 >> 16) & ((1 << 8) - 1);                             // 0713: 	UBFX.W	R5, R6, #16, #8
    R4 = R4 ^ R2;                                                 // 0714: 	EORS	R4, R2
    R2 = R1 >> 24;                                                // 0715: 	LSRS	R2, R1, #24
    R2 = *(UInt32*)(R0 + (R2 << 2));                            // 0716: 	LDR.W	R2, [R0,R2,LSL#2]
    R0 = (MyUInt32)(cryptData + 0x00005540);                      // 0717: 	MOV	R0, #(CD_1024_00005540 - 2483006)
    R6 = *(UInt32*)(R12 + 152);                                 // 0718: 	LDR.W	R6, [R12,#152]
    // 0719: 	ADD	R0, PC
    R5 = *(UInt32*)(R0 + (R5 << 2));                            // 0720: 	LDR.W	R5, [R0,R5,LSL#2]
    R5 = R5 ^ R6;                                                 // 0721: 	EORS	R5, R6
    R2 = R2 ^ R5;                                                 // 0722: 	EORS	R2, R5
    R5 = R10 & 0x000000FF;                                        // 0723: 	UXTB.W	R5, R10
    R5 = *(UInt32*)(LR + (R5 << 2));                            // 0724: 	LDR.W	R5, [LR,R5,LSL#2]
    R2 = R2 ^ R5;                                                 // 0725: 	EORS	R2, R5
    R5 = (R11 >> 8) & ((1 << 8) - 1);                             // 0726: 	UBFX.W	R5, R11, #8, #8
    R3 = (MyUInt32)(cryptData + 0x0000E030);                      // 0727: 	MOV	R3, #(CD_1024_0000E030 - 2483038)
    // 0728: 	ADD	R3, PC
    R5 = *(UInt32*)(R3 + (R5 << 2));                            // 0729: 	LDR.W	R5, [R3,R5,LSL#2]
    LR = R5 ^ R2;                                                 // 0730: 	EOR.W	LR, R5, R2
    R5 = (LR >> 8) & ((1 << 8) - 1);                              // 0731: 	UBFX.W	R5, LR, #8, #8
    R2 = (MyUInt32)(cryptData + 0x000075D8);                      // 0732: 	MOV	R2, #(CD_1024_000075D8 - 2483076)
    R6 = (R1 >> 16) & ((1 << 8) - 1);                             // 0733: 	UBFX.W	R6, R1, #16, #8
    R3 = (R8 >> 8) & ((1 << 8) - 1);                              // 0734: 	UBFX.W	R3, R8, #8, #8
    R8 = (MyUInt32)(cryptData + 0x00013135);                      // 0735: 	MOV	R8, #(CD_1024_00013135 - 2483094)
    R1 = R11 & 0x000000FF;                                        // 0736: 	UXTB.W	R1, R11
    // 0737: 	ADD	R2, PC
    R6 = *(UInt32*)(R0 + (R6 << 2));                            // 0738: 	LDR.W	R6, [R0,R6,LSL#2]
    R0 = R10 >> 24;                                               // 0739: 	MOV.W	R0, R10,LSR#24
    R5 = *(UInt32*)(R2 + (R5 << 2));                            // 0740: 	LDR.W	R5, [R2,R5,LSL#2]
    // 0741: 	ADD	R8, PC
    R3 = *(UInt32*)(R8 + (R3 << 2));                            // 0742: 	LDR.W	R3, [R8,R3,LSL#2]
    R4 = R4 ^ R5;                                                 // 0743: 	EORS	R4, R5
    R5 = *(UInt32*)(R12 + 156);                                 // 0744: 	LDR.W	R5, [R12,#156]
    R3 = R3 ^ R5;                                                 // 0745: 	EORS	R3, R5
    R3 = R3 ^ R6;                                                 // 0746: 	EORS	R3, R6
    R6 = (MyUInt32)(cryptData + 0x000028F8);                      // 0747: 	MOV	R6, #(CD_1024_000028F8 - 2483122)
    R5 = (MyUInt32)(cryptData + 0x000071B0);                      // 0748: 	MOV	R5, #(CD_1024_000071B0 - 2483132)
    // 0749: 	ADD	R6, PC
    R0 = *(UInt32*)(R6 + (R0 << 2));                            // 0750: 	LDR.W	R0, [R6,R0,LSL#2]
    // 0751: 	ADD	R5, PC
    R11 = R6;                                                     // 0752: 	MOV	R11, R6
    R1 = *(UInt32*)(R5 + (R1 << 2));                            // 0753: 	LDR.W	R1, [R5,R1,LSL#2]
    R0 = R0 ^ R3;                                                 // 0754: 	EORS	R0, R3
    R9 = R1 ^ R0;                                                 // 0755: 	EOR.W	R9, R1, R0
    R0 = (R9 >> 16) & ((1 << 8) - 1);                             // 0756: 	UBFX.W	R0, R9, #16, #8
    R10 = (MyUInt32)(cryptData + 0x00015E08);                     // 0757: 	MOV	R10, #(CD_1024_00015E08 - 2483158)
    // 0758: 	ADD	R10, PC
    R0 = *(UInt32*)(R10 + (R0 << 2));                           // 0759: 	LDR.W	R0, [R10,R0,LSL#2]
    R0 = R0 ^ R4;                                                 // 0760: 	EORS	R0, R4
    temp3 = R0;                                                   // 0761: 	STR	R0, [SP,#960+temp3]
    R3 = (MyUInt32)(cryptData + 0x0000EC44);                      // 0762: 	MOV	R3, #(CD_1024_0000EC44 - 2483178)
    R0 = R0 & 0x000000FF;                                         // 0763: 	UXTB	R0, R0
    // 0764: 	ADD	R3, PC
    R0 = *(UInt32*)(R3 + (R0 << 2));                            // 0765: 	LDR.W	R0, [R3,R0,LSL#2]
    temp4 = R0;                                                   // 0766: 	STR	R0, [SP,#960+temp4]
    R0 = temp1;                                                   // 0767: 	LDR	R0, [SP,#960+temp1]
    R3 = (R0 >> 8) & ((1 << 8) - 1);                              // 0768: 	UBFX.W	R3, R0, #8, #8
    R1 = temp5;                                                   // 0769: 	LDR	R1, [SP,#960+temp5]
    R3 = *(UInt32*)(R2 + (R3 << 2));                            // 0770: 	LDR.W	R3, [R2,R3,LSL#2]
    R4 = R1 & 0x000000FF;                                         // 0771: 	UXTB	R4, R1
    R4 = *(UInt32*)(R5 + (R4 << 2));                            // 0772: 	LDR.W	R4, [R5,R4,LSL#2]
    R5 = *(UInt32*)(R12 + 160);                                 // 0773: 	LDR.W	R5, [R12,#160]
    R4 = R4 ^ R5;                                                 // 0774: 	EORS	R4, R5
    R3 = R3 ^ R4;                                                 // 0775: 	EORS	R3, R4
    R4 = (LR >> 16) & ((1 << 8) - 1);                             // 0776: 	UBFX.W	R4, LR, #16, #8
    R5 = (MyUInt32)(cryptData + 0x0000FC48);                      // 0777: 	MOV	R5, #(CD_1024_0000FC48 - 2483224)
    // 0778: 	ADD	R5, PC
    R4 = *(UInt32*)(R5 + (R4 << 2));                            // 0779: 	LDR.W	R4, [R5,R4,LSL#2]
    R3 = R3 ^ R4;                                                 // 0780: 	EORS	R3, R4
    R4 = R9 >> 24;                                                // 0781: 	MOV.W	R4, R9,LSR#24
    R4 = *(UInt32*)(R6 + (R4 << 2));                            // 0782: 	LDR.W	R4, [R6,R4,LSL#2]
    R3 = R3 ^ R4;                                                 // 0783: 	EORS	R3, R4
    temp2 = R3;                                                   // 0784: 	STR	R3, [SP,#960+temp2]
    R4 = R3 >> 24;                                                // 0785: 	LSRS	R4, R3, #24
    R3 = (MyUInt32)(cryptData + 0x00005D40);                      // 0786: 	MOV	R3, #(CD_1024_00005D40 - 2483258)
    R5 = *(UInt32*)(R12 + 180);                                 // 0787: 	LDR.W	R5, [R12,#180]
    // 0788: 	ADD	R3, PC
    R4 = *(UInt32*)(R3 + (R4 << 2));                            // 0789: 	LDR.W	R4, [R3,R4,LSL#2]
    R3 = temp4;                                                   // 0790: 	LDR	R3, [SP,#960+temp4]
    R6 = (MyUInt32)(cryptData + 0x00000C34);                      // 0791: 	MOV	R6, #(CD_1024_00000C34 - 2483274)
    // 0792: 	ADD	R6, PC
    R4 = R4 ^ R5;                                                 // 0793: 	EORS	R4, R5
    R5 = (R1 >> 16) & ((1 << 8) - 1);                             // 0794: 	UBFX.W	R5, R1, #16, #8
    R4 = R4 ^ R3;                                                 // 0795: 	EORS	R4, R3
    R3 = R0;                                                      // 0796: 	MOV	R3, R0
    R0 = R3 >> 24;                                                // 0797: 	LSRS	R0, R3, #24
    R0 = *(UInt32*)(R6 + (R0 << 2));                            // 0798: 	LDR.W	R0, [R6,R0,LSL#2]
    R6 = (MyUInt32)(cryptData + 0x00005540);                      // 0799: 	MOV	R6, #(CD_1024_00005540 - 2483300)
    // 0800: 	ADD	R6, PC
    R5 = *(UInt32*)(R6 + (R5 << 2));                            // 0801: 	LDR.W	R5, [R6,R5,LSL#2]
    R6 = *(UInt32*)(R12 + 168);                                 // 0802: 	LDR.W	R6, [R12,#168]
    R5 = R5 ^ R6;                                                 // 0803: 	EORS	R5, R6
    R6 = (MyUInt32)(cryptData + 0x00000834);                      // 0804: 	MOV	R6, #(CD_1024_00000834 - 2483326)
    R0 = R0 ^ R5;                                                 // 0805: 	EORS	R0, R5
    R5 = LR & 0x000000FF;                                         // 0806: 	UXTB.W	R5, LR
    // 0807: 	ADD	R6, PC
    R5 = *(UInt32*)(R6 + (R5 << 2));                            // 0808: 	LDR.W	R5, [R6,R5,LSL#2]
    R0 = R0 ^ R5;                                                 // 0809: 	EORS	R0, R5
    R5 = (R9 >> 8) & ((1 << 8) - 1);                              // 0810: 	UBFX.W	R5, R9, #8, #8
    R5 = *(UInt32*)(R2 + (R5 << 2));                            // 0811: 	LDR.W	R5, [R2,R5,LSL#2]
    R0 = R0 ^ R5;                                                 // 0812: 	EORS	R0, R5
    temp6 = R0;                                                   // 0813: 	STR	R0, [SP,#960+temp6]
    R5 = (R0 >> 8) & ((1 << 8) - 1);                              // 0814: 	UBFX.W	R5, R0, #8, #8
    R6 = (R3 >> 16) & ((1 << 8) - 1);                             // 0815: 	UBFX.W	R6, R3, #16, #8
    R5 = *(UInt32*)(R8 + (R5 << 2));                            // 0816: 	LDR.W	R5, [R8,R5,LSL#2]
    R6 = *(UInt32*)(R10 + (R6 << 2));                           // 0817: 	LDR.W	R6, [R10,R6,LSL#2]
    R8 = R5 ^ R4;                                                 // 0818: 	EOR.W	R8, R5, R4
    R5 = (R1 >> 8) & ((1 << 8) - 1);                              // 0819: 	UBFX.W	R5, R1, #8, #8
    R4 = *(UInt32*)(R12 + 172);                                 // 0820: 	LDR.W	R4, [R12,#172]
    R1 = R9 & 0x000000FF;                                         // 0821: 	UXTB.W	R1, R9
    R5 = *(UInt32*)(R2 + (R5 << 2));                            // 0822: 	LDR.W	R5, [R2,R5,LSL#2]
    R2 = LR >> 24;                                                // 0823: 	MOV.W	R2, LR,LSR#24
    R2 = *(UInt32*)(R11 + (R2 << 2));                           // 0824: 	LDR.W	R2, [R11,R2,LSL#2]
    R5 = R5 ^ R4;                                                 // 0825: 	EORS	R5, R4
    R6 = R6 ^ R5;                                                 // 0826: 	EORS	R6, R5
    R2 = R2 ^ R6;                                                 // 0827: 	EORS	R2, R6
    R6 = (MyUInt32)(cryptData + 0x0000C3E0);                      // 0828: 	MOV	R6, #(CD_1024_0000C3E0 - 2483404)
    // 0829: 	ADD	R6, PC
    R1 = *(UInt32*)(R6 + (R1 << 2));                            // 0830: 	LDR.W	R1, [R6,R1,LSL#2]
    R11 = R1 ^ R2;                                                // 0831: 	EOR.W	R11, R1, R2
    R2 = (R11 >> 16) & ((1 << 8) - 1);                            // 0832: 	UBFX.W	R2, R11, #16, #8
    R0 = (MyUInt32)(cryptData + 0x000149EC);                      // 0833: 	MOV	R0, #(CD_1024_000149EC - 2483426)
    // 0834: 	ADD	R0, PC
    R2 = *(UInt32*)(R0 + (R2 << 2));                            // 0835: 	LDR.W	R2, [R0,R2,LSL#2]
    R0 = R2 ^ R8;                                                 // 0836: 	EOR.W	R0, R2, R8
    temp1 = R0;                                                   // 0837: 	STR	R0, [SP,#960+temp1]
    R10 = (MyUInt32)(cryptData + 0x0000BAA4);                     // 0838: 	MOV	R10, #(CD_1024_0000BAA4 - 2483452)
    R2 = R0 & 0x000000FF;                                         // 0839: 	UXTB	R2, R0
    LR = temp3;                                                   // 0840: 	LDR.W	LR, [SP,#960+temp3]
    // 0841: 	ADD	R10, PC
    R2 = *(UInt32*)(R10 + (R2 << 2));                           // 0842: 	LDR.W	R2, [R10,R2,LSL#2]
    R6 = (LR >> 8) & ((1 << 8) - 1);                              // 0843: 	UBFX.W	R6, LR, #8, #8
    R0 = (MyUInt32)(cryptData + 0x0000CC1C);                      // 0844: 	MOV	R0, #(CD_1024_0000CC1C - 2483470)
    // 0845: 	ADD	R0, PC
    R9 = R0;                                                      // 0846: 	MOV	R9, R0
    R0 = temp2;                                                   // 0847: 	LDR	R0, [SP,#960+temp2]
    R1 = (MyUInt32)(cryptData + 0x0000EC44);                      // 0848: 	MOV	R1, #(CD_1024_0000EC44 - 2483496)
    R4 = *(UInt32*)(R12 + 176);                                 // 0849: 	LDR.W	R4, [R12,#176]
    R6 = *(UInt32*)(R9 + (R6 << 2));                            // 0850: 	LDR.W	R6, [R9,R6,LSL#2]
    R8 = temp6;                                                   // 0851: 	LDR.W	R8, [SP,#960+temp6]
    // 0852: 	ADD	R1, PC
    R5 = R0 & 0x000000FF;                                         // 0853: 	UXTB	R5, R0
    R5 = *(UInt32*)(R1 + (R5 << 2));                            // 0854: 	LDR.W	R5, [R1,R5,LSL#2]
    R5 = R5 ^ R4;                                                 // 0855: 	EORS	R5, R4
    R6 = R6 ^ R5;                                                 // 0856: 	EORS	R6, R5
    R5 = (R8 >> 16) & ((1 << 8) - 1);                             // 0857: 	UBFX.W	R5, R8, #16, #8
    R1 = (MyUInt32)(cryptData + 0x00005540);                      // 0858: 	MOV	R1, #(CD_1024_00005540 - 2483520)
    // 0859: 	ADD	R1, PC
    R5 = *(UInt32*)(R1 + (R5 << 2));                            // 0860: 	LDR.W	R5, [R1,R5,LSL#2]
    R4 = R5 ^ R6;                                                 // 0861: 	EOR.W	R4, R5, R6
    R6 = (MyUInt32)(cryptData + 0x0000D01C);                      // 0862: 	MOV	R6, #(CD_1024_0000D01C - 2483542)
    R5 = R11 >> 24;                                               // 0863: 	MOV.W	R5, R11,LSR#24
    // 0864: 	ADD	R6, PC
    R5 = *(UInt32*)(R6 + (R5 << 2));                            // 0865: 	LDR.W	R5, [R6,R5,LSL#2]
    R3 = R5 ^ R4;                                                 // 0866: 	EOR.W	R3, R5, R4
    temp4 = R3;                                                   // 0867: 	STR	R3, [SP,#960+temp4]
    R5 = (MyUInt32)(cryptData + 0x00000C34);                      // 0868: 	MOV	R5, #(CD_1024_00000C34 - 2483566)
    R4 = R3 >> 24;                                                // 0869: 	LSRS	R4, R3, #24
    R3 = LR;                                                      // 0870: 	MOV	R3, LR
    // 0871: 	ADD	R5, PC
    R4 = *(UInt32*)(R5 + (R4 << 2));                            // 0872: 	LDR.W	R4, [R5,R4,LSL#2]
    R5 = *(UInt32*)(R12 + 196);                                 // 0873: 	LDR.W	R5, [R12,#196]
    R4 = R4 ^ R5;                                                 // 0874: 	EORS	R4, R5
    R2 = R2 ^ R4;                                                 // 0875: 	EORS	R2, R4
    R4 = R8;                                                      // 0876: 	MOV	R4, R8
    temp5 = R2;                                                   // 0877: 	STR	R2, [SP,#960+temp5]
    R2 = LR >> 24;                                                // 0878: 	MOV.W	R2, LR,LSR#24
    R5 = (R0 >> 16) & ((1 << 8) - 1);                             // 0879: 	UBFX.W	R5, R0, #16, #8
    R2 = *(UInt32*)(R6 + (R2 << 2));                            // 0880: 	LDR.W	R2, [R6,R2,LSL#2]
    R5 = *(UInt32*)(R1 + (R5 << 2));                            // 0881: 	LDR.W	R5, [R1,R5,LSL#2]
    R6 = *(UInt32*)(R12 + 184);                                 // 0882: 	LDR.W	R6, [R12,#184]
    R1 = (MyUInt32)(cryptData + 0x000071B0);                      // 0883: 	MOV	R1, #(CD_1024_000071B0 - 2483612)
    // 0884: 	ADD	R1, PC
    R5 = R5 ^ R6;                                                 // 0885: 	EORS	R5, R6
    R2 = R2 ^ R5;                                                 // 0886: 	EORS	R2, R5
    R5 = R8 & 0x000000FF;                                         // 0887: 	UXTB.W	R5, R8
    R5 = *(UInt32*)(R1 + (R5 << 2));                            // 0888: 	LDR.W	R5, [R1,R5,LSL#2]
    R2 = R2 ^ R5;                                                 // 0889: 	EORS	R2, R5
    R5 = (R11 >> 8) & ((1 << 8) - 1);                             // 0890: 	UBFX.W	R5, R11, #8, #8
    R8 = (MyUInt32)(cryptData + 0x0000E030);                      // 0891: 	MOV	R8, #(CD_1024_0000E030 - 2483640)
    // 0892: 	ADD	R8, PC
    R5 = *(UInt32*)(R8 + (R5 << 2));                            // 0893: 	LDR.W	R5, [R8,R5,LSL#2]
    LR = R5 ^ R2;                                                 // 0894: 	EOR.W	LR, R5, R2
    R5 = (LR >> 8) & ((1 << 8) - 1);                              // 0895: 	UBFX.W	R5, LR, #8, #8
    R1 = (MyUInt32)(cryptData + 0x00005940);                      // 0896: 	MOV	R1, #(CD_1024_00005940 - 2483662)
    // 0897: 	ADD	R1, PC
    R5 = *(UInt32*)(R1 + (R5 << 2));                            // 0898: 	LDR.W	R5, [R1,R5,LSL#2]
    R1 = temp5;                                                   // 0899: 	LDR	R1, [SP,#960+temp5]
    R6 = (R3 >> 16) & ((1 << 8) - 1);                             // 0900: 	UBFX.W	R6, R3, #16, #8
    R8 = R5 ^ R1;                                                 // 0901: 	EOR.W	R8, R5, R1
    R1 = (MyUInt32)(cryptData + 0x0000FC48);                      // 0902: 	MOV	R1, #(CD_1024_0000FC48 - 2483700)
    R3 = (R0 >> 8) & ((1 << 8) - 1);                              // 0903: 	UBFX.W	R3, R0, #8, #8
    R5 = *(UInt32*)(R12 + 188);                                 // 0904: 	LDR.W	R5, [R12,#188]
    R0 = R4 >> 24;                                                // 0905: 	LSRS	R0, R4, #24
    R3 = *(UInt32*)(R9 + (R3 << 2));                            // 0906: 	LDR.W	R3, [R9,R3,LSL#2]
    // 0907: 	ADD	R1, PC
    R6 = *(UInt32*)(R1 + (R6 << 2));                            // 0908: 	LDR.W	R6, [R1,R6,LSL#2]
    R1 = R11 & 0x000000FF;                                        // 0909: 	UXTB.W	R1, R11
    R3 = R3 ^ R5;                                                 // 0910: 	EORS	R3, R5
    R3 = R3 ^ R6;                                                 // 0911: 	EORS	R3, R6
    R6 = (MyUInt32)(cryptData + 0x0000A258);                      // 0912: 	MOV	R6, #(CD_1024_0000A258 - 2483730)
    R2 = (MyUInt32)(cryptData + 0x00000834);                      // 0913: 	MOV	R2, #(CD_1024_00000834 - 2483736)
    // 0914: 	ADD	R6, PC
    R0 = *(UInt32*)(R6 + (R0 << 2));                            // 0915: 	LDR.W	R0, [R6,R0,LSL#2]
    // 0916: 	ADD	R2, PC
    R1 = *(UInt32*)(R2 + (R1 << 2));                            // 0917: 	LDR.W	R1, [R2,R1,LSL#2]
    R0 = R0 ^ R3;                                                 // 0918: 	EORS	R0, R3
    R9 = R1 ^ R0;                                                 // 0919: 	EOR.W	R9, R1, R0
    R0 = (R9 >> 16) & ((1 << 8) - 1);                             // 0920: 	UBFX.W	R0, R9, #16, #8
    R11 = (MyUInt32)(cryptData + 0x000149EC);                     // 0921: 	MOV	R11, #(CD_1024_000149EC - 2483760)
    // 0922: 	ADD	R11, PC
    R0 = *(UInt32*)(R11 + (R0 << 2));                           // 0923: 	LDR.W	R0, [R11,R0,LSL#2]
    R0 = R0 ^ R8;                                                 // 0924: 	EOR.W	R0, R0, R8
    temp3 = R0;                                                   // 0925: 	STR	R0, [SP,#960+temp3]
    R0 = R0 & 0x000000FF;                                         // 0926: 	UXTB	R0, R0
    R0 = *(UInt32*)(R10 + (R0 << 2));                           // 0927: 	LDR.W	R0, [R10,R0,LSL#2]
    R10 = temp1;                                                  // 0928: 	LDR.W	R10, [SP,#960+temp1]
    R3 = (R10 >> 8) & ((1 << 8) - 1);                             // 0929: 	UBFX.W	R3, R10, #8, #8
    R1 = (MyUInt32)(cryptData + 0x00013135);                      // 0930: 	MOV	R1, #(CD_1024_00013135 - 2483796)
    R2 = temp4;                                                   // 0931: 	LDR	R2, [SP,#960+temp4]
    // 0932: 	ADD	R1, PC
    R3 = *(UInt32*)(R1 + (R3 << 2));                            // 0933: 	LDR.W	R3, [R1,R3,LSL#2]
    R1 = (MyUInt32)(cryptData + 0x000071B0);                      // 0934: 	MOV	R1, #(CD_1024_000071B0 - 2483816)
    R5 = *(UInt32*)(R12 + 192);                                 // 0935: 	LDR.W	R5, [R12,#192]
    R4 = R2 & 0x000000FF;                                         // 0936: 	UXTB	R4, R2
    // 0937: 	ADD	R1, PC
    R4 = *(UInt32*)(R1 + (R4 << 2));                            // 0938: 	LDR.W	R4, [R1,R4,LSL#2]
    R4 = R4 ^ R5;                                                 // 0939: 	EORS	R4, R5
    R3 = R3 ^ R4;                                                 // 0940: 	EORS	R3, R4
    R4 = (LR >> 16) & ((1 << 8) - 1);                             // 0941: 	UBFX.W	R4, LR, #16, #8
    R1 = (MyUInt32)(cryptData + 0x0000E844);                      // 0942: 	MOV	R1, #(CD_1024_0000E844 - 2483842)
    R8 = (MyUInt32)(cryptData + 0x00000C34);                      // 0943: 	MOV	R8, #(CD_1024_00000C34 - 2483856)
    // 0944: 	ADD	R1, PC
    R5 = *(UInt32*)(R12 + 212);                                 // 0945: 	LDR.W	R5, [R12,#212]
    R4 = *(UInt32*)(R1 + (R4 << 2));                            // 0946: 	LDR.W	R4, [R1,R4,LSL#2]
    // 0947: 	ADD	R8, PC
    R3 = R3 ^ R4;                                                 // 0948: 	EORS	R3, R4
    R4 = R9 >> 24;                                                // 0949: 	MOV.W	R4, R9,LSR#24
    R4 = *(UInt32*)(R8 + (R4 << 2));                            // 0950: 	LDR.W	R4, [R8,R4,LSL#2]
    R3 = R3 ^ R4;                                                 // 0951: 	EORS	R3, R4
    R4 = R3 >> 24;                                                // 0952: 	LSRS	R4, R3, #24
    temp2 = R3;                                                   // 0953: 	STR	R3, [SP,#960+temp2]
    R3 = R10;                                                     // 0954: 	MOV	R3, R10
    R4 = *(UInt32*)(R6 + (R4 << 2));                            // 0955: 	LDR.W	R4, [R6,R4,LSL#2]
    R4 = R4 ^ R5;                                                 // 0956: 	EORS	R4, R5
    R5 = (MyUInt32)(cryptData + 0x00005D40);                      // 0957: 	MOV	R5, #(CD_1024_00005D40 - 2483896)
    R4 = R4 ^ R0;                                                 // 0958: 	EORS	R4, R0
    R0 = R10 >> 24;                                               // 0959: 	MOV.W	R0, R10,LSR#24
    // 0960: 	ADD	R5, PC
    R0 = *(UInt32*)(R5 + (R0 << 2));                            // 0961: 	LDR.W	R0, [R5,R0,LSL#2]
    R5 = (R2 >> 16) & ((1 << 8) - 1);                             // 0962: 	UBFX.W	R5, R2, #16, #8
    R6 = *(UInt32*)(R12 + 200);                                 // 0963: 	LDR.W	R6, [R12,#200]
    R5 = *(UInt32*)(R1 + (R5 << 2));                            // 0964: 	LDR.W	R5, [R1,R5,LSL#2]
    R1 = (MyUInt32)(cryptData + 0x0000C3E0);                      // 0965: 	MOV	R1, #(CD_1024_0000C3E0 - 2483922)
    // 0966: 	ADD	R1, PC
    R5 = R5 ^ R6;                                                 // 0967: 	EORS	R5, R6
    R0 = R0 ^ R5;                                                 // 0968: 	EORS	R0, R5
    R5 = LR & 0x000000FF;                                         // 0969: 	UXTB.W	R5, LR
    R5 = *(UInt32*)(R1 + (R5 << 2));                            // 0970: 	LDR.W	R5, [R1,R5,LSL#2]
    R0 = R0 ^ R5;                                                 // 0971: 	EORS	R0, R5
    R5 = (R9 >> 8) & ((1 << 8) - 1);                              // 0972: 	UBFX.W	R5, R9, #8, #8
    R1 = (MyUInt32)(cryptData + 0x000075D8);                      // 0973: 	MOV	R1, #(CD_1024_000075D8 - 2483950)
    // 0974: 	ADD	R1, PC
    R5 = *(UInt32*)(R1 + (R5 << 2));                            // 0975: 	LDR.W	R5, [R1,R5,LSL#2]
    R1 = R9 & 0x000000FF;                                         // 0976: 	UXTB.W	R1, R9
    R10 = R5 ^ R0;                                                // 0977: 	EOR.W	R10, R5, R0
    R5 = (R10 >> 8) & ((1 << 8) - 1);                             // 0978: 	UBFX.W	R5, R10, #8, #8
    R0 = (MyUInt32)(cryptData + 0x0000E030);                      // 0979: 	MOV	R0, #(CD_1024_0000E030 - 2483976)
    // 0980: 	ADD	R0, PC
    R5 = *(UInt32*)(R0 + (R5 << 2));                            // 0981: 	LDR.W	R5, [R0,R5,LSL#2]
    R0 = R5 ^ R4;                                                 // 0982: 	EOR.W	R0, R5, R4
    temp5 = R0;                                                   // 0983: 	STR	R0, [SP,#960+temp5]
    R6 = (R3 >> 16) & ((1 << 8) - 1);                             // 0984: 	UBFX.W	R6, R3, #16, #8
    R5 = (R2 >> 8) & ((1 << 8) - 1);                              // 0985: 	UBFX.W	R5, R2, #8, #8
    R0 = (MyUInt32)(cryptData + 0x00013135);                      // 0986: 	MOV	R0, #(CD_1024_00013135 - 2484022)
    R2 = LR >> 24;                                                // 0987: 	MOV.W	R2, LR,LSR#24
    LR = R8;                                                      // 0988: 	MOV	LR, R8
    R4 = *(UInt32*)(R12 + 204);                                 // 0989: 	LDR.W	R4, [R12,#204]
    R6 = *(UInt32*)(R11 + (R6 << 2));                           // 0990: 	LDR.W	R6, [R11,R6,LSL#2]
    R2 = *(UInt32*)(LR + (R2 << 2));                            // 0991: 	LDR.W	R2, [LR,R2,LSL#2]
    // 0992: 	ADD	R0, PC
    R5 = *(UInt32*)(R0 + (R5 << 2));                            // 0993: 	LDR.W	R5, [R0,R5,LSL#2]
    R5 = R5 ^ R4;                                                 // 0994: 	EORS	R5, R4
    R6 = R6 ^ R5;                                                 // 0995: 	EORS	R6, R5
    R2 = R2 ^ R6;                                                 // 0996: 	EORS	R2, R6
    R6 = (MyUInt32)(cryptData + 0x00000834);                      // 0997: 	MOV	R6, #(CD_1024_00000834 - 2484042)
    // 0998: 	ADD	R6, PC
    R1 = *(UInt32*)(R6 + (R1 << 2));                            // 0999: 	LDR.W	R1, [R6,R1,LSL#2]
    R9 = R1 ^ R2;                                                 // 1000: 	EOR.W	R9, R1, R2
    R2 = (R9 >> 16) & ((1 << 8) - 1);                             // 1001: 	UBFX.W	R2, R9, #16, #8
    R1 = temp5;                                                   // 1002: 	LDR	R1, [SP,#960+temp5]
    R3 = temp3;                                                   // 1003: 	LDR	R3, [SP,#960+temp3]
    R2 = *(UInt32*)(R11 + (R2 << 2));                           // 1004: 	LDR.W	R2, [R11,R2,LSL#2]
    R1 = R1 ^ R2;                                                 // 1005: 	EORS	R1, R2
    R2 = R1 & 0x000000FF;                                         // 1006: 	UXTB	R2, R1
    temp1 = R1;                                                   // 1007: 	STR	R1, [SP,#960+temp1]
    R2 = *(UInt32*)(R6 + (R2 << 2));                            // 1008: 	LDR.W	R2, [R6,R2,LSL#2]
    R6 = (R3 >> 8) & ((1 << 8) - 1);                              // 1009: 	UBFX.W	R6, R3, #8, #8
    R6 = *(UInt32*)(R0 + (R6 << 2));                            // 1010: 	LDR.W	R6, [R0,R6,LSL#2]
    R0 = temp2;                                                   // 1011: 	LDR	R0, [SP,#960+temp2]
    R11 = (MyUInt32)(cryptData + 0x0000BAA4);                     // 1012: 	MOV	R11, #(CD_1024_0000BAA4 - 2484096)
    R4 = *(UInt32*)(R12 + 208);                                 // 1013: 	LDR.W	R4, [R12,#208]
    // 1014: 	ADD	R11, PC
    R5 = R0 & 0x000000FF;                                         // 1015: 	UXTB	R5, R0
    R5 = *(UInt32*)(R11 + (R5 << 2));                           // 1016: 	LDR.W	R5, [R11,R5,LSL#2]
    R5 = R5 ^ R4;                                                 // 1017: 	EORS	R5, R4
    R6 = R6 ^ R5;                                                 // 1018: 	EORS	R6, R5
    R5 = (R10 >> 16) & ((1 << 8) - 1);                            // 1019: 	UBFX.W	R5, R10, #16, #8
    R4 = (MyUInt32)(cryptData + 0x00005540);                      // 1020: 	MOV	R4, #(CD_1024_00005540 - 2484124)
    R8 = (MyUInt32)(cryptData + 0x000028F8);                      // 1021: 	MOV	R8, #(CD_1024_000028F8 - 2484134)
    // 1022: 	ADD	R4, PC
    R5 = *(UInt32*)(R4 + (R5 << 2));                            // 1023: 	LDR.W	R5, [R4,R5,LSL#2]
    // 1024: 	ADD	R8, PC
    R1 = R8;                                                      // 1025: 	MOV	R1, R8
    R6 = R6 ^ R5;                                                 // 1026: 	EORS	R6, R5
    R5 = R9 >> 24;                                                // 1027: 	MOV.W	R5, R9,LSR#24
    R5 = *(UInt32*)(R1 + (R5 << 2));                            // 1028: 	LDR.W	R5, [R1,R5,LSL#2]
    R4 = R5 ^ R6;                                                 // 1029: 	EOR.W	R4, R5, R6
    R6 = R0;                                                      // 1030: 	MOV	R6, R0
    R5 = R4 >> 24;                                                // 1031: 	LSRS	R5, R4, #24
    temp4 = R4;                                                   // 1032: 	STR	R4, [SP,#960+temp4]
    R4 = *(UInt32*)(R12 + 228);                                 // 1033: 	LDR.W	R4, [R12,#228]
    R5 = *(UInt32*)(LR + (R5 << 2));                            // 1034: 	LDR.W	R5, [LR,R5,LSL#2]
    R5 = R5 ^ R4;                                                 // 1035: 	EORS	R5, R4
    R2 = R2 ^ R5;                                                 // 1036: 	EORS	R2, R5
    temp5 = R2;                                                   // 1037: 	STR	R2, [SP,#960+temp5]
    R4 = (R0 >> 16) & ((1 << 8) - 1);                             // 1038: 	UBFX.W	R4, R0, #16, #8
    R5 = (MyUInt32)(cryptData + 0x00015E08);                      // 1039: 	MOV	R5, #(CD_1024_00015E08 - 2484190)
    R2 = R3 >> 24;                                                // 1040: 	LSRS	R2, R3, #24
    R2 = *(UInt32*)(R1 + (R2 << 2));                            // 1041: 	LDR.W	R2, [R1,R2,LSL#2]
    // 1042: 	ADD	R5, PC
    R4 = *(UInt32*)(R5 + (R4 << 2));                            // 1043: 	LDR.W	R4, [R5,R4,LSL#2]
    R5 = *(UInt32*)(R12 + 216);                                 // 1044: 	LDR.W	R5, [R12,#216]
    R4 = R4 ^ R5;                                                 // 1045: 	EORS	R4, R5
    R2 = R2 ^ R4;                                                 // 1046: 	EORS	R2, R4
    R4 = R10 & 0x000000FF;                                        // 1047: 	UXTB.W	R4, R10
    R4 = *(UInt32*)(R11 + (R4 << 2));                           // 1048: 	LDR.W	R4, [R11,R4,LSL#2]
    R2 = R2 ^ R4;                                                 // 1049: 	EORS	R2, R4
    R4 = (R9 >> 8) & ((1 << 8) - 1);                              // 1050: 	UBFX.W	R4, R9, #8, #8
    R1 = (MyUInt32)(cryptData + 0x0000E030);                      // 1051: 	MOV	R1, #(CD_1024_0000E030 - 2484226)
    // 1052: 	ADD	R1, PC
    R4 = *(UInt32*)(R1 + (R4 << 2));                            // 1053: 	LDR.W	R4, [R1,R4,LSL#2]
    LR = R4 ^ R2;                                                 // 1054: 	EOR.W	LR, R4, R2
    R4 = (LR >> 8) & ((1 << 8) - 1);                              // 1055: 	UBFX.W	R4, LR, #8, #8
    R8 = (MyUInt32)(cryptData + 0x00013135);                      // 1056: 	MOV	R8, #(CD_1024_00013135 - 2484250)
    R0 = temp5;                                                   // 1057: 	LDR	R0, [SP,#960+temp5]
    // 1058: 	ADD	R8, PC
    R4 = *(UInt32*)(R8 + (R4 << 2));                            // 1059: 	LDR.W	R4, [R8,R4,LSL#2]
    R2 = R4 ^ R0;                                                 // 1060: 	EOR.W	R2, R4, R0
    R4 = (R3 >> 16) & ((1 << 8) - 1);                             // 1061: 	UBFX.W	R4, R3, #16, #8
    R0 = (MyUInt32)(cryptData + 0x000149EC);                      // 1062: 	MOV	R0, #(CD_1024_000149EC - 2484278)
    R3 = (R6 >> 8) & ((1 << 8) - 1);                              // 1063: 	UBFX.W	R3, R6, #8, #8
    R6 = R11;                                                     // 1064: 	MOV	R6, R11
    // 1065: 	ADD	R0, PC
    R4 = *(UInt32*)(R0 + (R4 << 2));                            // 1066: 	LDR.W	R4, [R0,R4,LSL#2]
    R0 = (MyUInt32)(cryptData + 0x0000CC1C);                      // 1067: 	MOV	R0, #(CD_1024_0000CC1C - 2484300)
    R5 = *(UInt32*)(R12 + 220);                                 // 1068: 	LDR.W	R5, [R12,#220]
    R1 = (MyUInt32)(cryptData + 0x0000A258);                      // 1069: 	MOV	R1, #(CD_1024_0000A258 - 2484314)
    // 1070: 	ADD	R0, PC
    R3 = *(UInt32*)(R0 + (R3 << 2));                            // 1071: 	LDR.W	R3, [R0,R3,LSL#2]
    R0 = R10 >> 24;                                               // 1072: 	MOV.W	R0, R10,LSR#24
    // 1073: 	ADD	R1, PC
    R0 = *(UInt32*)(R1 + (R0 << 2));                            // 1074: 	LDR.W	R0, [R1,R0,LSL#2]
    R1 = R9 & 0x000000FF;                                         // 1075: 	UXTB.W	R1, R9
    R9 = R8;                                                      // 1076: 	MOV	R9, R8
    R1 = *(UInt32*)(R6 + (R1 << 2));                            // 1077: 	LDR.W	R1, [R6,R1,LSL#2]
    R3 = R3 ^ R5;                                                 // 1078: 	EORS	R3, R5
    R3 = R3 ^ R4;                                                 // 1079: 	EORS	R3, R4
    R0 = R0 ^ R3;                                                 // 1080: 	EORS	R0, R3
    R3 = R1 ^ R0;                                                 // 1081: 	EOR.W	R3, R1, R0
    R0 = (R3 >> 16) & ((1 << 8) - 1);                             // 1082: 	UBFX.W	R0, R3, #16, #8
    R11 = (MyUInt32)(cryptData + 0x0000FC48);                     // 1083: 	MOV	R11, #(CD_1024_0000FC48 - 2484352)
    // 1084: 	ADD	R11, PC
    R0 = *(UInt32*)(R11 + (R0 << 2));                           // 1085: 	LDR.W	R0, [R11,R0,LSL#2]
    R0 = R0 ^ R2;                                                 // 1086: 	EORS	R0, R2
    R2 = temp1;                                                   // 1087: 	LDR	R2, [SP,#960+temp1]
    temp3 = R0;                                                   // 1088: 	STR	R0, [SP,#960+temp3]
    R0 = R0 & 0x000000FF;                                         // 1089: 	UXTB	R0, R0
    R0 = *(UInt32*)(R6 + (R0 << 2));                            // 1090: 	LDR.W	R0, [R6,R0,LSL#2]
    R1 = (R2 >> 8) & ((1 << 8) - 1);                              // 1091: 	UBFX.W	R1, R2, #8, #8
    R6 = temp4;                                                   // 1092: 	LDR	R6, [SP,#960+temp4]
    R4 = (MyUInt32)(cryptData + 0x0000C3E0);                      // 1093: 	MOV	R4, #(CD_1024_0000C3E0 - 2484388)
    R1 = *(UInt32*)(R8 + (R1 << 2));                            // 1094: 	LDR.W	R1, [R8,R1,LSL#2]
    // 1095: 	ADD	R4, PC
    R5 = R6 & 0x000000FF;                                         // 1096: 	UXTB	R5, R6
    R5 = *(UInt32*)(R4 + (R5 << 2));                            // 1097: 	LDR.W	R5, [R4,R5,LSL#2]
    R4 = *(UInt32*)(R12 + 224);                                 // 1098: 	LDR.W	R4, [R12,#224]
    R5 = R5 ^ R4;                                                 // 1099: 	EORS	R5, R4
    R1 = R1 ^ R5;                                                 // 1100: 	EORS	R1, R5
    R5 = (LR >> 16) & ((1 << 8) - 1);                             // 1101: 	UBFX.W	R5, LR, #16, #8
    R10 = (MyUInt32)(cryptData + 0x0000E844);                     // 1102: 	MOV	R10, #(CD_1024_0000E844 - 2484420)
    R4 = (MyUInt32)(cryptData + 0x00000C34);                      // 1103: 	MOV	R4, #(CD_1024_00000C34 - 2484428)
    // 1104: 	ADD	R10, PC
    R11 = R10;                                                    // 1105: 	MOV	R11, R10
    // 1106: 	ADD	R4, PC
    R5 = *(UInt32*)(R11 + (R5 << 2));                           // 1107: 	LDR.W	R5, [R11,R5,LSL#2]
    R1 = R1 ^ R5;                                                 // 1108: 	EORS	R1, R5
    R5 = R3 >> 24;                                                // 1109: 	LSRS	R5, R3, #24
    R5 = *(UInt32*)(R4 + (R5 << 2));                            // 1110: 	LDR.W	R5, [R4,R5,LSL#2]
    R10 = R5 ^ R1;                                                // 1111: 	EOR.W	R10, R5, R1
    R1 = (MyUInt32)(cryptData + 0x0000D01C);                      // 1112: 	MOV	R1, #(CD_1024_0000D01C - 2484462)
    R5 = R10 >> 24;                                               // 1113: 	MOV.W	R5, R10,LSR#24
    R4 = *(UInt32*)(R12 + 244);                                 // 1114: 	LDR.W	R4, [R12,#244]
    // 1115: 	ADD	R1, PC
    R5 = *(UInt32*)(R1 + (R5 << 2));                            // 1116: 	LDR.W	R5, [R1,R5,LSL#2]
    R1 = (MyUInt32)(cryptData + 0x00005D40);                      // 1117: 	MOV	R1, #(CD_1024_00005D40 - 2484476)
    // 1118: 	ADD	R1, PC
    R5 = R5 ^ R4;                                                 // 1119: 	EORS	R5, R4
    R4 = (R6 >> 16) & ((1 << 8) - 1);                             // 1120: 	UBFX.W	R4, R6, #16, #8
    R5 = R5 ^ R0;                                                 // 1121: 	EORS	R5, R0
    R0 = R2 >> 24;                                                // 1122: 	LSRS	R0, R2, #24
    R0 = *(UInt32*)(R1 + (R0 << 2));                            // 1123: 	LDR.W	R0, [R1,R0,LSL#2]
    R1 = (MyUInt32)(cryptData + 0x00005540);                      // 1124: 	MOV	R1, #(CD_1024_00005540 - 2484500)
    // 1125: 	ADD	R1, PC
    R4 = *(UInt32*)(R1 + (R4 << 2));                            // 1126: 	LDR.W	R4, [R1,R4,LSL#2]
    R1 = *(UInt32*)(R12 + 232);                                 // 1127: 	LDR.W	R1, [R12,#232]
    R8 = (MyUInt32)(cryptData + 0x0000EC44);                      // 1128: 	MOV	R8, #(CD_1024_0000EC44 - 2484518)
    // 1129: 	ADD	R8, PC
    R1 = R1 ^ R4;                                                 // 1130: 	EORS	R1, R4
    R0 = R0 ^ R1;                                                 // 1131: 	EORS	R0, R1
    R1 = LR & 0x000000FF;                                         // 1132: 	UXTB.W	R1, LR
    R1 = *(UInt32*)(R8 + (R1 << 2));                            // 1133: 	LDR.W	R1, [R8,R1,LSL#2]
    R0 = R0 ^ R1;                                                 // 1134: 	EORS	R0, R1
    R1 = (R3 >> 8) & ((1 << 8) - 1);                              // 1135: 	UBFX.W	R1, R3, #8, #8
    R3 = R3 & 0x000000FF;                                         // 1136: 	UXTB	R3, R3
    R1 = *(UInt32*)(R9 + (R1 << 2));                            // 1137: 	LDR.W	R1, [R9,R1,LSL#2]
    R9 = R1 ^ R0;                                                 // 1138: 	EOR.W	R9, R1, R0
    R1 = (R9 >> 8) & ((1 << 8) - 1);                              // 1139: 	UBFX.W	R1, R9, #8, #8
    R4 = (MyUInt32)(cryptData + 0x000075D8);                      // 1140: 	MOV	R4, #(CD_1024_000075D8 - 2484560)
    // 1141: 	ADD	R4, PC
    R1 = *(UInt32*)(R4 + (R1 << 2));                            // 1142: 	LDR.W	R1, [R4,R1,LSL#2]
    R1 = R1 ^ R5;                                                 // 1143: 	EORS	R1, R5
    R5 = (R2 >> 16) & ((1 << 8) - 1);                             // 1144: 	UBFX.W	R5, R2, #16, #8
    R4 = (MyUInt32)(cryptData + 0x00015E08);                      // 1145: 	MOV	R4, #(CD_1024_00015E08 - 2484588)
    R2 = LR >> 24;                                                // 1146: 	MOV.W	R2, LR,LSR#24
    R6 = (R6 >> 8) & ((1 << 8) - 1);                              // 1147: 	UBFX.W	R6, R6, #8, #8
    // 1148: 	ADD	R4, PC
    R5 = *(UInt32*)(R4 + (R5 << 2));                            // 1149: 	LDR.W	R5, [R4,R5,LSL#2]
    R4 = (MyUInt32)(cryptData + 0x00005940);                      // 1150: 	MOV	R4, #(CD_1024_00005940 - 2484602)
    // 1151: 	ADD	R4, PC
    R6 = *(UInt32*)(R4 + (R6 << 2));                            // 1152: 	LDR.W	R6, [R4,R6,LSL#2]
    R4 = *(UInt32*)(R12 + 236);                                 // 1153: 	LDR.W	R4, [R12,#236]
    R6 = R6 ^ R4;                                                 // 1154: 	EORS	R6, R4
    R6 = R6 ^ R5;                                                 // 1155: 	EORS	R6, R5
    R5 = (MyUInt32)(cryptData + 0x000028F8);                      // 1156: 	MOV	R5, #(CD_1024_000028F8 - 2484632)
    LR = (MyUInt32)(cryptData + 0x0000BAA4);                      // 1157: 	MOV	LR, #(CD_1024_0000BAA4 - 2484638)
    // 1158: 	ADD	R5, PC
    R2 = *(UInt32*)(R5 + (R2 << 2));                            // 1159: 	LDR.W	R2, [R5,R2,LSL#2]
    // 1160: 	ADD	LR, PC
    R3 = *(UInt32*)(LR + (R3 << 2));                            // 1161: 	LDR.W	R3, [LR,R3,LSL#2]
    R2 = R2 ^ R6;                                                 // 1162: 	EORS	R2, R6
    R6 = R3 ^ R2;                                                 // 1163: 	EOR.W	R6, R3, R2
    R3 = R10 & 0x000000FF;                                        // 1164: 	UXTB.W	R3, R10
    R2 = (R6 >> 16) & ((1 << 8) - 1);                             // 1165: 	UBFX.W	R2, R6, #16, #8
    R3 = *(UInt32*)(R8 + (R3 << 2));                            // 1166: 	LDR.W	R3, [R8,R3,LSL#2]
    R2 = *(UInt32*)(R11 + (R2 << 2));                           // 1167: 	LDR.W	R2, [R11,R2,LSL#2]
    R11 = R2 ^ R1;                                                // 1168: 	EOR.W	R11, R2, R1
    R1 = (R11 >> 16) & ((1 << 8) - 1);                            // 1169: 	UBFX.W	R1, R11, #16, #8
    R2 = (MyUInt32)(cryptData + 0x0000D41C);                      // 1170: 	MOV	R2, #(CD_1024_0000D41C - 2484684)
    R0 = temp3;                                                   // 1171: 	LDR	R0, [SP,#960+temp3]
    // 1172: 	ADD	R2, PC
    R5 = *(UInt32*)(R2 + (R1 << 2));                            // 1173: 	LDR.W	R5, [R2,R1,LSL#2]
    R2 = (R0 >> 8) & ((1 << 8) - 1);                              // 1174: 	UBFX.W	R2, R0, #8, #8
    R1 = (MyUInt32)(cryptData + 0x00013135);                      // 1175: 	MOV	R1, #(CD_1024_00013135 - 2484706)
    R4 = *(UInt32*)(R12 + 240);                                 // 1176: 	LDR.W	R4, [R12,#240]
    // 1177: 	ADD	R1, PC
    R2 = *(UInt32*)(R1 + (R2 << 2));                            // 1178: 	LDR.W	R2, [R1,R2,LSL#2]
    R3 = R3 ^ R4;                                                 // 1179: 	EORS	R3, R4
    R2 = R2 ^ R3;                                                 // 1180: 	EORS	R2, R3
    R3 = (R9 >> 16) & ((1 << 8) - 1);                             // 1181: 	UBFX.W	R3, R9, #16, #8
    R1 = (MyUInt32)(cryptData + 0x0000FC48);                      // 1182: 	MOV	R1, #(CD_1024_0000FC48 - 2484728)
    // 1183: 	ADD	R1, PC
    R3 = *(UInt32*)(R1 + (R3 << 2));                            // 1184: 	LDR.W	R3, [R1,R3,LSL#2]
    R1 = (MyUInt32)(cryptData + 0x0000A258);                      // 1185: 	MOV	R1, #(CD_1024_0000A258 - 2484742)
    // 1186: 	ADD	R1, PC
    R2 = R2 ^ R3;                                                 // 1187: 	EORS	R2, R3
    R3 = R6 >> 24;                                                // 1188: 	LSRS	R3, R6, #24
    R3 = *(UInt32*)(R1 + (R3 << 2));                            // 1189: 	LDR.W	R3, [R1,R3,LSL#2]
    R8 = R3 ^ R2;                                                 // 1190: 	EOR.W	R8, R3, R2
    R2 = (R8 >> 8) & ((1 << 8) - 1);                              // 1191: 	UBFX.W	R2, R8, #8, #8
    R4 = (MyUInt32)(cryptData + 0x00001C84);                      // 1192: 	MOV	R4, #(CD_1024_00001C84 - 2484768)
    // 1193: 	ADD	R4, PC
    R2 = *(UInt32*)(R4 + (R2 << 2));                            // 1194: 	LDR.W	R2, [R4,R2,LSL#2]
    R4 = *(UInt32*)(R12 + 268);                                 // 1195: 	LDR.W	R4, [R12,#268]
    R2 = R2 ^ R4;                                                 // 1196: 	EORS	R2, R4
    R4 = (MyUInt32)(cryptData + 0x00005D40);                      // 1197: 	MOV	R4, #(CD_1024_00005D40 - 2484794)
    R3 = R5 ^ R2;                                                 // 1198: 	EOR.W	R3, R5, R2
    R2 = R0 >> 24;                                                // 1199: 	LSRS	R2, R0, #24
    // 1200: 	ADD	R4, PC
    R2 = *(UInt32*)(R4 + (R2 << 2));                            // 1201: 	LDR.W	R2, [R4,R2,LSL#2]
    R4 = (R10 >> 16) & ((1 << 8) - 1);                            // 1202: 	UBFX.W	R4, R10, #16, #8
    R5 = (MyUInt32)(cryptData + 0x000149EC);                      // 1203: 	MOV	R5, #(CD_1024_000149EC - 2484812)
    // 1204: 	ADD	R5, PC
    R4 = *(UInt32*)(R5 + (R4 << 2));                            // 1205: 	LDR.W	R4, [R5,R4,LSL#2]
    R5 = *(UInt32*)(R12 + 248);                                 // 1206: 	LDR.W	R5, [R12,#248]
    R4 = R4 ^ R5;                                                 // 1207: 	EORS	R4, R5
    R2 = R2 ^ R4;                                                 // 1208: 	EORS	R2, R4
    R4 = R9 & 0x000000FF;                                         // 1209: 	UXTB.W	R4, R9
    R4 = *(UInt32*)(LR + (R4 << 2));                            // 1210: 	LDR.W	R4, [LR,R4,LSL#2]
    R2 = R2 ^ R4;                                                 // 1211: 	EORS	R2, R4
    R4 = (R6 >> 8) & ((1 << 8) - 1);                              // 1212: 	UBFX.W	R4, R6, #8, #8
    R5 = (MyUInt32)(cryptData + 0x0000E030);                      // 1213: 	MOV	R5, #(CD_1024_0000E030 - 2484848)
    // 1214: 	ADD	R5, PC
    R4 = *(UInt32*)(R5 + (R4 << 2));                            // 1215: 	LDR.W	R4, [R5,R4,LSL#2]
    R5 = (MyUInt32)(cryptData + 0x000145EC);                      // 1216: 	MOV	R5, #(CD_1024_000145EC - 2484862)
    // 1217: 	ADD	R5, PC
    LR = R4 ^ R2;                                                 // 1218: 	EOR.W	LR, R4, R2
    R4 = LR >> 24;                                                // 1219: 	MOV.W	R4, LR,LSR#24
    R4 = *(UInt32*)(R5 + (R4 << 2));                            // 1220: 	LDR.W	R4, [R5,R4,LSL#2]
    R5 = (R0 >> 16) & ((1 << 8) - 1);                             // 1221: 	UBFX.W	R5, R0, #16, #8
    R0 = R9 >> 24;                                                // 1222: 	MOV.W	R0, R9,LSR#24
    R0 = *(UInt32*)(R1 + (R0 << 2));                            // 1223: 	LDR.W	R0, [R1,R0,LSL#2]
    R2 = R4 ^ R3;                                                 // 1224: 	EOR.W	R2, R4, R3
    R3 = (MyUInt32)(cryptData + 0x00005540);                      // 1225: 	MOV	R3, #(CD_1024_00005540 - 2484904)
    R4 = (R10 >> 8) & ((1 << 8) - 1);                             // 1226: 	UBFX.W	R4, R10, #8, #8
    // 1227: 	ADD	R3, PC
    R5 = *(UInt32*)(R3 + (R5 << 2));                            // 1228: 	LDR.W	R5, [R3,R5,LSL#2]
    R3 = (MyUInt32)(cryptData + 0x000075D8);                      // 1229: 	MOV	R3, #(CD_1024_000075D8 - 2484918)
    // 1230: 	ADD	R3, PC
    R4 = *(UInt32*)(R3 + (R4 << 2));                            // 1231: 	LDR.W	R4, [R3,R4,LSL#2]
    R3 = *(UInt32*)(R12 + 252);                                 // 1232: 	LDR.W	R3, [R12,#252]
    R1 = (MyUInt32)(cryptData + 0x0000EC44);                      // 1233: 	MOV	R1, #(CD_1024_0000EC44 - 2484936)
    // 1234: 	ADD	R1, PC
    R3 = R3 ^ R4;                                                 // 1235: 	EORS	R3, R4
    R3 = R3 ^ R5;                                                 // 1236: 	EORS	R3, R5
    R0 = R0 ^ R3;                                                 // 1237: 	EORS	R0, R3
    R3 = R6 & 0x000000FF;                                         // 1238: 	UXTB	R3, R6
    R3 = *(UInt32*)(R1 + (R3 << 2));                            // 1239: 	LDR.W	R3, [R1,R3,LSL#2]
    R6 = R3 ^ R0;                                                 // 1240: 	EOR.W	R6, R3, R0
    R3 = (MyUInt32)(cryptData + 0x000024F8);                      // 1241: 	MOV	R3, #(CD_1024_000024F8 - 2484964)
    R0 = R6 & 0x000000FF;                                         // 1242: 	UXTB	R0, R6
    // 1243: 	ADD	R3, PC
    R0 = *(UInt32*)(R3 + (R0 << 2));                            // 1244: 	LDR.W	R0, [R3,R0,LSL#2]
    R0 = R0 ^ R2;                                                 // 1245: 	EORS	R0, R2
    R1 = (R0 >> 8) & ((1 << 8) - 1);                              // 1246: 	UBFX.W	R1, R0, #8, #8
    R3 = (MyUInt32)(cryptData + 0x00010048);                      // 1247: 	MOV	R3, #(CD_1024_00010048 - 2484992)
    R5 = (MyUInt32)(cryptData + 0x00001060);                      // 1248: 	MOV	R5, #(CD_1024_00001060 - 2485000)
    // 1249: 	ADD	R3, PC
    R1 = *(UInt32*)(R3 + (R1 << 2));                            // 1250: 	LDR.W	R1, [R3,R1,LSL#2]
    R3 = R0 & 0x000000FF;                                         // 1251: 	UXTB	R3, R0
    // 1252: 	ADD	R5, PC
    R3 = *(UInt32*)(R5 + (R3 << 2));                            // 1253: 	LDR.W	R3, [R5,R3,LSL#2]
    R5 = *(UInt32*)(R12 + 284);                                 // 1254: 	LDR.W	R5, [R12,#284]
    R3 = R3 ^ R5;                                                 // 1255: 	EORS	R3, R5
    R1 = R1 ^ R3;                                                 // 1256: 	EORS	R1, R3
    R3 = (R0 >> 16) & ((1 << 8) - 1);                             // 1257: 	UBFX.W	R3, R0, #16, #8
    R5 = (MyUInt32)(cryptData + 0x00004938);                      // 1258: 	MOV	R5, #(CD_1024_00004938 - 2485028)
    R0 = R0 >> 24;                                                // 1259: 	LSRS	R0, R0, #24
    // 1260: 	ADD	R5, PC
    R3 = *(UInt32*)(R5 + (R3 << 2));                            // 1261: 	LDR.W	R3, [R5,R3,LSL#2]
    R1 = R1 ^ R3;                                                 // 1262: 	EORS	R1, R3
    R3 = (MyUInt32)(cryptData + 0x0000699C);                      // 1263: 	MOV	R3, #(CD_1024_0000699C - 2485044)
    // 1264: 	ADD	R3, PC
    R0 = *(UInt32*)(R3 + (R0 << 2));                            // 1265: 	LDR.W	R0, [R3,R0,LSL#2]
    R3 = (MyUInt32)(cryptData + 0x00015A04);                      // 1266: 	MOV	R3, #(CD_1024_00015A04 - 2485058)
    // 1267: 	ADD	R3, PC
    R10 = R0 ^ R1;                                                // 1268: 	EOR.W	R10, R0, R1
    R0 = R11 >> 24;                                               // 1269: 	MOV.W	R0, R11,LSR#24
    R0 = *(UInt32*)(R3 + (R0 << 2));                            // 1270: 	LDR.W	R0, [R3,R0,LSL#2]
    R3 = (R8 >> 16) & ((1 << 8) - 1);                             // 1271: 	UBFX.W	R3, R8, #16, #8
    R5 = (MyUInt32)(cryptData + 0x00011CD4);                      // 1272: 	MOV	R5, #(CD_1024_00011CD4 - 2485084)
    // 1273: 	ADD	R5, PC
    R3 = *(UInt32*)(R5 + (R3 << 2));                            // 1274: 	LDR.W	R3, [R5,R3,LSL#2]
    R5 = *(UInt32*)(R12 + 264);                                 // 1275: 	LDR.W	R5, [R12,#264]
    R3 = R3 ^ R5;                                                 // 1276: 	EORS	R3, R5
    R5 = (MyUInt32)(cryptData + 0x00007DDC);                      // 1277: 	MOV	R5, #(CD_1024_00007DDC - 2485110)
    R0 = R0 ^ R3;                                                 // 1278: 	EORS	R0, R3
    R3 = LR & 0x000000FF;                                         // 1279: 	UXTB.W	R3, LR
    // 1280: 	ADD	R5, PC
    R3 = *(UInt32*)(R5 + (R3 << 2));                            // 1281: 	LDR.W	R3, [R5,R3,LSL#2]
    R0 = R0 ^ R3;                                                 // 1282: 	EORS	R0, R3
    R3 = (R6 >> 8) & ((1 << 8) - 1);                              // 1283: 	UBFX.W	R3, R6, #8, #8
    R5 = (MyUInt32)(cryptData + 0x0000BED5);                      // 1284: 	MOV	R5, #(CD_1024_0000BED5 - 2485130)
    // 1285: 	ADD	R5, PC
    R3 = *(UInt32*)(R5 + (R3 << 2));                            // 1286: 	LDR.W	R3, [R5,R3,LSL#2]
    R0 = R0 ^ R3;                                                 // 1287: 	EORS	R0, R3
    R3 = (R0 >> 8) & ((1 << 8) - 1);                              // 1288: 	UBFX.W	R3, R0, #8, #8
    R5 = (MyUInt32)(cryptData + 0x0000A658);                      // 1289: 	MOV	R5, #(CD_1024_0000A658 - 2485158)
    R4 = (MyUInt32)(cryptData + 0x00001464);                      // 1290: 	MOV	R4, #(CD_1024_00001464 - 2485166)
    // 1291: 	ADD	R5, PC
    R3 = *(UInt32*)(R5 + (R3 << 2));                            // 1292: 	LDR.W	R3, [R5,R3,LSL#2]
    R5 = R0 & 0x000000FF;                                         // 1293: 	UXTB	R5, R0
    // 1294: 	ADD	R4, PC
    R5 = *(UInt32*)(R4 + (R5 << 2));                            // 1295: 	LDR.W	R5, [R4,R5,LSL#2]
    R4 = *(UInt32*)(R12 + 280);                                 // 1296: 	LDR.W	R4, [R12,#280]
    R5 = R5 ^ R4;                                                 // 1297: 	EORS	R5, R4
    R3 = R3 ^ R5;                                                 // 1298: 	EORS	R3, R5
    R5 = (R0 >> 16) & ((1 << 8) - 1);                             // 1299: 	UBFX.W	R5, R0, #16, #8
    R4 = (MyUInt32)(cryptData + 0x00000000);                      // 1300: 	MOV	R4, #(CD_1024_00000000 - 2485194)
    R0 = R0 >> 24;                                                // 1301: 	LSRS	R0, R0, #24
    // 1302: 	ADD	R4, PC
    R5 = *(UInt32*)(R4 + (R5 << 2));                            // 1303: 	LDR.W	R5, [R4,R5,LSL#2]
    R3 = R3 ^ R5;                                                 // 1304: 	EORS	R3, R5
    R5 = (MyUInt32)(cryptData + 0x0000DC2C);                      // 1305: 	MOV	R5, #(CD_1024_0000DC2C - 2485210)
    // 1306: 	ADD	R5, PC
    R0 = *(UInt32*)(R5 + (R0 << 2));                            // 1307: 	LDR.W	R0, [R5,R0,LSL#2]
    R5 = R0 ^ R3;                                                 // 1308: 	EOR.W	R5, R0, R3
    R3 = (MyUInt32)(cryptData + 0x0000AA58);                      // 1309: 	MOV	R3, #(CD_1024_0000AA58 - 2485240)
    R0 = R11 & 0x000000FF;                                        // 1310: 	UXTB.W	R0, R11
    R4 = (MyUInt32)(cryptData + 0x00011099);                      // 1311: 	MOV	R4, #(CD_1024_00011099 - 2485250)
    // 1312: 	ADD	R3, PC
    R0 = *(UInt32*)(R3 + (R0 << 2));                            // 1313: 	LDR.W	R0, [R3,R0,LSL#2]
    R3 = R8 >> 24;                                                // 1314: 	MOV.W	R3, R8,LSR#24
    // 1315: 	ADD	R4, PC
    R3 = *(UInt32*)(R4 + (R3 << 2));                            // 1316: 	LDR.W	R3, [R4,R3,LSL#2]
    R4 = *(UInt32*)(R12 + 260);                                 // 1317: 	LDR.W	R4, [R12,#260]
    R3 = R3 ^ R4;                                                 // 1318: 	EORS	R3, R4
    R0 = R0 ^ R3;                                                 // 1319: 	EORS	R0, R3
    R3 = (LR >> 8) & ((1 << 8) - 1);                              // 1320: 	UBFX.W	R3, LR, #8, #8
    R4 = (MyUInt32)(cryptData + 0x00006144);                      // 1321: 	MOV	R4, #(CD_1024_00006144 - 2485276)
    // 1322: 	ADD	R4, PC
    R3 = *(UInt32*)(R4 + (R3 << 2));                            // 1323: 	LDR.W	R3, [R4,R3,LSL#2]
    R0 = R0 ^ R3;                                                 // 1324: 	EORS	R0, R3
    R3 = (R6 >> 16) & ((1 << 8) - 1);                             // 1325: 	UBFX.W	R3, R6, #16, #8
    R4 = (MyUInt32)(cryptData + 0x0000862B);                      // 1326: 	MOV	R4, #(CD_1024_0000862B - 2485296)
    // 1327: 	ADD	R4, PC
    R3 = *(UInt32*)(R4 + (R3 << 2));                            // 1328: 	LDR.W	R3, [R4,R3,LSL#2]
    R0 = R0 ^ R3;                                                 // 1329: 	EORS	R0, R3
    R3 = (R0 >> 8) & ((1 << 8) - 1);                              // 1330: 	UBFX.W	R3, R0, #8, #8
    R4 = (MyUInt32)(cryptData + 0x0000D828);                      // 1331: 	MOV	R4, #(CD_1024_0000D828 - 2485324)
    R1 = (MyUInt32)(cryptData + 0x0000E430);                      // 1332: 	MOV	R1, #(CD_1024_0000E430 - 2485332)
    // 1333: 	ADD	R4, PC
    R3 = *(UInt32*)(R4 + (R3 << 2));                            // 1334: 	LDR.W	R3, [R4,R3,LSL#2]
    R4 = R0 & 0x000000FF;                                         // 1335: 	UXTB	R4, R0
    // 1336: 	ADD	R1, PC
    R1 = *(UInt32*)(R1 + (R4 << 2));                            // 1337: 	LDR.W	R1, [R1,R4,LSL#2]
    R4 = *(UInt32*)(R12 + 276);                                 // 1338: 	LDR.W	R4, [R12,#276]
    R1 = R1 ^ R4;                                                 // 1339: 	EORS	R1, R4
    R1 = R1 ^ R3;                                                 // 1340: 	EORS	R1, R3
    R3 = (R0 >> 16) & ((1 << 8) - 1);                             // 1341: 	UBFX.W	R3, R0, #16, #8
    R4 = (MyUInt32)(cryptData + 0x00008A30);                      // 1342: 	MOV	R4, #(CD_1024_00008A30 - 2485360)
    R0 = R0 >> 24;                                                // 1343: 	LSRS	R0, R0, #24
    // 1344: 	ADD	R4, PC
    R3 = *(UInt32*)(R4 + (R3 << 2));                            // 1345: 	LDR.W	R3, [R4,R3,LSL#2]
    R1 = R1 ^ R3;                                                 // 1346: 	EORS	R1, R3
    R3 = (MyUInt32)(cryptData + 0x0000F444);                      // 1347: 	MOV	R3, #(CD_1024_0000F444 - 2485376)
    // 1348: 	ADD	R3, PC
    R0 = *(UInt32*)(R3 + (R0 << 2));                            // 1349: 	LDR.W	R0, [R3,R0,LSL#2]
    R0 = R0 ^ R1;                                                 // 1350: 	EORS	R0, R1
    R1 = (R11 >> 8) & ((1 << 8) - 1);                             // 1351: 	UBFX.W	R1, R11, #8, #8
    R3 = (MyUInt32)(cryptData + 0x00012920);                      // 1352: 	MOV	R3, #(CD_1024_00012920 - 2485404)
    R4 = (MyUInt32)(cryptData + 0x00009E58);                      // 1353: 	MOV	R4, #(CD_1024_00009E58 - 2485414)
    // 1354: 	ADD	R3, PC
    R1 = *(UInt32*)(R3 + (R1 << 2));                            // 1355: 	LDR.W	R1, [R3,R1,LSL#2]
    R3 = R8 & 0x000000FF;                                         // 1356: 	UXTB.W	R3, R8
    // 1357: 	ADD	R4, PC
    R3 = *(UInt32*)(R4 + (R3 << 2));                            // 1358: 	LDR.W	R3, [R4,R3,LSL#2]
    R4 = *(UInt32*)(R12 + 256);                                 // 1359: 	LDR.W	R4, [R12,#256]
    R2 = (LR >> 16) & ((1 << 8) - 1);                             // 1360: 	UBFX.W	R2, LR, #16, #8
    R3 = R3 ^ R4;                                                 // 1361: 	EORS	R3, R4
    R1 = R1 ^ R3;                                                 // 1362: 	EORS	R1, R3
    R3 = (MyUInt32)(cryptData + 0x000020C8);                      // 1363: 	MOV	R3, #(CD_1024_000020C8 - 2485440)
    // 1364: 	ADD	R3, PC
    R2 = *(UInt32*)(R3 + (R2 << 2));                            // 1365: 	LDR.W	R2, [R3,R2,LSL#2]
    R3 = (MyUInt32)(cryptData + 0x0000F848);                      // 1366: 	MOV	R3, #(CD_1024_0000F848 - 2485454)
    // 1367: 	ADD	R3, PC
    R1 = R1 ^ R2;                                                 // 1368: 	EORS	R1, R2
    R2 = R6 >> 24;                                                // 1369: 	LSRS	R2, R6, #24
    R2 = *(UInt32*)(R3 + (R2 << 2));                            // 1370: 	LDR.W	R2, [R3,R2,LSL#2]
    R1 = R1 ^ R2;                                                 // 1371: 	EORS	R1, R2
    R2 = (R1 >> 8) & ((1 << 8) - 1);                              // 1372: 	UBFX.W	R2, R1, #8, #8
    R3 = (MyUInt32)(cryptData + 0x000118A0);                      // 1373: 	MOV	R3, #(CD_1024_000118A0 - 2485486)
    R6 = (MyUInt32)(cryptData + 0x00013945);                      // 1374: 	MOV	R6, #(CD_1024_00013945 - 2485494)
    // 1375: 	ADD	R3, PC
    R2 = *(UInt32*)(R3 + (R2 << 2));                            // 1376: 	LDR.W	R2, [R3,R2,LSL#2]
    R3 = R1 & 0x000000FF;                                         // 1377: 	UXTB	R3, R1
    // 1378: 	ADD	R6, PC
    R3 = *(UInt32*)(R6 + (R3 << 2));                            // 1379: 	LDR.W	R3, [R6,R3,LSL#2]
    R6 = *(UInt32*)(R12 + 272);                                 // 1380: 	LDR.W	R6, [R12,#272]
    R3 = R3 ^ R6;                                                 // 1381: 	EORS	R3, R6
    R2 = R2 ^ R3;                                                 // 1382: 	EORS	R2, R3
    R3 = (R1 >> 16) & ((1 << 8) - 1);                             // 1383: 	UBFX.W	R3, R1, #16, #8
    R6 = (MyUInt32)(cryptData + 0x00013D45);                      // 1384: 	MOV	R6, #(CD_1024_00013D45 - 2485522)
    R1 = R1 >> 24;                                                // 1385: 	LSRS	R1, R1, #24
    // 1386: 	ADD	R6, PC
    R3 = *(UInt32*)(R6 + (R3 << 2));                            // 1387: 	LDR.W	R3, [R6,R3,LSL#2]
    R2 = R2 ^ R3;                                                 // 1388: 	EORS	R2, R3
    R3 = (MyUInt32)(cryptData + 0x00008E30);                      // 1389: 	MOV	R3, #(CD_1024_00008E30 - 2485538)
    // 1390: 	ADD	R3, PC
    R1 = *(UInt32*)(R3 + (R1 << 2));                            // 1391: 	LDR.W	R1, [R3,R1,LSL#2]
    R3 = (MyUInt32)(encryptedHash);                               // 1392: 	LDR	R3, [SP,#960+var_3B8]
    R2 = R2 ^ R1;                                                 // 1393: 	EORS	R2, R1
    //UNDEFINED!!!;                                               // 1394: 	TST.W	R3, #3
    //UNDEFINED!!!;                                               // 1395: 	BEQ	loc_25ED70
    R1 = R2 >> 8;                                                 // 1396: 	LSRS	R1, R2, #8
    ((UInt8*)R3)[0] = (UInt8)R2;                                  // 1397: 	STRB	R2, [R3]
    ((UInt8*)R3)[1] = (UInt8)R1;                                  // 1398: 	STRB	R1, [R3,#1]
    R1 = R2 >> 16;                                                // 1399: 	LSRS	R1, R2, #16
    ((UInt8*)R3)[2] = (UInt8)R1;                                  // 1400: 	STRB	R1, [R3,#2]
    R1 = R2 >> 24;                                                // 1401: 	LSRS	R1, R2, #24
    ((UInt8*)R3)[3] = (UInt8)R1;                                  // 1402: 	STRB	R1, [R3,#3]
    R1 = R0 >> 8;                                                 // 1403: 	LSRS	R1, R0, #8
    ((UInt8*)R3)[4] = (UInt8)R0;                                                 // 1404: 	STRB	R0, [R3,#4]
    ((UInt8*)R3)[5] = (UInt8)R1;                                                 // 1405: 	STRB	R1, [R3,#5]
    R1 = R0 >> 16;                                                // 1406: 	LSRS	R1, R0, #16
    R0 = R0 >> 24;                                                // 1407: 	LSRS	R0, R0, #24
    ((UInt8*)R3)[6] = (UInt8)R1;                                                 // 1408: 	STRB	R1, [R3,#6]
    ((UInt8*)R3)[7] = (UInt8)R0;                                                 // 1409: 	STRB	R0, [R3,#7]
    R0 = R5 >> 8;                                                 // 1410: 	LSRS	R0, R5, #8
    ((UInt8*)R3)[8] = (UInt8)R5;                                                 // 1411: 	STRB	R5, [R3,#8]
    ((UInt8*)R3)[9] = (UInt8)R0;                                                 // 1412: 	STRB	R0, [R3,#9]
    R0 = R5 >> 16;                                                // 1413: 	LSRS	R0, R5, #16
    ((UInt8*)R3)[10] = (UInt8)R0;                                                 // 1414: 	STRB	R0, [R3,#10]
    R0 = R5 >> 24;                                                // 1415: 	LSRS	R0, R5, #24
    ((UInt8*)R3)[11] = (UInt8)R0;                                                 // 1416: 	STRB	R0, [R3,#11]
    R0 = R10 >> 8;                                                // 1417: 	MOV.W	R0, R10,LSR#8
    ((UInt8*)R3)[12] = (UInt8)R10;                                                 // 1418: 	STRB.W	R10, [R3,#12]
    ((UInt8*)R3)[13] = (UInt8)R0;                                                 // 1419: 	STRB	R0, [R3,#13]
    R0 = R10 >> 16;                                               // 1420: 	MOV.W	R0, R10,LSR#16
    ((UInt8*)R3)[14] = (UInt8)R0;                                                 // 1421: 	STRB	R0, [R3,#14]
    R0 = R10 >> 24;                                               // 1422: 	MOV.W	R0, R10,LSR#24
    ((UInt8*)R3)[15] = (UInt8)R0;                                                 // 1423: 	STRB	R0, [R3,#15]
}


- (id) init
{
	self = [super init];
	if (self != nil)
	{
        self.cryptFileHandle = [NSFileHandle fileHandleForReadingAtPath: [[[NSBundle mainBundle] bundlePath] stringByAppendingPathComponent: @"scdata.bin"]];
        
        if (self.cryptFileHandle != nil)
        {
            [self.cryptFileHandle seekToFileOffset: 0];
            self.cryptData = [self.cryptFileHandle readDataToEndOfFile];
            [self.cryptFileHandle closeFile];
            if ([self.cryptData length] != 0)
            {
                return self;
            }
        }
	}
    
    return nil;
}

-(NSString*)bytesToHex: (UInt8*) bytes withLength: (int) length
{
    NSMutableString *hex = [NSMutableString stringWithCapacity: length * 2];

    for (int i = 0; i < length; i++)
    {
        [hex appendString: [NSString stringWithFormat: @"%02X", bytes[i]]];
    }
    
    return hex;
}

-(NSString*) getEncryptedHashForData: (NSData*) data
{
    UInt8 hashIn[48], hashOut[48];
    UInt8 rVector16[16];
    memset(hashIn, 0x10, 48);
    memset(hashOut, 0x0, 48);
    
    CC_SHA256([data bytes], (CC_LONG)[data length], (unsigned char*)&hashIn);

    SecRandomCopyBytes(kSecRandomDefault, 16, (uint8_t*)rVector16);
    
    for (int i = 0; i < 16; i++)
    {
        hashIn[i] = hashIn[i] ^ rVector16[i];
    }
    encryptHash(&hashIn[0], pData, [self.cryptData bytes], &hashOut[0]);
    
    for (int i = 0; i < 16; i++)
    {
        hashIn[i + 16] = hashIn[i + 16] ^ hashOut[i];
    }
    encryptHash(&hashIn[16], pData, [self.cryptData bytes], &hashOut[16]);

    for (int i = 0; i < 16; i++)
    {
        hashIn[i + 32] = hashIn[i + 32] ^ hashOut[i + 16];
    }
    encryptHash(&hashIn[32], pData, [self.cryptData bytes], &hashOut[32]);
    
    NSString *cryptedHash = [NSString stringWithFormat:@"v1:%@:%@", [self bytesToHex: rVector16 withLength: 16], [self bytesToHex: hashOut withLength: 48]];
    
    return cryptedHash;
}

-(NSString*) getDeviceTokenKey
{
    const char *utf = "00001:trjtw2YVQdqfJyKaT2eqGjxYCVV3hwu6VPfk3Sy/Z3We82AP/IYi3DmZGQ2nicxF";
    return [NSString stringWithUTF8String: utf];
}

-(NSString*) getDeviceTokenValue
{
    const char *utf = "jklhLpiaQsenyI1jvOWWAwvIrspP/daXM18qM2zsT0Q=";
    return [NSString stringWithUTF8String: utf];
}


-(NSString*) getDSIGWithArray: (NSArray*) components
{
    UInt8 hmacOut[32];
    
    NSString *dtokenV = [self getDeviceTokenValue];
    NSString *dataStr = [components componentsJoinedByString:@"|"];
    
    const char* key = [dtokenV UTF8String];
    const char* data = [dataStr UTF8String];
    
    memset(hmacOut, 0, 32);
    CCHmac(2, key, strlen(key), data, strlen(data), hmacOut);
    
    return [self bytesToHex: hmacOut withLength: 10];
}

-(NSString*) getDSIGWithUsername: (NSString*) username withEMail: (NSString*) email withPassword: (NSString*) password withTimestamp: (NSString*) timestamp withReqToken: (NSString*) reqToken
{
    NSString *strings[4];

    if ([username length] > 0)
    {
        strings[0] = username;
    } else
    {
        strings[0] = email;
    }
    
    strings[1] = password;
    strings[2] = timestamp;
    strings[3] = reqToken;
    
    return [self getDSIGWithArray: [NSArray arrayWithObjects: strings count:4]];
}


@end
