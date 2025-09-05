#ifndef SM2_ECCBASEOP_H
#define SM2_ECCBASEOP_H

#include "../include/convert.h"
// 一般操作数的长度(长字个数)
#define DIG_LEN 8
typedef unsigned int small;
typedef small *big;

// ECC数据结构体
typedef struct
{
    small x[DIG_LEN];
    small y[DIG_LEN];
} affpoint;

typedef affpoint *epoint;

// 点结构体
typedef struct
{
    small x[DIG_LEN];
    small y[DIG_LEN];
    small z[DIG_LEN];
} projpoint;

typedef projpoint *point;

// 以下是椭圆曲线的参数(little endian)，用外部变量存储

// GF(p)
#define M 256

// p = 2^256-2^224-2^96+2^64-1
const small P[DIG_LEN] =
        {0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE};
// a = -3
const small A[DIG_LEN] =
        {0xFFFFFFFC, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE};
// b
const small B[DIG_LEN] =
        {0x4D940E93, 0xDDBCBD41, 0x15AB8F92, 0xF39789F5, 0xCF6509A7, 0x4D5A9E4B, 0x9D9F5E34, 0x28E9FA9E};
// y^2 = x^3 +ax + b
const small N[DIG_LEN] =
        {0x39D54123, 0x53BBF409, 0x21C6052B, 0x7203DF6B, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE};
// G
const affpoint G =
        {{0x334C74C7, 0x715A4589, 0xF2660BE1, 0x8FE30BBF, 0x6A39C994, 0x5F990446, 0x1F198119, 0x32C4AE2C},
         {0x2139F0A0, 0x02DF32E5, 0xC62A4740, 0xD0A9877C, 0x6B692153, 0x59BDCEE3, 0xF4F6779C, 0xBC3736A2}};

#define LOHALF(x) ((small)((x)&0xffff))
#define HIHALF(x) ((small)((x) >> 16 & 0xffff))
#define TOHIGH(x) ((small)((x) << 16))

int compare(big a, big b);

//把两个256位的数u,v相加（有限域GF(p)中的加法）
//结果存放在w中
void add(big w, big u, big v);

//u-v，有限域中的减法,计算结果存放在w中
//两个256位的数相减
void sub(big w, big u, big v);

//u mod v,结果存放在u中
void mod(big u, big v);
void mul(big w, big u, big v);
void squ(big x, big y);
void inv(big x, big y);
void modorder(big r, big x);
void modadd(big w, big u, big v, big p);
void modsub(big w, big u, big v, big p);
void modinv(big x, big y, big p);
void mulmodorder(big w, big u, big v);
void projpointdouble(point p, point q);
void projpointadd(point r, point p, point q);
void mixpointadd(point r, point p, epoint q);
void pointadd(epoint r, epoint p, epoint q);
void pointmul(epoint p, epoint q, big n);
void projpointdouble(point p, point q);
void mixpointadd(point r, point p, epoint q);
void projpointadd(point r, point p, point q);
void basepointmul(epoint p, big n);

/***************************************************
* function			   : pointVerify
* description		   : 验证点是否在曲线上，不包含无穷远点
* parameters:
-- q[in]		   : 点
* return 			   : 0--success;
非0--error code
***************************************************/
int pointVerify(epoint q);


#endif //SM2_ECCBASEOP_H
