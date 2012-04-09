/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef __PLATFORM_H
#define __PLATFORM_H
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Platform tested for gcc v4 on a Fedora core system.
 * It should generally work for any Linux system using
 * the gcc compiler, even v3 and v2.
 */
#ifdef __GNUC__
#define __int64 long long
#define stricmp strcasecmp
#define strnicmp strncasecmp
#define sprintf_s snprintf
#include <stdio.h>
#include <malloc.h>
int strcpy_s(
   char *dst,
   size_t dst_size,
   const char *src
);

#ifndef UNUSEDPARM
#define UNUSEDPARM(x) x=(x)
#endif
#endif

/* 
 * Visual Studio 6 
 */
#if _MSC_VER==1200
#include "module/mystring.h"
#define sprintf_s _snprintf

#ifndef UNUSEDPARM
#define UNUSEDPARM(x) x
#endif

#define S_IFDIR _S_IFDIR

#elif _MSC_VER==1600
//#define stricmp _stricmp

#endif

/* 
 * Visual Studio 2005 
 *
 * Supports both 32-bits and 64-bits.
 */
#if _MSC_VER==1400
#pragma warning(disable:4996)
#endif


#ifndef UNUSEDPARM
#define UNUSEDPARM(x) (void)x
#endif


#ifdef __cplusplus
}
#endif
#endif /*__PLATFORM_H*/
