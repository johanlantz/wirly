/*
* wirly.h
*
*  Created on: 30/04/2016
*  Author: johan
*/

#ifndef WIRLY_H_
#define WIRLY_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LIBWIRLY_EXPORTS
#define WIRLY_DLL_EXPORT __declspec(dllexport)
#else
#define WIRLY_DLL_EXPORT __declspec(dllimport)
#endif

WIRLY_DLL_EXPORT void test();

#ifdef __cplusplus
}
#endif
#endif //WIRLY_H