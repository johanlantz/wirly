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

typedef struct wirly_config {
	/**
	* Callback for receiving log output
	*
	* Default: NULL
	*
	*/
	void(*log_cb)(char* msg);
}wirly_config;

WIRLY_DLL_EXPORT void wirly_init(wirly_config* cfg);

WIRLY_DLL_EXPORT void wirly_decode_stream(char* path, char* codec, char* srtp_crypto_str, char* srtp_key_str);

#ifdef __cplusplus
}
#endif
#endif //WIRLY_H