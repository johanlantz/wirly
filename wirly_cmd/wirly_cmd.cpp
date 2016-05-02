
#include "wirly.h"
#include <stdio.h>

static void log_cb(char* msg) {
	printf(msg);
}

int main(int argc, char** argv)
{
	wirly_config cfg = { &log_cb };
	wirly_init(&cfg);
	printf(wirly_get_codecs());

	if (argc == 1) {
		wirly_decode_stream("C:\\users\\johan\\projects\\4500ilbcto-frs.pcap", "iLBC/8000", nullptr, nullptr);
	}
	else {
		wirly_decode_stream((char*)argv[1], (char*)argv[2], nullptr, nullptr);
	}
		

	getchar();


	return 0;
}

