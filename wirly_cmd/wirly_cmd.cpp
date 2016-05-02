
#include "wirly.h"
#include <stdio.h>

static void log_cb(char* msg) {
	printf(msg);
}

int main()
{
	wirly_config cfg = { &log_cb };
	wirly_init(&cfg);
	//wirly_decode_stream("C:\\users\\johan\\projects\\4500ilbcto-frs.pcap", "iLBC/8000", nullptr, nullptr);
	printf(wirly_get_codecs());
	getchar();


	return 0;
}

