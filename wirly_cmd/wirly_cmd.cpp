
#include "wirly.h"
#include <stdio.h>

static void log_cb(char* msg) {
	printf(msg);
}

int main()
{
	wirly_config cfg = { &log_cb };
	wirly_init(&cfg);
	wirly_decode_stream("C:\\projects\\fromFRStoSBC4500.pcap", "--codec=iLBC/8000", nullptr, nullptr);

	getchar();


	return 0;
}

