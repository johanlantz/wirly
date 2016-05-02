#include "wirly.h"
#include <pjsua.h>

struct wirly_config my_config = { NULL};

static struct app {
	pj_caching_pool  cp;
	pj_pool_t       *pool;
	pjmedia_endpt   *mept;
	pj_pcap_file    *pcap;
	pjmedia_port    *wav;
	pjmedia_codec   *codec;
	pjmedia_aud_stream  *aud_strm;
	unsigned         pt;
	pjmedia_transport   *srtp;
	pjmedia_rtp_session  rtp_sess;
	pj_bool_t        rtp_sess_init;
} app;

#define LOG_MAX_BUF_SIZE 512
static void WIRLY_LOG(const char* format, ...)
{
	if (my_config.log_cb) {
		static char buffer[LOG_MAX_BUF_SIZE];
		va_list args;
		va_start(args, format);
		vsnprintf(buffer, LOG_MAX_BUF_SIZE, format, args);
		va_end(args);
		my_config.log_cb(buffer);
	}
}

void wirly_init(wirly_config* cfg) {
	
		memcpy(&my_config, cfg, sizeof(wirly_config));
		WIRLY_LOG("Starting wirly");

}

static void cleanup()
{
	if (app.srtp) pjmedia_transport_close(app.srtp);
	if (app.wav) {
		pj_ssize_t pos = pjmedia_wav_writer_port_get_pos(app.wav);
		if (pos >= 0) {
			unsigned msec;
			msec = (unsigned)pos / 2 * 1000 / PJMEDIA_PIA_SRATE(&app.wav->info);
			WIRLY_LOG("Written: %dm:%02ds.%03d\n",
				msec / 1000 / 60,
				(msec / 1000) % 60,
				msec % 1000);
		}
		pjmedia_port_destroy(app.wav);
	}
	if (app.pcap) pj_pcap_close(app.pcap);
	if (app.codec) {
		pjmedia_codec_mgr *cmgr;
		pjmedia_codec_close(app.codec);
		cmgr = pjmedia_endpt_get_codec_mgr(app.mept);
		pjmedia_codec_mgr_dealloc_codec(cmgr, app.codec);
	}
	if (app.aud_strm) {
		pjmedia_aud_stream_stop(app.aud_strm);
		pjmedia_aud_stream_destroy(app.aud_strm);
	}
	if (app.mept) pjmedia_endpt_destroy(app.mept);
	if (app.pool) pj_pool_release(app.pool);
	pj_caching_pool_destroy(&app.cp);
	pj_shutdown();
}

static void err_cleanup(const char *title, pj_status_t status)
{
	if (status != PJ_SUCCESS) {
		char errmsg[PJ_ERR_MSG_SIZE];
		pj_strerror(status, errmsg, sizeof(errmsg));
		WIRLY_LOG("Error: %s: %s\n", title, errmsg);
	}
	else {
		WIRLY_LOG("Error: %s\n", title);
	}
	cleanup();
}

#define T(op)       do { \
    status = op; \
if (status != PJ_SUCCESS) \
    err_cleanup(#op, status); \
} while (0)

static void read_rtp(pj_uint8_t *buf, pj_size_t bufsize,
	pjmedia_rtp_hdr **rtp,
	pj_uint8_t **payload,
	unsigned *payload_size,
	pj_bool_t check_pt)
{
	pj_status_t status;

	/* Init RTP session */
	if (!app.rtp_sess_init) {
		T(pjmedia_rtp_session_init(&app.rtp_sess, 0, 0));
		app.rtp_sess_init = PJ_TRUE;
	}

	/* Loop reading until we have a good RTP packet */
	for (;;) {
		pj_size_t sz = bufsize;
		const pjmedia_rtp_hdr *r;
		const void *p;
		pjmedia_rtp_status seq_st;

		status = pj_pcap_read_udp(app.pcap, NULL, buf, &sz);
		if (status != PJ_SUCCESS) {
			err_cleanup("Error reading PCAP file", status);
			return;
		}
		/* Decode RTP packet to make sure that this is an RTP packet.
		* We will decode it again to get the payload after we do
		* SRTP decoding
		*/
		status = pjmedia_rtp_decode_rtp(&app.rtp_sess, buf, (int)sz, &r,
			&p, payload_size);
		if (status != PJ_SUCCESS) {
			char errmsg[PJ_ERR_MSG_SIZE];
			pj_strerror(status, errmsg, sizeof(errmsg));
			WIRLY_LOG("Not RTP packet, skipping packet: %s\n", errmsg);
			continue;
		}

		/* Decrypt SRTP */
#if PJMEDIA_HAS_SRTP
		if (app.srtp) {
			int len = (int)sz;
			status = pjmedia_transport_srtp_decrypt_pkt(app.srtp, PJ_TRUE,
				buf, &len);
			if (status != PJ_SUCCESS) {
				char errmsg[PJ_ERR_MSG_SIZE];
				pj_strerror(status, errmsg, sizeof(errmsg));
				WIRLY_LOG("SRTP packet decryption failed, skipping packet: %s\n",
					errmsg);
				continue;
			}
			sz = len;

			/* Decode RTP packet again */
			status = pjmedia_rtp_decode_rtp(&app.rtp_sess, buf, (int)sz, &r,
				&p, payload_size);
			if (status != PJ_SUCCESS) {
				char errmsg[PJ_ERR_MSG_SIZE];
				pj_strerror(status, errmsg, sizeof(errmsg));
				WIRLY_LOG("Not RTP packet, skipping packet: %s\n", errmsg);
				continue;
			}
		}
#endif

		/* Update RTP session */
		pjmedia_rtp_session_update2(&app.rtp_sess, r, &seq_st, PJ_FALSE);

		/* Skip out-of-order packet */
		if (seq_st.diff == 0) {
			WIRLY_LOG("Skipping out of order packet\n");
			continue;
		}

		/* Skip if payload type is different */
		if (check_pt && r->pt != app.pt) {
			WIRLY_LOG("Skipping RTP packet with bad payload type\n");
			continue;
		}

		/* Skip bad packet */
		if (seq_st.status.flag.bad) {
			WIRLY_LOG("Skipping bad RTP\n");
			continue;
		}


		*rtp = (pjmedia_rtp_hdr*)r;
		*payload = (pj_uint8_t*)p;

		/* We have good packet */
		break;
	}
}

pjmedia_frame play_frm;
static pj_bool_t play_frm_copied, play_frm_ready;

static pj_status_t wait_play(pjmedia_frame *f)
{
	play_frm_copied = PJ_FALSE;
	play_frm = *f;
	play_frm_ready = PJ_TRUE;
	while (!play_frm_copied) {
		pj_thread_sleep(1);
	}
	play_frm_ready = PJ_FALSE;

	return PJ_SUCCESS;
}

static pj_status_t play_cb(void *user_data, pjmedia_frame *f)
{
	PJ_UNUSED_ARG(user_data);

	if (!play_frm_ready) {
		WIRLY_LOG("play_cb()", "Warning! Play frame not ready");
		return PJ_SUCCESS;
	}

	pj_memcpy(f->buf, play_frm.buf, play_frm.size);
	f->size = play_frm.size;

	play_frm_copied = PJ_TRUE;
	return PJ_SUCCESS;
}

static void pcap2wav(const pj_str_t *codec,
	const pj_str_t *wav_filename,
	pjmedia_aud_dev_index dev_id,
	const pj_str_t *srtp_crypto,
	const pj_str_t *srtp_key)
{
	const pj_str_t WAV = { ".wav", 4 };
	struct pkt {
		pj_uint8_t   buffer[320];
		pjmedia_rtp_hdr *rtp;
		pj_uint8_t  *payload;
		unsigned     payload_len;
	} pkt0;
	pjmedia_codec_mgr *cmgr;
	const pjmedia_codec_info *ci;
	pjmedia_codec_param param;
	unsigned samples_per_frame;
	pj_status_t status;

	/* Initialize all codecs */
	T(pjmedia_codec_register_audio_codecs(app.mept, NULL));

	/* Create SRTP transport is needed */
#if PJMEDIA_HAS_SRTP
	if (srtp_crypto->slen) {
		pjmedia_srtp_crypto crypto;

		pj_bzero(&crypto, sizeof(crypto));
		crypto.key = *srtp_key;
		crypto.name = *srtp_crypto;
		T(pjmedia_transport_srtp_create(app.mept, NULL, NULL, &app.srtp));
		T(pjmedia_transport_srtp_start(app.srtp, &crypto, &crypto));
	}
#else
	PJ_UNUSED_ARG(srtp_crypto);
	PJ_UNUSED_ARG(srtp_key);
#endif

	/* Read first packet */
	read_rtp(pkt0.buffer, sizeof(pkt0.buffer), &pkt0.rtp,
		&pkt0.payload, &pkt0.payload_len, PJ_FALSE);

	cmgr = pjmedia_endpt_get_codec_mgr(app.mept);

	/* Get codec info and param for the specified payload type */
	app.pt = pkt0.rtp->pt;
	if (app.pt < 96) {
		T(pjmedia_codec_mgr_get_codec_info(cmgr, pkt0.rtp->pt, &ci));
	}
	else {
		unsigned cnt = 2;
		const pjmedia_codec_info *info[2];
		T(pjmedia_codec_mgr_find_codecs_by_id(cmgr, codec, &cnt,
			info, NULL));
		if (cnt != 1) {
			err_cleanup("Codec ID must be specified and unique!", 0);
			return;
		}
		ci = info[0];
	}
	T(pjmedia_codec_mgr_get_default_param(cmgr, ci, &param));

	/* Alloc and init codec */
	T(pjmedia_codec_mgr_alloc_codec(cmgr, ci, &app.codec));
	T(pjmedia_codec_init(app.codec, app.pool));
	T(pjmedia_codec_open(app.codec, &param));

	/* Init audio device or WAV file */
	samples_per_frame = ci->clock_rate * param.info.frm_ptime / 1000;
	if (pj_strcmp2(wav_filename, "-") == 0) {
		pjmedia_aud_param aud_param;

		/* Open audio device */
		T(pjmedia_aud_dev_default_param(dev_id, &aud_param));
		aud_param.dir = PJMEDIA_DIR_PLAYBACK;
		aud_param.channel_count = ci->channel_cnt;
		aud_param.clock_rate = ci->clock_rate;
		aud_param.samples_per_frame = samples_per_frame;
		T(pjmedia_aud_stream_create(&aud_param, NULL, &play_cb,
			NULL, &app.aud_strm));
		T(pjmedia_aud_stream_start(app.aud_strm));
	}
	else if (pj_stristr(wav_filename, &WAV)) {
		/* Open WAV file */
		T(pjmedia_wav_writer_port_create(app.pool, wav_filename->ptr,
			ci->clock_rate, ci->channel_cnt,
			samples_per_frame,
			param.info.pcm_bits_per_sample, 0, 0,
			&app.wav));
	}
	else {
		err_cleanup("invalid output file", PJ_EINVAL);
		return;
	}

	/* Loop reading PCAP and writing WAV file */
	for (;;) {
		struct pkt pkt1;
		pj_timestamp ts;
		pjmedia_frame frames[16], pcm_frame;
		short pcm[320];
		unsigned i, frame_cnt;
		long samples_cnt, ts_gap;

		pj_assert(sizeof(pcm) >= samples_per_frame);

		/* Parse first packet */
		ts.u64 = 0;
		frame_cnt = PJ_ARRAY_SIZE(frames);
		T(pjmedia_codec_parse(app.codec, pkt0.payload, pkt0.payload_len,
			&ts, &frame_cnt, frames));

		/* Decode and write to WAV file */
		samples_cnt = 0;
		for (i = 0; i<frame_cnt; ++i) {
			pjmedia_frame pcm_frame;

			pcm_frame.buf = pcm;
			pcm_frame.size = samples_per_frame * 2;

			T(pjmedia_codec_decode(app.codec, &frames[i],
				(unsigned)pcm_frame.size, &pcm_frame));
			if (app.wav) {
				T(pjmedia_port_put_frame(app.wav, &pcm_frame));
			}
			if (app.aud_strm) {
				T(wait_play(&pcm_frame));
			}
			samples_cnt += samples_per_frame;
		}

		/* Read next packet */
		read_rtp(pkt1.buffer, sizeof(pkt1.buffer), &pkt1.rtp,
			&pkt1.payload, &pkt1.payload_len, PJ_TRUE);

		/* Fill in the gap (if any) between pkt0 and pkt1 */
		ts_gap = pj_ntohl(pkt1.rtp->ts) - pj_ntohl(pkt0.rtp->ts) -
			samples_cnt;
		while (ts_gap >= (long)samples_per_frame) {

			pcm_frame.buf = pcm;
			pcm_frame.size = samples_per_frame * 2;

			if (app.codec->op->recover) {
				T(pjmedia_codec_recover(app.codec, (unsigned)pcm_frame.size,
					&pcm_frame));
			}
			else {
				pj_bzero(pcm_frame.buf, pcm_frame.size);
			}

			if (app.wav) {
				T(pjmedia_port_put_frame(app.wav, &pcm_frame));
			}
			if (app.aud_strm) {
				T(wait_play(&pcm_frame));
			}
			ts_gap -= samples_per_frame;
		}

		/* Next */
		pkt0 = pkt1;
		pkt0.rtp = (pjmedia_rtp_hdr*)pkt0.buffer;
		pkt0.payload = pkt0.buffer + (pkt1.payload - pkt1.buffer);
	}
}

void wirly_decode_stream(char* path, char* codec_str, char* srtp_crypto_str, char* srtp_key_str) {
	pjmedia_aud_dev_index dev_id = PJMEDIA_AUD_DEFAULT_PLAYBACK_DEV;
	pj_pcap_filter filter;
	pj_status_t status;
	char key_bin[32];
	char output_buf[256];

	pj_str_t pcap_ext = pj_str(".pcap");
	pj_str_t codec = pj_str(codec_str);
	pj_str_t srtp_crypto = pj_str(srtp_crypto_str);
	pj_str_t srtp_key = pj_str(srtp_key_str);
	pj_str_t input = pj_str(path);
	pj_str_t output = { output_buf, 0 };

	char* ext = pj_strstr(&input, &pcap_ext);
	if (ext == NULL || strlen(ext) > 5) {
		WIRLY_LOG("Error: Wireshark file must be in .pcap format.");
		return;
	}
	pj_strncpy(&output, &input, input.slen - pcap_ext.slen);
	pj_strcat2(&output, ".wav");
	output.ptr[output.slen] = '\0';

	pj_pcap_filter_default(&filter);
	filter.link = PJ_PCAP_LINK_TYPE_ETH;
	filter.proto = PJ_PCAP_PROTO_TYPE_UDP;

	/* Parse arguments */
	if (srtp_key.slen != 0) {
		int key_len = sizeof(key_bin);
		if (pj_base64_decode(&srtp_key, (pj_uint8_t*)key_bin, &key_len)) {
			WIRLY_LOG("Error: invalid srtp key");
			return;
		}
		srtp_key.ptr = key_bin;
		srtp_key.slen = key_len;
	}
		/*
		case OPT_SRC_IP: {
			pj_str_t t = pj_str(pj_optarg);
			pj_in_addr a = pj_inet_addr(&t);
			filter.ip_src = a.s_addr;
		}
							break;
		case OPT_DST_IP: {
			pj_str_t t = pj_str(pj_optarg);
			pj_in_addr a = pj_inet_addr(&t);
			filter.ip_dst = a.s_addr;
		}
							break;
		case OPT_SRC_PORT:
			filter.src_port = pj_htons((pj_uint16_t)atoi(pj_optarg));
			break;
		case OPT_DST_PORT:
			filter.dst_port = pj_htons((pj_uint16_t)atoi(pj_optarg));
			break;
		case OPT_CODEC:
			codec = pj_str(pj_optarg);
			break;
		case OPT_PLAY_DEV_ID:
			dev_id = atoi(pj_optarg);
			break;
		default:
			puts("Error: invalid option");
			return 1;
		}
	}*/

	if (!(srtp_crypto.slen) != !(srtp_key.slen)) {
		WIRLY_LOG("Error: both SRTP crypto and key must be specified");
		return;
	}

	T(pj_init());

	pj_caching_pool_init(&app.cp, NULL, 0);
	app.pool = pj_pool_create(&app.cp.factory, "pcaputil", 1000, 1000, NULL);

	T(pjlib_util_init());
	T(pjmedia_endpt_create(&app.cp.factory, NULL, 0, &app.mept));

	T(pj_pcap_open(app.pool, input.ptr, &app.pcap));
	T(pj_pcap_set_filter(app.pcap, &filter));

	pcap2wav(&codec, &output, dev_id, &srtp_crypto, &srtp_key);

	cleanup();
	return;
}

#define MAX_CODECS 32
#define MAX_CODEC_BUF_SIZE 1024
char* wirly_get_codecs() {
	static char codec_buf[MAX_CODEC_BUF_SIZE] = {0};
	unsigned i = 0;
	pjmedia_codec_mgr *cmgr;
	pjmedia_codec_info ci[MAX_CODECS];
	unsigned count = MAX_CODECS;
	pj_caching_pool c_pool;
	pj_pool_t* pool;
	pjmedia_endpt* media_endpoint;
	pj_status_t status;
	T(pj_init());

	pj_caching_pool_init(&c_pool, NULL, 0);
	pool = pj_pool_create(&c_pool.factory, "codec_enum", 1000, 1000, NULL);

	T(pjlib_util_init());
	T(pjmedia_endpt_create(&c_pool.factory, NULL, 0, &media_endpoint));
	
	T(pjmedia_codec_register_audio_codecs(media_endpoint, NULL));

	cmgr = pjmedia_endpt_get_codec_mgr(media_endpoint);
	T(pjmedia_codec_mgr_enum_codecs(cmgr,
		&count,
		ci,
		NULL));

	codec_buf[0] = '[';
	for (i = 0; i < count; i++) {
		pj_ansi_snprintf(codec_buf + strlen(codec_buf), MAX_CODEC_BUF_SIZE, "\"%.*s/%d\",", ci[i].encoding_name.slen, ci[i].encoding_name.ptr, ci[i].clock_rate);
	}
	codec_buf[strlen(codec_buf)-1] = ']';

	pjmedia_endpt_destroy(media_endpoint);
	pj_pool_release(pool);
	pj_caching_pool_destroy(&c_pool);
	pj_shutdown();

	return codec_buf;
}