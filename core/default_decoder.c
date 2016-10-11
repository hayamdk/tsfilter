#include "core/tsdump_def.h"

#ifdef TSD_PLATFORM_MSVC
#include <Windows.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "utils/arib_proginfo.h"
#include "core/module_hooks.h"
#include "utils/ts_parser.h"
#include "core/default_decoder.h"

int64_t ts_n_drops = 0;
int64_t ts_n_total = 0;
int64_t ts_n_scrambled = 0;
static int ts_counter[0x2000] = {0};

void ts_packet_counter(ts_header_t *tsh)
{
	ts_n_total++;

	unsigned int counter_should_be;

	if (!tsh) {
		ts_n_drops++;
		return;
	}

	if (tsh->pid == 0x1fff) { /* null packet */
		return;
	}

	if (tsh->transport_scrambling_control) {
		ts_n_scrambled++;
	}

	if (ts_counter[tsh->pid] != 0) { /* == 0 : initialized */
		if (tsh->adaptation_field_control & 0x01) {
			/* have payload */
			counter_should_be = (ts_counter[tsh->pid] + 1) % 16;
		} else {
			counter_should_be = ts_counter[tsh->pid] % 16;
		}

		if (counter_should_be != tsh->continuity_counter) {
			ts_n_drops++;
		}
	}

	ts_counter[tsh->pid] = tsh->continuity_counter + 16; /* offset 16 */
}

void create_ts_alignment_filter(ts_alignment_filter_t *filter)
{
	filter->buf_size = 188 * 1024;
	filter->buf = (uint8_t*)malloc(filter->buf_size);
	filter->remain = 0;
	filter->bytes = 0;
	filter->skip = 0;
}

void delete_ts_alignment_filter(ts_alignment_filter_t *filter)
{
	free(filter->buf);
}

void ts_alignment_filter(ts_alignment_filter_t *filter, uint8_t **out_buf, int *out_bytes, const uint8_t *in_buf, int in_bytes)
{
	uint8_t tmp[188];
	int bytes, skip, sync, skip_tmp, sync_tmp;

	bytes = filter->remain + in_bytes;
	if (bytes > filter->buf_size) {
		if (filter->remain > 0) {
			memcpy(tmp, &filter->buf[filter->bytes - filter->remain], filter->remain);
		}
		free(filter->buf);
		while (bytes > filter->buf_size) {
			filter->buf_size *= 2;
		}
		filter->buf = (uint8_t*)malloc(filter->buf_size);
		if (filter->remain > 0) {
			memcpy(filter->buf, tmp, filter->remain);
		}
	} else if (filter->remain > 0) {
		memmove(filter->buf, &filter->buf[filter->bytes - filter->remain], filter->remain);
	}
	memcpy(&filter->buf[filter->remain], in_buf, in_bytes);

	/* �ő��4sync�܂ŁA�ő�sync����skip�������� */
	sync = 0;
	skip = 0;
	for (skip_tmp = 0; skip_tmp < 188; skip_tmp++) {
		for (sync_tmp = 0; sync_tmp < 4 && sync_tmp*188+skip_tmp < bytes; sync_tmp++) {
			if (filter->buf[sync_tmp * 188 + skip_tmp] != 0x47) {
				break;
			}
		}
		if (sync < sync_tmp) {
			sync = sync_tmp;
			skip = skip_tmp;
		}
	}
	filter->bytes = bytes;
	filter->skip = skip;

	bytes -= skip;
	*out_bytes = bytes / 188 * 188;
	*out_buf = &filter->buf[skip];
	filter->remain = bytes - (*out_bytes);
}

/* 188�o�C�g�A���C���ł͂Ȃ��X�g���[���𑗂��Ă���BonDriver�i���Ƃ���Friio�j�ɑΉ����邽�߂̃_�~�[�f�R�[�_ */
void default_decoder(uint8_t **out_buf, int *out_bytes, const uint8_t *in_buf, int in_bytes)
{
	static ts_alignment_filter_t filter;
	static int init_filter = 0;

	if (!init_filter) {
		create_ts_alignment_filter(&filter);
		init_filter = 1;
	}

	ts_alignment_filter(&filter, out_buf, out_bytes, in_buf, in_bytes);
	if (filter.skip != 0) {
		output_message(MSG_WARNING, TSD_TEXT("skipped %d bytes"), filter.skip);
	}
}