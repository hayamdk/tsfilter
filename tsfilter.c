#include "core/tsdump_def.h"

#ifdef TSD_PLATFORM_MSVC
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/timeb.h>

#ifdef TSD_PLATFORM_MSVC

#include <fcntl.h>
#include <io.h>

#define my_fopen		_wfopen
#define my_fprintf		fwprintf

#else

#define my_fopen		fopen
#define my_fprintf		fprintf

#endif

#include "utils/arib_proginfo.h"
#include "utils/arib_parser.h"
#include "utils/tsdstr.h"
#include "core/default_decoder.h"

#define TS_PACKET_SIZE 188

static int set_filter = 0;
static int filter_event_id = -1;
static int filter_pids[256];
static int n_filter_pids = 0;
static int add_pat = 0;
static int add_pmt = 0;
static int sync = 1;

typedef struct
{
	unsigned int network_PID;
	PSI_parse_t PAT;
	PSI_parse_t PMTs[MAX_SERVICES_PER_CH];
	PSI_parse_t EIT0x12;
	PSI_parse_t EIT0x26;
	PSI_parse_t EIT0x27;
	int n_services;
	proginfo_t proginfos[MAX_SERVICES_PER_CH];
} parse_set_t;

static inline int64_t gettime()
{
	int64_t result;
#ifdef TSD_PLATFORM_MSVC
	struct _timeb tv;
	_ftime64_s(&tv);
#else
	struct timeb tv;
	ftime(&tv);
#endif
	result = (int64_t)tv.time * 1000;
	result += tv.millitm;

	return result;
}

static void pat_handler(void *param, const int n, const int i, const PAT_item_t *PAT_item)
{
	parse_set_t *set = (parse_set_t*)param;
	UNREF_ARG(n);
	UNREF_ARG(i);

	if (set->n_services >= MAX_SERVICES_PER_CH) {
		return;
	}

	if (PAT_item->program_number != 0) {
		set->PMTs[set->n_services].stat = PAYLOAD_STAT_INIT;
		set->PMTs[set->n_services].pid = PAT_item->pid;
		store_PAT(&set->proginfos[set->n_services], PAT_item);
		(set->n_services)++;
	}
}

static proginfo_t *find_curr_service(void *param, const unsigned int service_id)
{
	int i;
	parse_set_t *set = (parse_set_t*)param;
	for (i = 0; i < set->n_services; i++) {
		if (service_id == set->proginfos[i].service_id) {
			return &set->proginfos[i];
		}
	}
	return NULL;
}

static proginfo_t *find_curr_service_eit(void *param, const EIT_header_t *eit_h)
{
	if (eit_h->section_number != 0) {
		/* Œ»Ýis’†‚Ì”Ô‘g‚Å‚Í‚È‚¢ */
		return NULL;
	}
	return find_curr_service(param, eit_h->service_id);
}

static void init_set(parse_set_t *set)
{
	int i;
	set->PAT.pid = 0;
	set->PAT.stat = PAYLOAD_STAT_INIT;
	set->EIT0x12.pid = 0x12;
	set->EIT0x12.stat = PAYLOAD_STAT_INIT;
	set->EIT0x26.pid = 0x26;
	set->EIT0x26.stat = PAYLOAD_STAT_INIT;
	set->EIT0x27.pid = 0x27;
	set->EIT0x27.stat = PAYLOAD_STAT_INIT;
	set->n_services = 0;
	for (i = 0; i < MAX_SERVICES_PER_CH; i++) {
		init_proginfo(&set->proginfos[i]);
	}
}

static int is_pat(int pid)
{
	return (pid == 0x00);
}

static int is_pmt(int pid, parse_set_t *set)
{
	int i;
	for (i = 0; i < set->n_services; i++) {
		if (pid == (int)set->PMTs[i].pid) {
			return 1;
		}
	}
	return 0;
}

static int filter(const int pid, parse_set_t *set)
{
	int i;
	int curr_event = 0, no_hit = 0;

	if (!set_filter) {
		return 1;
	}

	if (filter_event_id > 0) {
		for (i = 0; i < set->n_services; i++) {
			if (set->proginfos[i].status & PGINFO_GET_EVENT_INFO) {
				if ((int)set->proginfos[i].event_id == filter_event_id) {
					curr_event = 1;
				}
			}
		}
		if (!curr_event) {
			return 0;
		}
	}

	if (n_filter_pids > 0) {
		for (i = 0; i < n_filter_pids; i++) {
			if (pid == filter_pids[i]) {
				return 1;
			}
		}
		no_hit = 1;
	}

	if (add_pat) {
		if (is_pat(pid)) {
			return 1;
		}
		no_hit = 1;
	}

	if (add_pmt) {
		if (is_pmt(pid, set)) {
			return 1;
		}
		no_hit = 1;
	}

	if (curr_event && !no_hit) {
		return 1;
	}

	return 0;
}

static int main_loop(FILE *fp_in, FILE *fp_out)
{
	int i, n_in, n, c;
	uint8_t buf[TS_PACKET_SIZE * 256], *buf_out, *p;
	ts_header_t tsh;
	parse_set_t set;
	int64_t in = 0, out = 0, t, last_print = 0;
	ts_alignment_filter_t f;

	init_set(&set);

	if (sync) {
		create_ts_alignment_filter(&f);
	}

	while ((n_in = (int)fread(buf, TS_PACKET_SIZE, sizeof(buf)/TS_PACKET_SIZE, fp_in)) > 0) {
		if (sync) {
			ts_alignment_filter(&f, &buf_out, &n, buf, n_in * TS_PACKET_SIZE);
			n /= TS_PACKET_SIZE;
		} else {
			n = n_in;
			buf_out = buf;
		}
		for (c = 0; c < n; c++) {
			p = &buf_out[c * TS_PACKET_SIZE];
			in++;

			t = gettime();
			if (t > last_print + 500) {
				fprintf(stderr, "in: %10"PRId64", out: %10"PRId64"\r", in * TS_PACKET_SIZE, out * TS_PACKET_SIZE);
				fflush(stderr);
				last_print = t;
			}

			if (!parse_ts_header(p, &tsh)) {
				if (!set_filter) {
					fwrite(p, TS_PACKET_SIZE, 1, fp_out);
				}
				continue;
			}
			if (!tsh.transport_scrambling_control) {
				if (set.n_services == 0) {
					parse_PAT(&set.PAT, p, &tsh, &set, pat_handler);
				} else {
					for (i = 0; i < set.n_services; i++) {
						parse_PMT(p, &tsh, &set.PMTs[i], &set.proginfos[i]);
					}
					parse_EIT(&set.EIT0x12, p, &tsh, &set, find_curr_service_eit);
					parse_EIT(&set.EIT0x26, p, &tsh, &set, find_curr_service_eit);
					parse_EIT(&set.EIT0x27, p, &tsh, &set, find_curr_service_eit);
				}
			}
			if (filter((int)tsh.pid, &set)) {
				fwrite(p, TS_PACKET_SIZE, 1, fp_out);
				out++;
			}
		}
	}

	return 0;
}

#ifdef TSD_PLATFORM_MSVC
int wmain
#else
int main
#endif
(int argc, const TSDCHAR *argv[])
{
	FILE *fp_in, *fp_out;
	const TSDCHAR *arg, *in_file = NULL, *out_file = NULL;
	int i, pid;

	for (i = 1; i < argc; i++) {
		arg = argv[i];
		if (tsd_strncmp(arg, TSD_TEXT("event_id="), strlen("event_id=")) == 0) {
			arg = &arg[strlen("event_id=")];
			filter_event_id = tsd_atoi(arg);
			if (0 <= filter_event_id && filter_event_id < 65536) {
				set_filter = 1;
			} else {
				filter_event_id = -1;
				fprintf(stderr, "Invalid event id: %d\n", filter_event_id);
			}
		} else if (tsd_strncmp(arg, TSD_TEXT("if="), strlen("if=")) == 0) {
			arg = &arg[strlen("if=")];
			in_file = arg;
		} else if (tsd_strncmp(arg, TSD_TEXT("of="), strlen("of=")) == 0) {
			arg = &arg[strlen("of=")];
			out_file = arg;
		} else if (tsd_strcmp(arg, TSD_TEXT("pmt")) == 0) {
			add_pat = 1;
			set_filter = 1;
		} else if (tsd_strcmp(arg, TSD_TEXT("pat")) == 0) {
			add_pmt = 1;
			set_filter = 1;
		} else if (tsd_strcmp(arg, TSD_TEXT("--nosync")) == 0) {
			sync = 0;
		} else {
			if (n_filter_pids < sizeof(filter_pids) / sizeof(int)) {
				pid = tsd_atoi(arg);
				if (0 <= pid && pid <= 4096) {
					filter_pids[n_filter_pids++] = pid;
					set_filter = 1;
				} else {
					fprintf(stderr, "Invalid PID: %d\n", pid);
				}
			}
		}
	}

	if (in_file) {
		fp_in = my_fopen(in_file, TSD_TEXT("rb"));
		if (!fp_in) {
			my_fprintf(stderr, TSD_TEXT("file open error: %s\n"), in_file);
			return 1;
		}
		my_fprintf(stderr, TSD_TEXT("input: %s\n"), in_file);
	} else {
#ifdef TSD_PLATFORM_MSVC
		_setmode(_fileno(stdin), _O_BINARY);
#endif
		fp_in = stdin;
		my_fprintf(stderr, TSD_TEXT("input: <stdin>\n"));
	}

	if (out_file) {
		fp_out = my_fopen(out_file, TSD_TEXT("wb"));
		if (!fp_out) {
			my_fprintf(stderr, TSD_TEXT("file open error: %s\n"), out_file);
			return 1;
		}
		my_fprintf(stderr, TSD_TEXT("output: %s\n"), out_file);
	} else {
#ifdef TSD_PLATFORM_MSVC
		_setmode(_fileno(stdout), _O_BINARY);
#endif
		fp_out = stdout;
		my_fprintf(stderr, TSD_TEXT("output: <stdout>\n"));
	}

	fflush(stderr);

	return main_loop(fp_in, fp_out);
}