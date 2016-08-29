#define PGINFO_GET_PAT				1
#define PGINFO_GET_PMT				2
#define PGINFO_GET_SERVICE_INFO		4
#define PGINFO_GET_EVENT_INFO		8
#define PGINFO_GET_SHORT_TEXT		16
#define PGINFO_GET_EXTEND_TEXT		32
#define PGINFO_GET_GENRE			64
#define PGINFO_UNKNOWN_STARTTIME	128
#define PGINFO_UNKNOWN_DURATION		256
#define PGINFO_READY_UPDATED		512
#define PGINFO_VALID_PCR			1024
#define PGINFO_PCR_UPDATED			2048
#define PGINFO_GET_TOT				4096
#define PGINFO_VALID_TOT_PCR		8192

#define PGINFO_GET					(PGINFO_GET_PAT|PGINFO_GET_SERVICE_INFO|PGINFO_GET_EVENT_INFO|PGINFO_GET_SHORT_TEXT)
#define PGINFO_GET_ALL				(PGINFO_GET|PGINFO_GET_EXTEND_TEXT|PGINFO_GET_GENRE)
#define PGINFO_TIMEINFO				(PGINFO_VALID_PCR|PGINFO_GET_TOT|PGINFO_VALID_TOT_PCR)
#define PGINFO_READY(s)				( ((s)&PGINFO_GET) == PGINFO_GET )
#define PGINFO_READY_TIMESTAMP(s)	( ((s)&PGINFO_TIMEINFO) == PGINFO_TIMEINFO )

#define MAX_PIDS_PER_SERVICE		64
#define MAX_SERVICES_PER_CH			32

#define PCR_BASE_MAX				0x200000000
#define PCR_BASE_HZ					(90*1000)

#ifdef TSD_PLATFORM_MSVC
#define ARIB_CHAR_SIZE_RATIO 1 /* WCHAR�ł̓T���Q�[�g�y�A������1������1WCHAR�ŕ\����̂�1�{����Ώ\�� */
#else
#define ARIB_CHAR_SIZE_RATIO 2 /* UTF-8�ł͂ЂƂ܂�2�{���m�ہi��ʓI�ȂЂ炪�ȁE������1.5�{�j */
#endif

typedef enum {
	PAYLOAD_STAT_INIT = 0,
	PAYLOAD_STAT_PROC,
	PAYLOAD_STAT_FINISHED
} PSI_stat_t;

typedef struct {
	unsigned int pid;
	PSI_stat_t stat;
	uint8_t payload[4096 + 3];
	uint8_t next_payload[188];
	int n_next_payload;
	int n_payload;
	int next_recv_payload;
	int recv_payload;
	unsigned int continuity_counter;
	uint32_t crc32;
} PSI_parse_t;

typedef struct {
	int aribstr_len;
	uint8_t aribstr[256];
	int str_len;
	TSDCHAR str[256*ARIB_CHAR_SIZE_RATIO];
} Sed_string_t;

typedef Sed_string_t Sd_string_t;

typedef struct {
	int aribdesc_len;
	uint8_t aribdesc[20]; /* ARIB TR-B14�ɂ����ď����16bytes�ƒ�߂��Ă��� */
	int desc_len;
	TSDCHAR desc[20*ARIB_CHAR_SIZE_RATIO+1];
	int aribitem_len;
	uint8_t aribitem[480]; /* ARIB TR-B14�ɂ����ď����440bytes�ƒ�߂��Ă��� */
	int item_len;
	TSDCHAR item[480*ARIB_CHAR_SIZE_RATIO+1];
} Eed_item_string_t;

typedef struct {
	int aribstr_len;
	uint8_t aribstr[20]; /* ARIB TR-B14�ɂ����ď����16bytes�ƒ�߂��Ă��� */
	int str_len;
	TSDCHAR str[20*ARIB_CHAR_SIZE_RATIO+1];
} Eed_desc_t;

typedef struct {
	int aribstr_len;
	uint8_t aribstr[480]; /* ARIB TR-B14�ɂ����ď����440bytes�ƒ�߂��Ă��� */
	int str_len;
	TSDCHAR str[480*ARIB_CHAR_SIZE_RATIO+1];
} Eed_text_t;

typedef struct {
	Eed_desc_t desc;
	Eed_text_t item;
} Eed_itemset_t;

typedef struct {
	unsigned int stream_type : 8;
	unsigned int pid : 16;
} PMT_pid_def_t;

/* �R���e���g�L�q�q (Content descriptor) */
typedef struct {
	unsigned int content_nibble_level_1 : 4;
	unsigned int content_nibble_level_2 : 4;
	unsigned int user_nibble_1 : 4;
	unsigned int user_nibble_2 : 4;
} Cd_t_item;

typedef struct {
	int n_items;
	Cd_t_item items[8]; /* TR-B14�̋K��ł͍ő�7 */
} Cd_t;

typedef struct {
	unsigned int mjd;
	int year;
	int mon;
	int day;
	int hour;
	int min;
	int sec;
	int usec;
} time_mjd_t;

typedef struct {
	int sign;
	int day;
	int hour;
	int min;
	int sec;
	int usec;
} time_offset_t;

typedef struct {

	int status;

	/***** PAT,PMT *****/
	//PSI_parse_t PMT_payload;
	//uint32_t PMT_last_CRC;
	int n_service_pids;
	PMT_pid_def_t service_pids[MAX_PIDS_PER_SERVICE];
	unsigned int service_id : 16;
	unsigned int PCR_pid : 16;

	/* TOT,TDT */
	time_mjd_t TOT_time;
	/* �{����TOT�̓T�[�r�X���Ƃ̃f�[�^�ł͂Ȃ����A
	proginfo�S�̂̃R�s�[�Ȃǂ��\�Ȃ悤�ɒl�Ƃ��Ď������Ă��� */
	uint64_t TOT_PCR;

	/***** PCR *****/
	uint64_t PCR_base;
	unsigned int PCR_ext : 9;
	unsigned int PCR_wraparounded : 1;

	/***** SDT *****/
	unsigned int network_id : 16;
	unsigned int ts_id : 16;

	Sd_string_t service_provider_name;
	Sd_string_t service_name;

	/***** EIT *****/
	unsigned int event_id : 16;

	int curr_desc;
	int last_desc;

	time_mjd_t start;
	time_offset_t dur;

	/* �Z�`���C�x���g�L�q�q */
	Sed_string_t event_name;
	Sed_string_t event_text;

	/* �g���`���C�x���g�L�q�q */
	int n_items;
	//Eed_item_string_t items[8];
	Eed_itemset_t items[8];

	/* �R���e���g�L�q�q */
	Cd_t genre_info;

} proginfo_t;

int get_extended_text(TSDCHAR *dst, size_t n, const proginfo_t *pi);
void get_genre_str(const TSDCHAR **genre1, const TSDCHAR **genre2, Cd_t_item item);
int proginfo_cmp(const proginfo_t *pi1, const proginfo_t *pi2);
int get_stream_timestamp(const proginfo_t *pi, time_mjd_t *jst_time);
int get_stream_timestamp_rough(const proginfo_t *pi, time_mjd_t *time_mjd);
int get_time_offset(time_offset_t *offset, const time_mjd_t *time_target, const time_mjd_t *time_orig);
void time_add_offset(time_mjd_t *dst, const time_mjd_t *orig, const time_offset_t *offset);
