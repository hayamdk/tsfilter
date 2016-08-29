#ifdef TSD_PLATFORM_MSVC
#define output_message(type, ...) do { fwprintf(stderr, __VA_ARGS__ ); fprintf(stderr, "\n"); } while(0)
#else
#define output_message(type, ...) do { fprintf(stderr, __VA_ARGS__ ); fprintf(stderr, "\n"); } while(0)
#endif