#ifndef __LIBIPCON_DEBUG_H__

#define __LIBIPCON_DEBUG_H__

#define ipcon_dbg(fmt, ...)	\
	fprintf(stderr, "[libipcon] DEBUG: "fmt, ##__VA_ARGS__)
#define ipcon_info(fmt, ...) \
	fprintf(stderr, "[libipcon] INFO: "fmt, ##__VA_ARGS__)
#define ipcon_warn(fmt, ...) \
	fprintf(stderr, "[libipcon] WARN: "fmt, ##__VA_ARGS__)
#define ipcon_err(fmt, ...) \
	fprintf(stderr, "[libipcon] ERROR: "fmt, ##__VA_ARGS__)

#endif
