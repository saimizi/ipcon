bin_PROGRAMS = ipcon_dump ipcon_user ipcon_server ipcon_sender ipcon_cmd ipcon_evil

common_cflags = -g -O2 -Wall \
		-I ${top_builddir}/driver/ \
		-I ${top_builddir}/lib/ \
		$(LIBNL_GENL_CFLAGS)

common_ldflags =$(LIBNL_GENL_LIBS)

ipcon_user_SOURCES = ipcon_user.c
ipcon_user_CFLAGS =$(common_cflags)
ipcon_user_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_user_LDADD = -lipcon $(common_ldflags)

ipcon_server_SOURCES = ipcon_server.c
ipcon_server_CFLAGS =$(common_cflags)
ipcon_server_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_server_LDADD = -lipcon $(common_ldflags)

ipcon_sender_SOURCES = ipcon_sender.c
ipcon_sender_CFLAGS =$(common_cflags)
ipcon_sender_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_sender_LDADD = -lipcon $(common_ldflags)

ipcon_cmd_SOURCES = ipcon_cmd.c
ipcon_cmd_CFLAGS =$(common_cflags)
ipcon_cmd_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_cmd_LDADD = -lipcon $(common_ldflags)

ipcon_dump_SOURCES = ipcon_dump.c
ipcon_dump_CFLAGS =$(common_cflags) \
		-I ${top_builddir}/driver/

ipcon_evil_SOURCES = ipcon_evil.c
ipcon_evil_CFLAGS =$(common_cflags) \
		-I ${top_builddir}/driver/

AM_CFLAGS = -g -O2 -Wall
