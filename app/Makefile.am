bin_PROGRAMS = ipcon_reg ipcon_dump ipcon_multicast ipcon_server ipcon_cmd

nltest_SOURCES = nltest.c
nltest_CFLAGS = $(LIBNL_CFLAGS) $(LIBNL_GENL_CFLAGS)
nltest_LDADD = $(LIBNL_LIBS) $(LIBNL_GENL_LIBS) $(LIBNL_CLI_LIBS)

nltest2_SOURCES = nltest2.c
nltest2_CFLAGS = $(LIBNL_GENL_CFLAGS)
nltest2_LDADD = $(LIBNL_GENL_LIBS)

nltest_client_SOURCES = nltest_client.c
nltest_client_CFLAGS = $(LIBNL_GENL_CFLAGS)
nltest_client_LDADD = $(LIBNL_GENL_LIBS)

common_cflags = -g -O2 -Wall \
		-I ${top_builddir}/driver/ \
		-I ${top_builddir}/lib/

ipcon_reg_SOURCES = ipcon_reg.c
ipcon_reg_CFLAGS =$(common_cflags)
ipcon_reg_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_reg_LDADD = -lipcon

ipcon_multicast_SOURCES = ipcon_multicast.c
ipcon_multicast_CFLAGS =$(common_cflags)
ipcon_multicast_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_multicast_LDADD = -lipcon

ipcon_server_SOURCES = ipcon_server.c
ipcon_server_CFLAGS =$(common_cflags)
ipcon_server_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_server_LDADD = -lipcon

ipcon_cmd_SOURCES = ipcon_cmd.c
ipcon_cmd_CFLAGS =$(common_cflags)
ipcon_cmd_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_cmd_LDADD = -lipcon

ipcon_dump_SOURCES = ipcon_dump.c
ipcon_dump_CFLAGS =$(common_cflags) \
		-I ${top_builddir}/driver/

AM_CFLAGS = -g -O2 -Wall
