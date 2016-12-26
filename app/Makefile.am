bin_PROGRAMS = nltest nltest2 nltest_client ipcon_reg ipcon_dump

nltest_SOURCES = nltest.c
nltest_CFLAGS = $(LIBNL_CFLAGS) $(LIBNL_GENL_CFLAGS)
nltest_LDADD = $(LIBNL_LIBS) $(LIBNL_GENL_LIBS) $(LIBNL_CLI_LIBS)

nltest2_SOURCES = nltest2.c
nltest2_CFLAGS = $(LIBNL_GENL_CFLAGS)
nltest2_LDADD = $(LIBNL_GENL_LIBS)

nltest_client_SOURCES = nltest_client.c
nltest_client_CFLAGS = $(LIBNL_GENL_CFLAGS)
nltest_client_LDADD = $(LIBNL_GENL_LIBS)

common_cflags = -g -O2 -Wall

ipcon_reg_SOURCES = ipcon_reg.c
ipcon_reg_CFLAGS =$(common_cflags) \
		-I ${top_builddir}/driver/ \
		-I ${top_builddir}/lib/
ipcon_reg_LDFLAGS= -L${top_builddir}/lib/.libs
ipcon_reg_LDADD = -lipcon

ipcon_dump_SOURCES = ipcon_dump.c
ipcon_dump_CFLAGS =$(common_cflags) \
		-I ${top_builddir}/driver/

AM_CFLAGS = -g -O2 -Wall
