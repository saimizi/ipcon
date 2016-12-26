lib_LTLIBRARIES = libipcon.la

#-Wstrict-aliasing=2 will error (struct sockaddr *) &nl_addr...
libipcon_la_CPPFLAGS =	-Wextra \
			-Werror \
			-Wformat=2 \
			-Wcast-qual \
			-Wcast-align \
			-Wconversion \
			-Wfloat-equal \
			-Wpointer-arith \
			-Wswitch-enum \
			-Wno-unused-function \
			-O2 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 \
			-ftrapv \
			-fstack-protector \
			-I ${top_builddir}/driver

libipcon_la_SOURCES =	libipcon.c libipcon_internal.c
libipcon_la_LDFLAGS = -Wl,--version-script,${srcdir}/ipcon.map -version-info 0:0:0
