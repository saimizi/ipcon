AC_INIT([nltest],0.0.1)

AM_INIT_AUTOMAKE([foreign])

# 古いバージョンのautomakeはAM_SILENT_RULESをサポートしていないため、
# 比較安全な使い方として、次のとおり、AM_SILENT_RULESがサポートされて入れば、定義するとの意味
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])

# デフォルトsilent-rulesを有効
# この使い方はAutomakeはバージョン1.11以降である必要がある
AM_SILENT_RULES([yes])

# ソースコードのディレクトリを示す
#AC_CONFIG_SRCDIR([src/main.c])

#AC_CONFIG_HEADERS([config.h])


# CFLAGSは指定されていない場合、AC_PROG_CC はデフォルトの「-g -O2」を指定する。
# これを防ぐため、AC_INITとAC_PROG_CCの間でCFLAGSを""に指定すれば良い。
# 同様CXXFLAGSも同じ
# AC_PROG_CCのマニュアルをご参照
: ${CFLAGS=""}
: ${CXXFLAGS=""}

AC_PROG_CC
AC_PROG_CXX

# pkg-configを用いて使用するライブラリのパスを取得
# "libnl-genl-3.0" はpkg-config --list-allで検索できる
# これによって、libnl-genl-3.0パスはMakeifle.amにおいて、
# 下記のように参照できる
#	CFLAGS(-I): $(LIBNL_GENL_CFLAGS)
#	LDFLAGS(-l): $(LIBNL_GENL_LIBS)
PKG_CHECK_MODULES([LIBNL], [libnl-3.0])
PKG_CHECK_MODULES([LIBNL_GENL], [libnl-genl-3.0])
PKG_CHECK_MODULES([LIBNL_CLI], [libnl-cli-3.0])


# --with-fooの使い方
# configure時--with-fooで設定した値はwith_fooに保存される
# ここ、--with-ksrcを用いて、Linuxカーネルのソースパスを取得する
AC_ARG_WITH([ksrc],
	AS_HELP_STRING([--with-ksrc],[Linux kernel path.]))

AS_IF([test "x$with_ksrc" != "x"],
	[ksrc=$with_ksrc],
	[ksrc="/lib/modules/`uname -r`/build"])


# Makeifle.in内の@ksrc@を置き換える
# Makifile.n内で、KSRC=@ksrc@で記述すれば,生成されたMakefile内で置き換えられる
# ここは、driver/Makefile.in内で使用
# ドライバをビルドするため、Autotoolのルールを使用しない。
# このため、Makefile.amの代わりにMakefile.inを使用
AC_SUBST(ksrc)

AC_CONFIG_FILES([Makefile
		 app/Makefile
		 driver/Makefile
		])
AC_OUTPUT

echo \
"-------------------------------------------------

${PACKAGE_NAME} Version ${PACKAGE_VERSION}

Prefix: '${prefix}'.
Compiler: '${CC} ${CFLAGS} ${CPPFLAGS}'

Package features:
	kernel src: ${ksrc}

-------------------------------------------------"
