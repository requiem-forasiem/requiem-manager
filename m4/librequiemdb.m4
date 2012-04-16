dnl Autoconf macros for librequiemdb
dnl $id$

# Modified for LIBREQUIEMDB -- Yoann Vandoorselaere
# Modified for LIBGNUTLS -- nmav
# Configure paths for LIBGCRYPT
# Shamelessly stolen from the one of XDELTA by Owen Taylor
# Werner Koch   99-12-09

dnl AM_PATH_LIBREQUIEMDB([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]], THREAD_SUPPORT)
dnl Test for librequiemdb, and define LIBREQUIEMDB_CFLAGS, LIBREQUIEMDB_LDFLAGS, and LIBREQUIEMDB_LIBS
dnl
AC_DEFUN([AM_PATH_LIBREQUIEMDB],
[dnl
dnl Get the cflags and libraries from the librequiemdb-config script
dnl
AC_ARG_WITH(librequiemdb-prefix, AC_HELP_STRING(--with-librequiemdb-prefix=PFX, 
		                                Prefix where librequiemdb is installed (optional)),
          librequiemdb_config_prefix="$withval", librequiemdb_config_prefix="")

  if test x$librequiemdb_config_prefix != x ; then
     if test x${LIBREQUIEMDB_CONFIG+set} != xset ; then
        LIBREQUIEMDB_CONFIG=$librequiemdb_config_prefix/bin/librequiemdb-config
     fi
  fi

  AC_PATH_PROG(LIBREQUIEMDB_CONFIG, librequiemdb-config, no)

  if test "$LIBREQUIEMDB_CONFIG" != "no"; then
        if $($LIBREQUIEMDB_CONFIG --thread > /dev/null 2>&1); then
                if test x$4 = xtrue || test x$4 = xyes; then
                        librequiemdb_config_args="--thread"
                fi
        fi
  fi

  min_librequiemdb_version=ifelse([$1], ,0.1.0,$1)
  AC_MSG_CHECKING(for librequiemdb - version >= $min_librequiemdb_version)
  no_librequiemdb=""
  if test "$LIBREQUIEMDB_CONFIG" = "no" ; then
    no_librequiemdb=yes
  else
    LIBREQUIEMDB_CFLAGS=`$LIBREQUIEMDB_CONFIG $librequiemdb_config_args $librequiemdb_config_args --cflags`
    LIBREQUIEMDB_LDFLAGS=`$LIBREQUIEMDB_CONFIG $librequiemdb_config_args $librequiemdb_config_args --ldflags`
    LIBREQUIEMDB_LIBS=`$LIBREQUIEMDB_CONFIG $librequiemdb_config_args $librequiemdb_config_args --libs`
    librequiemdb_config_version=`$LIBREQUIEMDB_CONFIG $librequiemdb_config_args --version`


      ac_save_CFLAGS="$CFLAGS"
      ac_save_LDFLAGS="$LDFLAGS"
      ac_save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $LIBREQUIEMDB_CFLAGS"
      LDFLAGS="$LDFLAGS $LIBREQUIEMDB_LDFLAGS"
      LIBS="$LIBS $LIBREQUIEMDB_LIBS"
dnl
dnl Now check if the installed librequiemdb is sufficiently new. Also sanity
dnl checks the results of librequiemdb-config to some extent
dnl
      rm -f conf.librequiemdbtest
      AC_TRY_RUN([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <librequiemdb/requiemdb-version.h>

int
main ()
{
    system ("touch conf.librequiemdbtest");

    if( strcmp( requiemdb_check_version(NULL), "$librequiemdb_config_version" ) )
    {
      printf("\n*** 'librequiemdb-config --version' returned %s, but LIBREQUIEMDB (%s)\n",
             "$librequiemdb_config_version", requiemdb_check_version(NULL) );
      printf("*** was found! If librequiemdb-config was correct, then it is best\n");
      printf("*** to remove the old version of LIBREQUIEMDB. You may also be able to fix the error\n");
      printf("*** by modifying your LD_LIBRARY_PATH enviroment variable, or by editing\n");
      printf("*** /etc/ld.so.conf. Make sure you have run ldconfig if that is\n");
      printf("*** required on your system.\n");
      printf("*** If librequiemdb-config was wrong, set the environment variable LIBREQUIEMDB_CONFIG\n");
      printf("*** to point to the correct copy of librequiemdb-config, and remove the file config.cache\n");
      printf("*** before re-running configure\n");
    }
    else if ( strcmp(requiemdb_check_version(NULL), LIBREQUIEMDB_VERSION ) )
    {
      printf("\n*** LIBREQUIEMDB header file (version %s) does not match\n", LIBREQUIEMDB_VERSION);
      printf("*** library (version %s)\n", requiemdb_check_version(NULL) );
    }
    else
    {
      if ( requiemdb_check_version( "$min_librequiemdb_version" ) )
      {
        return 0;
      }
     else
      {
        printf("no\n*** An old version of LIBREQUIEMDB (%s) was found.\n",
                requiemdb_check_version(NULL) );
        printf("*** You need a version of LIBREQUIEMDB newer than %s. The latest version of\n",
               "$min_librequiemdb_version" );
        printf("*** LIBREQUIEMDB is always available from https://github.com/requiem-forasiem/librequiemdb\n");
        printf("*** \n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the librequiemdb-config shell script is\n");
        printf("*** being found. The easiest way to fix this is to remove the old version\n");
        printf("*** of LIBREQUIEMDB, but you can also set the LIBREQUIEMDB_CONFIG environment to point to the\n");
        printf("*** correct copy of librequiemdb-config. (In this case, you will have to\n");
        printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
        printf("*** so that the correct libraries are found at run-time))\n");
      }
    }
  return 1;
}
],, no_librequiemdb=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"
       LDFLAGS="$ac_save_LDFLAGS"
  fi

  if test "x$no_librequiemdb" = x ; then
     AC_MSG_RESULT(yes)
     ifelse([$2], , :, [$2])
  else
     if test -f conf.librequiemdbtest ; then
        :
     else
        AC_MSG_RESULT(no)
     fi
     if test "$LIBREQUIEMDB_CONFIG" = "no" ; then
       echo "*** The librequiemdb-config script installed by LIBREQUIEMDB could not be found"
       echo "*** If LIBREQUIEMDB was installed in PREFIX, make sure PREFIX/bin is in"
       echo "*** your path, or set the LIBREQUIEMDB_CONFIG environment variable to the"
       echo "*** full path to librequiemdb-config."
     else
       if test -f conf.librequiemdbtest ; then
        :
       else
          echo "*** Could not run librequiemdb test program, checking why..."
          CFLAGS="$CFLAGS $LIBREQUIEMDB_CFLAGS"
	  LDFLAGS="$LDFLAGS $LIBREQUIEMDB_LDFLAGS"
          LIBS="$LIBS $LIBREQUIEMDB_LIBS"
          AC_TRY_LINK([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <librequiemdb/requiemdb-version.h>
],      [ return !!requiemdb_check_version(NULL); ],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding LIBREQUIEMDB or finding the wrong"
          echo "*** version of LIBREQUIEMDB. If it is not finding LIBREQUIEMDB, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
          echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"
          echo "***" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means LIBREQUIEMDB was incorrectly installed"
          echo "*** or that you have moved LIBREQUIEMDB since it was installed. In the latter case, you"
          echo "*** may want to edit the librequiemdb-config script: $LIBREQUIEMDB_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
	  LDFLAGS="$ac_save_LDFLAGS"
          LIBS="$ac_save_LIBS"
       fi
     fi
     LIBREQUIEMDB_CFLAGS=""
     LIBREQUIEMDB_LDFLAGS=""
     LIBREQUIEMDB_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  rm -f conf.librequiemdbtest
  AC_SUBST(LIBREQUIEMDB_CFLAGS)
  AC_SUBST(LIBREQUIEMDB_LDFLAGS)
  AC_SUBST(LIBREQUIEMDB_LIBS)
])

dnl *-*wedit:notab*-*  Please keep this as the last line.
