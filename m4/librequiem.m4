dnl Autoconf macros for librequiem
dnl $id$

# Modified for LIBREQUIEM -- Yoann Vandoorselaere
# Modified for LIBGNUTLS -- nmav
# Configure paths for LIBGCRYPT
# Shamelessly stolen from the one of XDELTA by Owen Taylor
# Werner Koch   99-12-09

dnl AM_PATH_LIBREQUIEM([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]], THREAD_SUPPORT)
dnl Test for librequiem, and define LIBREQUIEM_PREFIX, LIBREQUIEM_CFLAGS, LIBREQUIEM_PTHREAD_CFLAGS,
dnl LIBREQUIEM_LDFLAGS, and LIBREQUIEM_LIBS
dnl
AC_DEFUN([AM_PATH_LIBREQUIEM],
[dnl
dnl Get the cflags and libraries from the librequiem-config script
dnl
AC_ARG_WITH(librequiem-prefix, AC_HELP_STRING(--with-librequiem-prefix=PFX,
            Prefix where librequiem is installed (optional)),
            librequiem_config_prefix="$withval", librequiem_config_prefix="")

  if test x$librequiem_config_prefix != x ; then
     if test x${LIBREQUIEM_CONFIG+set} != xset ; then
        LIBREQUIEM_CONFIG=$librequiem_config_prefix/bin/librequiem-config
     fi
  fi

  AC_PATH_PROG(LIBREQUIEM_CONFIG, librequiem-config, no)
  if test "$LIBREQUIEM_CONFIG" != "no"; then
  	if $($LIBREQUIEM_CONFIG --thread > /dev/null 2>&1); then
        	LIBREQUIEM_PTHREAD_CFLAGS=`$LIBREQUIEM_CONFIG --thread --cflags`

        	if test x$4 = xtrue || test x$4 = xyes; then
                	librequiem_config_args="--thread"
        	else
                	librequiem_config_args="--no-thread"
        	fi
  	else
        	LIBREQUIEM_PTHREAD_CFLAGS=`$LIBREQUIEM_CONFIG --pthread-cflags`
  	fi
  fi

  min_librequiem_version=ifelse([$1], ,0.1.0,$1)
  AC_MSG_CHECKING(for librequiem - version >= $min_librequiem_version)
  no_librequiem=""
  if test "$LIBREQUIEM_CONFIG" = "no" ; then
    no_librequiem=yes
  else
    LIBREQUIEM_CFLAGS=`$LIBREQUIEM_CONFIG $librequiem_config_args --cflags`
    LIBREQUIEM_LDFLAGS=`$LIBREQUIEM_CONFIG $librequiem_config_args --ldflags`
    LIBREQUIEM_LIBS=`$LIBREQUIEM_CONFIG $librequiem_config_args --libs`
    LIBREQUIEM_PREFIX=`$LIBREQUIEM_CONFIG $librequiem_config_args --prefix`
    LIBREQUIEM_CONFIG_PREFIX=`$LIBREQUIEM_CONFIG $librequiem_config_args --config-prefix`
    librequiem_config_version=`$LIBREQUIEM_CONFIG $librequiem_config_args --version`


      ac_save_CFLAGS="$CFLAGS"
      ac_save_LDFLAGS="$LDFLAGS"
      ac_save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $LIBREQUIEM_CFLAGS"
      LDFLAGS="$LDFLAGS $LIBREQUIEM_LDFLAGS"
      LIBS="$LIBS $LIBREQUIEM_LIBS"
dnl
dnl Now check if the installed librequiem is sufficiently new. Also sanity
dnl checks the results of librequiem-config to some extent
dnl
      rm -f conf.librequiemtest
      AC_TRY_RUN([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <librequiem/requiem.h>

int
main ()
{
    system ("touch conf.librequiemtest");

    if( strcmp( requiem_check_version(NULL), "$librequiem_config_version" ) )
    {
      printf("\n*** 'librequiem-config --version' returned %s, but LIBREQUIEM (%s)\n",
             "$librequiem_config_version", requiem_check_version(NULL) );
      printf("*** was found! If librequiem-config was correct, then it is best\n");
      printf("*** to remove the old version of LIBREQUIEM. You may also be able to fix the error\n");
      printf("*** by modifying your LD_LIBRARY_PATH enviroment variable, or by editing\n");
      printf("*** /etc/ld.so.conf. Make sure you have run ldconfig if that is\n");
      printf("*** required on your system.\n");
      printf("*** If librequiem-config was wrong, set the environment variable LIBREQUIEM_CONFIG\n");
      printf("*** to point to the correct copy of librequiem-config, and remove the file config.cache\n");
      printf("*** before re-running configure\n");
    }
    else if ( strcmp(requiem_check_version(NULL), LIBREQUIEM_VERSION ) ) {
        printf("\n*** LIBREQUIEM header file (version %s) does not match\n", LIBREQUIEM_VERSION);
        printf("*** library (version %s)\n", requiem_check_version(NULL) );
    }
    else {
      if ( requiem_check_version( "$min_librequiem_version" ) )
        return 0;
      else {
        printf("no\n*** An old version of LIBREQUIEM (%s) was found.\n",
                requiem_check_version(NULL) );
        printf("*** You need a version of LIBREQUIEM newer than %s. The latest version of\n",
               "$min_librequiem_version" );
        printf("*** LIBREQUIEM is always available from https://github.com/requiem-forasiem/librequiem\n");
        printf("*** \n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the librequiem-config shell script is\n");
        printf("*** being found. The easiest way to fix this is to remove the old version\n");
        printf("*** of LIBREQUIEM, but you can also set the LIBREQUIEM_CONFIG environment to point to the\n");
        printf("*** correct copy of librequiem-config. (In this case, you will have to\n");
        printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
        printf("*** so that the correct libraries are found at run-time))\n");
      }
    }
    return 1;
}
],, no_librequiem=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"
       LDFLAGS="$ac_save_LDFLAGS"
  fi

  if test "x$no_librequiem" = x ; then
     AC_MSG_RESULT(yes)
     ifelse([$2], , :, [$2])
  else
     if test -f conf.librequiemtest ; then
        :
     else
        AC_MSG_RESULT(no)
     fi
     if test "$LIBREQUIEM_CONFIG" = "no" ; then
       echo "*** The librequiem-config script installed by LIBREQUIEM could not be found"
       echo "*** If LIBREQUIEM was installed in PREFIX, make sure PREFIX/bin is in"
       echo "*** your path, or set the LIBREQUIEM_CONFIG environment variable to the"
       echo "*** full path to librequiem-config."
     else
       if test -f conf.librequiemtest ; then
        :
       else
          echo "*** Could not run librequiem test program, checking why..."
          CFLAGS="$CFLAGS $LIBREQUIEM_CFLAGS"
          LDFLAGS="$LDFLAGS $LIBREQUIEM_LDFLAGS"
          LIBS="$LIBS $LIBREQUIEM_LIBS"
          AC_TRY_LINK([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <librequiem/requiem.h>
],      [ return !!requiem_check_version(NULL); ],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding LIBREQUIEM or finding the wrong"
          echo "*** version of LIBREQUIEM. If it is not finding LIBREQUIEM, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
          echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"
          echo "***" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means LIBREQUIEM was incorrectly installed"
          echo "*** or that you have moved LIBREQUIEM since it was installed. In the latter case, you"
          echo "*** may want to edit the librequiem-config script: $LIBREQUIEM_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
          LDFLAGS="$ac_save_LDFLAGS"
          LIBS="$ac_save_LIBS"
       fi
     fi
     LIBREQUIEM_CFLAGS=""
     LIBREQUIEM_LDFLAGS=""
     LIBREQUIEM_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  rm -f conf.librequiemtest
  AC_SUBST(LIBREQUIEM_CFLAGS)
  AC_SUBST(LIBREQUIEM_PTHREAD_CFLAGS)
  AC_SUBST(LIBREQUIEM_LDFLAGS)
  AC_SUBST(LIBREQUIEM_LIBS)
  AC_SUBST(LIBREQUIEM_PREFIX)
  AC_SUBST(LIBREQUIEM_CONFIG_PREFIX)

  m4_ifdef([LT_INIT],
           [AC_DEFINE([REQUIEM_APPLICATION_USE_LIBTOOL2], [], [Define whether application use libtool >= 2.0])],
           [])

])

dnl *-*wedit:notab*-*  Please keep this as the last line.
