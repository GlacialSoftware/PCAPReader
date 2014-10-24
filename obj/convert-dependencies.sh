#!/bin/sh
# AUTO-GENERATED FILE, DO NOT EDIT!
if [ -f $1.org ]; then
  sed -e 's!^C:/cygwin/lib!/usr/lib!ig;s! C:/cygwin/lib! /usr/lib!ig;s!^C:/cygwin/bin!/usr/bin!ig;s! C:/cygwin/bin! /usr/bin!ig;s!^C:/cygwin/!/!ig;s! C:/cygwin/! /!ig;s!^U:!/cygdrive/u!ig;s! U:! /cygdrive/u!ig;s!^T:!/cygdrive/t!ig;s! T:! /cygdrive/t!ig;s!^N:!/cygdrive/n!ig;s! N:! /cygdrive/n!ig;s!^M:!/cygdrive/m!ig;s! M:! /cygdrive/m!ig;s!^L:!/cygdrive/l!ig;s! L:! /cygdrive/l!ig;s!^K:!/cygdrive/k!ig;s! K:! /cygdrive/k!ig;s!^J:!/cygdrive/j!ig;s! J:! /cygdrive/j!ig;s!^E:!/cygdrive/e!ig;s! E:! /cygdrive/e!ig;s!^C:!/cygdrive/c!ig;s! C:! /cygdrive/c!ig;' $1.org > $1 && rm -f $1.org
fi
