/*
 * Copyright (c) 2018, 2019 Alexander Naumov <alexander_naumov@opensuse.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING); if not, see
 * http://www.gnu.org/licenses/, or contact Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 *
 ****************************************************************
 */

#define _GNU_SOURCE
#include<stdio.h>
#include<syslog.h>
#include<string.h>
#include<stdlib.h>
#include<stdarg.h>

const char *log_p;

void slog(int arg_count, ...)
{
  int i;
  va_list ap;
  va_start(ap, arg_count);

  char *str;
  int len = 0;
  for (i=1; i <= arg_count; i++) {
    str = va_arg(ap, char *);
    len += strlen(str);
  }

  va_start(ap, arg_count);

  char *LOG = malloc(len + 1);
  if (LOG) {
    strcpy (LOG, va_arg(ap, char *));

    for (i = 2; i <= arg_count; i++)
      strcat(LOG, va_arg(ap, char *));
  }
  openlog (log_p, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
  syslog (LOG_INFO, LOG);
  free(LOG);
}


char *make_log_prefix(char *service, char *user)
{
  char *begin = "pam2control(";
  char *spliter = ":";
  char *end = ")";

  char *log_prefix;
  log_prefix = malloc(
        strlen(begin) +
        strlen(service) +
        strlen(spliter) +
        strlen(user) +
        strlen(end) + 1);

  if (log_prefix) {
        strcpy (log_prefix, begin);
        strcat (log_prefix, service);
        strcat (log_prefix, spliter);
        strcat (log_prefix, user);
        strcat (log_prefix, end);
  }
  log_p = log_prefix;
  return log_prefix;
}

