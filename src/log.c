/*
 * Copyright (c) 2018-2020 Alexander Naumov <alexander_naumov@opensuse.org>
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
#include<sys/stat.h>
#include<fcntl.h>
#include<stdio.h>
#include<syslog.h>
#include<string.h>
#include<stdlib.h>
#include<stdarg.h>
#include<errno.h>
#include<time.h>

const char *log_path;
const char *log_proc;

void
ilog(int number, char *str)
{
  openlog (log_proc, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
  syslog (LOG_INFO, "%d %s", number, str);
}

void
blog(void *address, char *str)
{
  openlog (log_proc, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
  syslog (LOG_INFO, "%p %s", address, str);
}


void
slog(int arg_count, ...)
{
  int i;
  int len = 0;
  char *LOG = NULL;
  char *str;

  va_list ap;
  va_start(ap, arg_count);

  for (i=1; i <= arg_count; i++) {
    str = va_arg(ap, char *);
    len += strlen(str);

    if (i==1) {
      LOG = (char *)malloc(len + 1);
      if (LOG)
        strcpy (LOG, str);
    }
    else{
      LOG = (char *)realloc(LOG, len + 1);
      if (LOG)
        strcat(LOG, str);
    }
  }
  openlog (log_proc, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
  syslog (LOG_INFO, LOG);
  free(LOG);
}


int
history(char *service, char *access, char *host, char *user, char *msg)
{
  FILE *fp;
  time_t t;
  struct tm *tm;
  char *date;
  char *logfile;

  t = time(NULL);
  tm = localtime(&t);
  if (tm == NULL)
    return 1;

  strftime(date, 24, "-%Y-%m.log", tm);
  logfile = (char *)malloc(strlen(log_path) + strlen(date) + 1);
  if (logfile) {
    strcpy (logfile, log_path);
    strcat (logfile, date);
  }
  else {
    slog(1,"can't allocate memory for logfile entry");
    return 1;
  }

  if ((fp = fopen(logfile, "a")) == NULL) {
    slog(1, "can't open logfile...");
    if (errno == EROFS)
      slog(1, "logfile is on read only FS");
    if (errno == ENOENT)
      slog(1, "bad PATH of logfile");
    return 1;
  }

  strftime(date, 64, "%c", tm);
  if (fprintf(fp, "%-28s %-8s %-5s %10s@%-15s %-20s\n",  date, service, access, user, host, msg) < 0) {
    slog(1, "something goes wrong by put info to the logfile");
    return 1;
  }

  if (fclose(fp) != 0) {
    slog(1, "something goes wrong by closing file");
    return 1;
  }

  free(logfile);
  return 0;
}


void
make_log_prefix(char *service, char *user)
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
  log_proc = log_prefix;
}

