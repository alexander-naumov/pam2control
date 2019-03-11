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

#include<syslog.h>
#include<string.h>
#include<stdlib.h>

const char *log_p;

void slog(char *log_string)
{
  openlog (log_p, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
  syslog (LOG_INFO, log_string);
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

