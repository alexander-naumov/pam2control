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
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <stdlib.h>

#include "config.h"
#include "log.h"

void print_list(node_t *);
void get_default(settings_t *);
int get_config(node_t *, char *, char *);
void slog(int number, ...);
void make_log_prefix(char *service, char *user);


int allow(pam_handle_t *pamh, char *service, char *user)
{
  settings_t *def = NULL;
  def = malloc(sizeof(settings_t));
  if (def == NULL) {
    slog(1, "error, can't allocate memory");
    exit(1);
  }

  get_default(def);

  slog(2, "DEFAULT is set to ", def->DEFAULT);
  if (def->DEBUG)
    slog(1, "DEBUG is set to TRUE");
  else
    slog(1, "DEBUG is set to FALSE");

  node_t *conf = NULL;
  conf = malloc(sizeof(node_t));
  if (conf == NULL){
    slog(1, "error, can't allocate memory");
    exit(1);
  }
  
  get_config(conf, user, service);
  slog(1, "I got node_t");

  if (def->DEBUG && conf)
    print_list(conf);

  return PAM_SUCCESS;
  /*
  if (strcmp(def->DEFAULT, "OPEN") == 0)
    return PAM_SUCCESS;
  else
    return PAM_AUTH_ERR;
  */
}


int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  slog(1, "==== open new session =========================");
  return PAM_SUCCESS;
}


int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  char *service = NULL;
  char *user = NULL;
  char *host = NULL;

  (void) pam_get_user(pamh, (const char **) &user, NULL); 
  (void) pam_get_item(pamh, PAM_SERVICE, (const void **) &service);
  (void) pam_get_item(pamh, PAM_RHOST, (const void **) &host);

  make_log_prefix(service, user);
  slog(1, "==== authentication phase =====================");

  if (strstr(host,"::1"))
    host = "localhost";
  
  return allow(pamh, service, user);
}


int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}


int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  slog(1, "==== closing session ==========================");
  return PAM_SUCCESS;
}

