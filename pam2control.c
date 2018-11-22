/*
 * Copyright (c) 2018 Alexander Naumov <alexander_naumov@opensuse.org>
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

/*
 * gcc -fPIC -c pam2control.c config.c log.c
 * gcc -shared -o pam2control.so pam2control.o config.o log.o -lpam
*/

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <stdlib.h>

#include "config.h"
#include "log.h"

int get_config(node_t *, char *, char *);
void slog(char *log_string);
char *make_log_prefix(char *service, char *user);

char *get_default()
{
  return "OPEN";
}

int allow(pam_handle_t *pamh, char *log_prefix, char *service, char *user)
{
  char *def0 = "DEFAULT is set to ";
  char *def1 = get_default();

  char *DEFAULT = malloc(
    strlen(def0) +
    strlen(def1) + 1);

  if (DEFAULT) {
    strcpy (DEFAULT, def0);
    strcat (DEFAULT, def1);
  }	  
  slog(DEFAULT);
  free(DEFAULT);
  
  node_t *conf = NULL;
  conf = malloc(sizeof(node_t));
  if (conf == NULL){
    slog("error, can't allocate memory");
    exit(1);
  }
  
  get_config(conf, user, service);
  slog("I got node_t");
  return PAM_SUCCESS;
  /*
  if (strcmp(def1, "OPEN") == r)
    return PAM_SUCCESS;
  else
    return PAM_AUTH_ERR;
  */
}


int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
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

  char *log_prefix = make_log_prefix(service, user);
  slog("==== authentication phase =====================");

  if (strstr(host,"::1"))
    host = "localhost";
  
  return allow(pamh, log_prefix, service, user);
}


int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}


int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

