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

void       print_list(node_t *);
void       print_access(access_t *, char *);
void       get_default(settings_t *);
int        get_config(node_t *, char *, char *);
void       slog(int number, ...);
void       blog(void *, char *);
void       make_log_prefix(char *, char *);
int        remove_by_service(node_t *, char *);
access_t * create_access(access_t *, char *, node_t *);

int DEBUG = 0;

void rmn(char *str)
{
  if (str == NULL)
    return;
  int length = strlen(str);
  if (str[length-1] == '\n')
    str[length-1] = '\0';
}

int user_list_checker(access_t *LIST, char *user)
{
  if (LIST) {
    slog(1,"after show");
    while(LIST){
      rmn(user);
      rmn(LIST->user);
      slog(3, "LIST->user -> '", LIST->user, "'");
      slog(3, "user -> '", user, "'");

      if (strncmp(LIST->user, user, strlen(user)) == 0) {
        slog(1, "SAME");
        return 1;
      }
      slog(1, "NOT SAME, NEXT...");
      LIST = LIST->next;
    }
  }
  slog(1,"EXIT");
  return 0;
}


int allow(pam_handle_t *pamh, char *service, char *user)
{
  settings_t *def = NULL;
  def = malloc(sizeof(settings_t));
  if (def == NULL) {
    slog(1, "error, can't allocate memory");
    exit(1);
  }

  get_default(def);

  if (DEBUG) {
    slog(3, "p2c: DEFAULT - '", def->DEFAULT, "'");
    slog(3, "p2c: MAILSER - '", def->MAILSERVER, "'");
  }

  node_t *conf = NULL;
  conf = malloc(sizeof(node_t));
  if (conf == NULL){
    slog(1, "error, can't allocate memory");
    exit(1);
  }
  
  get_config(conf, user, service);
  if (DEBUG && conf) {
    slog(1, "SHOW CONF");
    print_list(conf);
  }

  remove_by_service(conf, service);

  if (DEBUG) {
    slog(3,"--- ", service, " ------------------");
    print_list(conf);
  }

  access_t *OPEN  = NULL;
  access_t *CLOSE = NULL;
  OPEN  = create_access(OPEN,  "open",  conf);
  CLOSE = create_access(CLOSE, "close", conf);

  if (DEBUG) {
    print_access(OPEN, "OPEN");
    print_access(CLOSE,"CLOSE");
    slog(1,"=============================");
  }

  if (user_list_checker(CLOSE, user))
    return PAM_AUTH_ERR;

  if (user_list_checker(OPEN, user))
    return PAM_SUCCESS;

  /* DEFAULT RULE */
  if ((strncmp(def->DEFAULT, "OPEN",  4) == 0) ||
      (strncmp(def->DEFAULT, "open",  4) == 0))
    return PAM_SUCCESS;

  return PAM_AUTH_ERR;
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

  for (int i = 0; i<argc; i++)
  {
    if ((argv[i]) && (strncmp(argv[i],"debug",5) == 0))
      DEBUG = 1;
  }
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

