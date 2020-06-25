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

#include "conv.h"
#include "config.h"
#include "log.h"
#include "smtp.h"

char *    pin_generate(char *);
char *    conv_PIN(pam_handle_t *);
int       email_login_notify(char *, char *, char *, char *, char *);
int       email_pin(char *, char *, char *, char *, char *, char *);
int       history(char *, char *, char *, char *, char *);
void      print_list(node_t *);
void      print_access(access_t *, char *);
void      get_default(settings_t *);
node_t *  get_config(node_t *, char *, char *);
void      slog(int, ...);
void      debug(int, ...);
void      debug_addr(void *, char *);
void      debug_int(int, char *);
access_t *create_access(access_t *, char *, char *, char *, node_t *);
notify_t *create_notify(notify_t *, char *, char *, char *, node_t *);

int DEBUG = 0;
char *log_proc;

char *
rmn(char *str)
{
  if (str == NULL)
    return str;
  int length = strlen(str);
  if (str[length-1] == '\n')
    str[length-1] = '\0';
  return str;
}


char *
pin_generate(char *pin)
{
  ssize_t randval;
  FILE *fd;
  fd = fopen("/dev/urandom", "r");
  fread(&randval, sizeof(randval), 1, fd);
  fclose(fd);

  snprintf(pin, 9, "%zu", randval);
  return pin;
}


int
user_list_checker(access_t *LIST, char *user)
{
  if (LIST) {
    while(LIST){
      rmn(user);
      rmn(LIST->user);
      debug(3, user, " => ", LIST->user);

      if ((strncmp(LIST->user, user, strlen(user)) == 0) &&
          (strlen(LIST->user) == strlen(user))) {
        debug(1, "same!");
        return 1;
      }
      debug(1, "not same, next...");
      LIST = LIST->next;
    }
  }
  debug(1,"--------------");
  return 0;
}


int
send_mail(notify_t *ntf, char *server, char *user, char *host, char *service, char *pin)
{
  int sent_mails = 0;

  while(ntf && ntf->mail && ntf->list){
    while(ntf->list) {
      if ((strncmp(ntf->list->user, user, strlen(user)) == 0) &&
          (strlen (ntf->list->user) == strlen(user))) {

        debug(2,"ntf->list->user = ", ntf->list->user);
        debug(2,"user = ", user);
        if (pin == NULL)
          email_login_notify(server, ntf->mail, host, user, service);
        else
          email_pin(server, ntf->mail, host, user, service, pin);
        /* TODO: add error handling for email funcions; return -1 */
        sent_mails++;
      }
      ntf->list = ntf->list->next;
    }
    ntf = ntf->next;
  }
  return sent_mails;
}


int
allow(pam_handle_t *pamh, char *service, char *user, char* host)
{
  settings_t *def = NULL;
  def = (settings_t *)malloc(sizeof(settings_t));
  if (def == NULL) {
    slog(1, "error, can't allocate memory");
    exit(1);
  }

  get_default(def);

  debug(3, "p2c: DEFAULT - '", def->DEFAULT, "'");
  debug(3, "p2c: MAILSER - '", def->MAILSERVER, "'");
  debug(3, "p2c: LOGFILE - '", def->LOGFILE, "'");

  node_t *conf = NULL;
  conf = get_config(conf, user, service);
  if (DEBUG && conf)
    print_list(conf);

  access_t *OPEN   = NULL;
  access_t *CLOSE  = NULL;
  notify_t *NOTIFY = NULL;
  notify_t *PIN    = NULL;

  OPEN   = create_access(OPEN,   "open",    service, user, conf);
  CLOSE  = create_access(CLOSE,  "close",   service, user, conf);
  NOTIFY = create_notify(NOTIFY, "notify:", service, user, conf);
  PIN    = create_notify(PIN,    "pin:",    service, user, conf);

  if (DEBUG) {
    print_access(OPEN, "OPEN");
    print_access(CLOSE,"CLOSE");
    debug(1,"=============================");
  }

  /* CLOSE */
  if (user_list_checker(CLOSE, user)){
    history(service, "CLOSE", host, user, "access denied (block list)");
    return PAM_AUTH_ERR;
  }

  /*  PIN  */
  char *pin = (char *)malloc(sizeof(char)*8);
  pin = pin_generate(pin);
  debug(2, "generated PIN: ", pin);

  int sent_mails = send_mail(PIN, def->MAILSERVER, user, host, service, pin);
  if (sent_mails < 0) {
    slog(1, "something goes wrong by sending PIN mail");
    return PAM_AUTH_ERR;
  }

  if (sent_mails == 0)
    debug(1, "nobody needs your PIN :)");

  if (sent_mails > 0) {
    debug_int(sent_mails, " PIN mail(s) sent successfully");
    if (!strncmp(pin, conv_PIN(pamh), 8)) {
      debug(1, "PIN (entered by user) is correct");
      send_mail(NOTIFY, def->MAILSERVER, user, host, service, NULL);
      history(service, "OPEN", host, user, "PIN confirmed");
      return PAM_SUCCESS;
    }
    else {
      history(service, "CLOSE", host, user, "wrong PIN provided");
      return PAM_AUTH_ERR;
    }
  }

  /* OPEN */
  if (user_list_checker(OPEN, user)) {
    send_mail(NOTIFY, def->MAILSERVER, user, host, service, NULL);
    history(service, "OPEN", host, user, "access granted");
    return PAM_SUCCESS;
  }

  /* DEFAULT RULE */
  if ((strncmp(def->DEFAULT, "OPEN",  4) == 0) ||
      (strncmp(def->DEFAULT, "open",  4) == 0)) {
    send_mail(NOTIFY, def->MAILSERVER, user, host, service, NULL);
    history(service, "OPEN", host, user, "access granted (default rule)");
    return PAM_SUCCESS;
  }

  history(service, "CLOSE", host, user, "access denied (default rule)");
  return PAM_AUTH_ERR;
}


int
pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  char *user    = NULL;
  char *service = NULL;

  (void) pam_get_user(pamh, (const char **) &user, NULL);
  (void) pam_get_item(pamh, PAM_SERVICE, (const void **) &service);

  asprintf(&log_proc, "pam2control(%s:%s)", service, user);
  slog(1, "==== open new session =========================");
  return PAM_SUCCESS;
}


int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  int ret = PAM_AUTH_ERR;

  char *service = NULL;
  char *user    = NULL;
  char *host    = NULL;

  (void) pam_get_user(pamh, (const char **) &user, NULL); 
  (void) pam_get_item(pamh, PAM_SERVICE, (const void **) &service);
  (void) pam_get_item(pamh, PAM_RHOST, (const void **) &host);

  asprintf(&log_proc, "pam2control(%s:%s)", service, user);
  slog(1, "==== authentication phase =====================");

  for (int i = 0; i<argc; i++)
  {
    if ((argv[i]) && (strncmp(argv[i],"debug",5) == 0))
      DEBUG = 1;
  }

  if (strstr(host,"::1") || strlen(host) == 0)
    host = "localhost";

  ret = allow(pamh, service, user, host);

  if (ret == PAM_SUCCESS){
    slog(1, "access granted");
    return PAM_SUCCESS;
  }

  slog(1, "access denied");
  return ret;
}


int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}


int
pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  char *user    = NULL;
  char *service = NULL;
  char *host    = NULL;

  (void) pam_get_user(pamh, (const char **) &user, NULL);
  (void) pam_get_item(pamh, PAM_SERVICE, (const void **) &service);
  (void) pam_get_item(pamh, PAM_RHOST, (const void **) &host);

  asprintf(&log_proc, "pam2control(%s:%s)", service, user);
  slog(1, "==== closing session ==========================");


  if (strstr(host,"::1") || strlen(host) == 0)
    host = "localhost";

  settings_t *def = NULL;
  def = (settings_t *)malloc(sizeof(settings_t));
  if (def == NULL) {
    slog(1, "error, can't allocate memory");
    exit(1);
  }
  get_default(def);
  slog(2, "closing session: user -> ", user);
  history(service, "OPEN", host, user, "closing session");
  return PAM_SUCCESS;
}

