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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <grp.h>

#include "config.h"
#include "pam2control.h"

void  slog(int, ...);
void  debug(int, ...);
void  debug_addr(void *, char *);
void  debug_int(int, char *);
char *make_log_prefix(char *, char *);
char *rmn(char *);

const char *log_path;

int
length(struct node* head)
{
  struct node* current = head;
  int count = 0;
  while (current != NULL) {
    count++;
    current = current->next;
  }
  return count;
}


void
print_access(access_t *LIST, char *flavor)
{
  debug(3, "==== ACCESS ", flavor, " ===========");
  if (LIST == NULL) {
    debug(1, "NULL...");
    return;
  }

  while(LIST) {
    debug_addr(LIST, LIST->user);
    LIST = LIST->next;
  }
}

void
print_list(node_t *cur)
{
  char *log_node = NULL;

  char *cur_service= "Service:   ";
  char *cur_option = "\nOption:    ";
  char *cur_target = "\nTarget:    ";
  char *cur_param  = "\nParameters:";

  while (cur != NULL) {
    log_node = (char *)malloc(
	  strlen(cur_service) +
	  strlen(cur_option) +
	  strlen(cur_target) +
	  strlen(cur_param) +

	  strlen(cur->service) +
	  strlen(cur->option) +
	  strlen(cur->target) +
	  strlen(cur->param) + 1);

    if (log_node) {
	  strcpy(log_node, cur_service);
	  strcat(log_node, cur->service);

	  strcat(log_node, cur_option);
	  strcat(log_node, cur->option);

	  strcat(log_node, cur_target);
	  strcat(log_node, cur->target);

	  strcat(log_node, cur_param);
	  strcat(log_node, cur->param);
    }
    else
      debug(1,"conf: print_list, can't allocate memory");

    debug(1, log_node);
    debug(1,"-------------");

    if (cur->next != NULL)
      cur = cur->next;
    else
      return;
  }
  free(log_node);
}


char **
get_user_list_group(const char *name)
{
  int errno = 0;
  struct group *grp = NULL;

  if (name == NULL || *name == '\0')
    slog(1, "wrong group name...");

  grp = getgrnam(name);
  if (grp == NULL) {
    if (errno == 0)
      slog(3, "can't find group '", name, "'");
    else
      slog(1, "something goes wrong by getting group info");
    return NULL;
  }
  return grp->gr_mem;
}


access_t *
push_access(access_t *head, char *user)
{
  access_t *cur = NULL;
  cur = (access_t *)malloc(sizeof(access_t));
  if (cur) {
    cur->user = user;
    cur->next = NULL;
    debug_addr(cur, " <- cur");
    debug(2, "cur->user =        ", rmn(cur->user));
  }
  else
    slog(1, "can't allocate memory...");

  if (head) {
    while (head->next != NULL) {
      head = head->next;
      debug_addr(head, " <- head");
    }
    head->next = cur;
  }
  else
    head = cur;

  return head;
}


access_t *
create_access(access_t *head, char *flavor, char *service, node_t* conf)
{
  access_t *cur = NULL;
  while(conf) {
    if ((!strncmp(conf->service, service, strlen(service))) &&
        (!strncmp(conf->option, flavor, strlen(flavor)))    &&
        (conf->param)){

          if (!strncmp(conf->target, "user", 4))
            cur = push_access(cur, conf->param);

          if (!strncmp(conf->target, "group", 5)){
            char **user_list = get_user_list_group(rmn(conf->param));

            if (user_list)
              while (*user_list != NULL) {
                char *name = (char *)malloc(strlen(*user_list) + 1);
                strcpy(name, *user_list);
                cur = push_access(cur, name);
                user_list++;
              }
            else
              slog(3, "group '", conf->param, "' is empty");
          }

    }
    if (!head)
      head = cur;
    conf = conf->next;
  }
  return head;
}


node_t *
push(node_t *head, char *service, char *option, char *target, char *param) {
    node_t *cur = NULL;
    cur = (node_t *)malloc(sizeof(node_t));
    if (cur) {
      cur->service = service;
      cur->option  = option;
      cur->target  = target;
      cur->param   = param;
      cur->next    = NULL;
    }
    else
      slog(1, "Error by parsing config: can't allocate memory...");

    if (head) {
      while (head->next != NULL) {
        head = head->next;
      }
      head->next = cur;
    }
    else
      head = cur;

    return head;
}


node_t *
get_config(node_t *head, char *user, char *service)
{
  node_t *ret = NULL;
  char *pch;
  char *conf_line[4] = {NULL, NULL, NULL, NULL};
  int i = 0;

  FILE *stream;
  char *line = NULL;
  size_t len = 0;

  stream = fopen(CONFFILE, "r");
  if (stream == NULL) {
    slog(2, "can't open file: ", CONFFILE);
    exit(1);
  }

  while ((getline(&line, &len, stream)) != -1) {
    if ((line[0] == '#')                     ||
        (strlen(line) < 9)                   ||
        (strncmp("DEFAULT", line, 7) == 0)   ||
        (strncmp("MAILSERVER", line, 10) == 0))
      continue;

    i = 0;
    pch = strtok (line," ");
    while (pch != NULL) {
      conf_line[i] = strdup(pch);
      pch = strtok (NULL, " ");
      i++;
    }
    if (conf_line[0] && conf_line[1] && conf_line[2] && conf_line[3]) {
      head = push(head, conf_line[0], conf_line[1], conf_line[2], conf_line[3]);
      if (!ret)
        ret = head;
    }
  }
  fclose(stream);
  free(line);
  return ret;
}


void
get_default(settings_t *def)
{
  size_t len = 0;
  FILE *stream;
  char *line = NULL;
  char *pch;

  def->MAILSERVER = NULL;
  def->DEFAULT = "CLOSE";
  def->LOGFILE = "/var/log/pam2control/p2c";

  stream = fopen(CONFFILE, "r");
  if (stream == NULL) {
    slog(2, "can't open file: ", CONFFILE);
    exit(1);
  }

  while ((getline(&line, &len, stream)) != -1) {
    if (strchr(line, ':') == NULL)
      continue;

    pch = strtok (line,":");

    if (strncmp("MAILSERVER", pch, 10) == 0) {
      pch = strtok (NULL, ":");
      def->MAILSERVER = strdup(pch);
      rmn(def->MAILSERVER);
    }

    if (strncmp("DEFAULT", pch, 7) == 0) {
      pch = strtok (NULL, ":");
      def->DEFAULT = strdup(pch);
      rmn(def->DEFAULT);
    }

    if (strncmp("LOGFILE", pch, 7) == 0) {
      pch = strtok (NULL, ":");
      def->LOGFILE = strdup(pch);
      rmn(def->LOGFILE);
    }
    log_path = def->LOGFILE;
  }
  fclose(stream);
}

