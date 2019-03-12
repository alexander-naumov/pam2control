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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#include "config.h"

void slog(int number, ...);
char *make_log_prefix(char *service, char *user);

int length(struct node* head)
{
  struct node* current = head;
  int count = 0;
  while (current != NULL) {
    count++;
    current = current->next;
  }
  return count;
}

void print_list(node_t *cur)
{
  char *log_node;// = NULL;

  char *cur_service= "Service:   ";
  char *cur_option = "\nOption:    ";
  char *cur_target = "\nTarget:    ";
  char *cur_param  = "\nParameters:";

  //node_t *cur = head;
  while (cur != NULL) {
    log_node = NULL;
    log_node = malloc(
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
    slog(1, log_node);
    cur = cur->next;
  }
  free(log_node);
}

void push(node_t *head, int index, char *service, char *option, char *target, char *param) {
    node_t *cur = head;
    while (cur->next != NULL) {
        cur = cur->next;
    }
    cur->next = malloc(sizeof(node_t));

    cur->next->index   = index;
    cur->next->service = service;
    cur->next->option  = option;
    cur->next->target  = target;
    cur->next->param   = param;

    cur->next->next = NULL;
}

void push_start(node_t **head, int index, char *service, char *option, char *target, char *param) {
    node_t * node;
    node = malloc(sizeof(node_t));

    node->index   = index;
    node->service = service;
    node->option  = option;
    node->target  = target;
    node->param   = param;

    node->next = *head;
    *head = node;
}

int pop(node_t ** head) {
    int retval = -1;
    node_t * next_node = NULL;

    if (*head == NULL) {
        return -1;
    }

    next_node = (*head)->next;
    retval = (*head)->index;
    free(*head);
    *head = next_node;

    return retval;
}

int remove_by_index(node_t ** head, int n) {
    int retval = -1;
    node_t * cur = *head;
    node_t * temp_node = NULL;

    if (n == 0) {
        return pop(head);
    }
    for (int i = 0; i < n-1; i++) {
        if (cur->next == NULL) {
            return -1;
	}
        cur = cur->next;
    }
    //printf("index %d = %p\n", cur->index, (void *)&cur->index);
    temp_node = cur->next;
    retval = temp_node->index;
    cur->next = temp_node->next;
    free(temp_node);

    return retval;
}

int remove_by_service(node_t ** head, char *service)
{
  node_t *cur = *head;
  if (cur == NULL) return -1;

  while (cur->next != NULL) {
    if (strcmp(cur->service, service) != 0) {
      printf("index %d \n", cur->index);
      
      cur->index  = cur->next->index;
      cur->service= cur->next->service;
      cur->option = cur->next->option;
      cur->target = cur->next->target;
      cur->param  = cur->next->param;
      cur->next   = cur->next->next;
    }
    else {
      cur = cur->next;
    }
  }
  return 0;
}

node_t *get_config(node_t *head, char *user, char *service)
{
  char *LOG;
  char *pch;
  char *conf_line[4];
  int i,index = 0;

  FILE *stream;
  char *line = NULL;
  size_t len = 0;

  stream = fopen(CONFFILE, "r");
  if (stream == NULL) {
    slog(2, "can't open file: ", CONFFILE);
    exit(1);
  }
  slog(1, "CONFFILE was opened successfully");

  while ((getline(&line, &len, stream)) != -1) {
    slog(1, line);
    i = 0;
    pch = strtok (line," ");

    while (pch != NULL) {
      conf_line[i] = malloc(sizeof(pch));
      strcpy(conf_line[i], pch);
      pch = strtok (NULL, " ");
      i++;
    }
    head->index   = index;
    head->service = conf_line[0];
    head->option  = conf_line[1];
    head->target  = conf_line[2];
    head->param   = conf_line[3];
    push(head, head->index, head->service, head->option, head->target, head->param);
    index++;
  }
  fclose(stream);
  pop(&head);
  remove_by_service(&head, service);

  //printf("length = %d\n", length(head)); 
  //printf("---------------------------\n");

  //print_list(head);
  free(line);
  //free(head);
  return head;
}


void get_default(settings_t *def)
{
  size_t len = 0;
  FILE *stream;
  char *line = NULL;
  char *pch;
  char *LOG;

  stream = fopen(CONFFILE, "r");
  if (stream == NULL) {
    slog(2, "can't open file: ", CONFFILE);
    exit(1);
  }
  slog(1, "DEBUG: default() CONFFILE was opened successfully");

  while ((getline(&line, &len, stream)) != -1) {
    if (strchr(line, ':') == NULL)
      continue;

    pch = strtok (line,":");
    if (strncmp("MAILSERVER", pch, strlen(pch)) == 0) {
      pch = strtok (NULL, ":");
      def->MAILSERVER = malloc(sizeof(pch));
      strncpy(def->MAILSERVER, pch, sizeof(pch));
    }
    else if (strncmp("DEFAULT", pch, strlen(pch)) == 0) {
      pch = strtok (NULL, ":");
      def->DEFAULT = malloc(sizeof(pch));
      strncpy(def->DEFAULT, pch, sizeof(pch));
    }
    else if (strncmp("DEBUG", pch, strlen(pch)) == 0) {
      pch = strtok (NULL, ":");
      def->DEBUG = malloc(sizeof(pch));
      strncpy(def->DEBUG, pch, sizeof(pch));
    }
  }
  fclose(stream);
}

