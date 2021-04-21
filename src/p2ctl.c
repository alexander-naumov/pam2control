/*
 * Copyright (c) 2020-2021 Alexander Naumov <alexander_naumov@opensuse.org>
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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define VERSION "0.3 beta (17.04.21)\0"

char *pam_path[] = {
  "/lib/security",
  "/lib64/security",
  "/lib/x86_64-linux-gnu",
  "/lib/i386-linux-gnu",
  "/usr/lib/x86_64-linux-gnu",
  "/usr/lib/x86_64-linux-gnu/security",
  "/usr/lib/i386-linux-gnu",
  "/usr/lib/i386-linux-gnu/security",
  "/usr/lib"                           /* FreeBSD */
};


void
usage(int ret)
{
printf("\nUsage: p2ctl [OPTIONS]... [FILE]...\n\n");
printf("Available options:\n");
printf("  pam_configure  [service] - configure daemon to use pam2control\n");
printf("  pam_configured [service] - configure daemon to use pam2control (debug mode)\n");
printf("  search_path              - show PATH of PAM modules\n");
printf("  version                  - show version of pam2control\n");
printf("  help                     - show this help message\n\n");
exit(ret);
}


char *
modules_search(char *PATH[])
{
  DIR *dp;
  struct dirent *ep;

  if (PATH[0] == NULL)
    return NULL;

  dp = opendir (PATH[0]);
  if (dp != NULL) {
    while ((ep = readdir (dp)) != NULL) {
      if (strncmp(ep->d_name, "pam_", 4) == 0) {
        (void) closedir (dp);
        return PATH[0];
      }
    }
    (void) closedir (dp);
  }
  return modules_search(&PATH[1]);
}


void
pam_configure(char *service, int debug)
{
  int fd;
  ssize_t fd_w;
  char *path;
  char *conf;

  if (debug)
    asprintf(&conf,
           "auth       required     pam2control.so debug\n" \
           "session    required     pam2control.so debug\n");
  else
    asprintf(&conf,
           "auth       required     pam2control.so\n" \
           "session    required     pam2control.so\n");

  asprintf(&path, "/etc/pam.d/%s", service);

  if ((fd = open(path, O_WRONLY)) < 0) {
    fprintf(stderr, "open: %s\n", strerror(errno));
    exit(1);
  }

  if (lseek(fd, 0, SEEK_END) < 0) {
    fprintf(stderr, "lseek: %s\n", strerror(errno));
    exit(1);
  }

  if ((fd_w = write(fd, conf, strlen(conf))) != strlen(conf)) {
    fprintf(stderr, "write: %s\n", strerror(errno));
    exit(1);
  }

  close(fd);
  free(path);
  free(conf);
}


void
pam_list()
{
  struct dirent *dir;
  DIR *dp = opendir("/etc/pam.d/");

  if (dp != NULL) {
    while ((dir = readdir (dp)) != NULL) {
      if (strcmp(dir->d_name, ".") != 0 &&
          strcmp(dir->d_name, "..") != 0)
        printf("%s\n", dir->d_name);
    }
  }
  (void) closedir (dp);
}


int main(int argc, char *argv[])
{
  /* TODO
   * rem info from /etc/pam.d/sshd, etc
   * check my config
   * everything from pam-accesscontrol
   */

  if (argc == 1 || argc == 2 && argv[1]) {
    if (!strncmp(argv[1], "version", 7))
      printf("Version: %s\n\n", VERSION);

    if (!strncmp(argv[1], "help", 4))
      usage(0);

    if (!strncmp(argv[1], "search_path", 11))
      printf("%s\n", modules_search(pam_path));

    if (!strncmp(argv[1], "pam_list", 8))
      pam_list();

    else
      usage(1);
  }

  if (argc == 3 && argv[1] && argv[2]) {

    if (!strncmp(argv[1], "pam_configured", 14))
      pam_configure(argv[2], 1);

    else if (!strncmp(argv[1], "pam_configure", 13))
      pam_configure(argv[2], 0);

    else
      usage(1);
  }

  return 0;
}
