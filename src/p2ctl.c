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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>

char *VERSION = "0.3 beta (16.04.21)";

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
printf("  search_path  - show PATH of PAM modules\n");
printf("  version      - show version of pam2control\n");
printf("  help         - show this help message\n\n");

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


int main(int argc, char *argv[])
{
  /* TODO
   * add info to   /etc/pam.d/sshd, etc
   * rem info from /etc/pam.d/sshd, etc
   * show list
   * check my config
   * everything from pam-accesscontrol
   */

  if (argc == 1)
    usage(1);

  if (argc == 2 && argv[1]) {
    if (!strncmp(argv[1], "version", 7)) {
      printf("Version %s\n\n", VERSION);
      return 0;
    }
    if (!strncmp(argv[1], "help", 4))
      usage(0);

    if (!strncmp(argv[1], "search_path", 11))
      printf("%s\n", modules_search(pam_path));

    else
      usage(1);
  }
  
  return 0;
}
