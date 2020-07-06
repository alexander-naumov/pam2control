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

#include <stdarg.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "log.h"

void      slog(int, ...);
void      debug(int, ...);

char *
conv_PIN(pam_handle_t *pamh)
{
  char  *pin = NULL;
  struct pam_conv     *pam_convp;
  struct pam_message  *msg_tmp;
  struct pam_response *response = NULL;

  if (pam_get_item(pamh, PAM_CONV, (const void **)&pam_convp) != PAM_SUCCESS) {
    slog(1, "conv: Can't get PAM_CONV item");
    return pin;
  }

  if ((pam_convp == NULL) || (pam_convp->conv == NULL)) {
    slog(1, "conv: no conversation function defined");
    return pin;
  }

  msg_tmp = (struct pam_message *)calloc(1, sizeof (struct pam_message));
  if (msg_tmp == NULL) {
    slog(1, "conv: out of memory");
    return pin;
  }

  msg_tmp->msg_style = PAM_PROMPT_ECHO_ON;
  msg_tmp->msg       = (char *)"PIN: ";

  const struct pam_message *msg = msg_tmp; 
  (pam_convp->conv)(1, &msg, &response, pam_convp->appdata_ptr);

  if (response)
    pin = strndup(response->resp, 8);
  else {
    debug(1, "pam_convp->conv: NO RESPONCE!");
    pin = (char *)"ERRORPIN";
  }
  debug(3, "conv: entered pin -> '", pin, "'");

  free(response);
  free(msg_tmp);
  return pin;
}
