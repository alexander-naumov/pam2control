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
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>

#include "log.h"

#define HOSTLEN           256
#define SMTP_PORT         25
#define SMTP_MTU          800
#define MAX_EMAIL_LEN     64
#define SOCK_WRITE        1
#define SOCK_READ         0

void      slog(int, ...);
void      debug(int, ...);
void      debug_int(int, char *);

int
connect_smtp(char* server, short port)
{
  int sock = -1;
  struct sockaddr_in conn;
  struct hostent *host = NULL;

  if((host = gethostbyname(server)) == NULL) {
    debug(2, "gethostbyname: ", strerror(errno));
    return -1;
  }

  conn.sin_family = AF_INET;
  conn.sin_port   = htons(port);
  conn.sin_addr   = *((struct in_addr *)host->h_addr);

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    debug(2, "socket: ", strerror(errno));
    return -1;
  }

  if (connect(sock, (struct sockaddr *)&conn, sizeof(conn)) < 0) {
    close(sock);
    debug(2, "connect: ", strerror(errno));
    return -1;
  }
  return sock;
}


int
socket_io(short IO, int sock, char *data, int len_IO)
{
  fd_set fd;
  struct timeval tv;
  int ret;
  int len = 0;

  if ((0 >= len_IO) || (data == NULL))
    return -1;

  FD_ZERO(&fd);
  FD_SET(sock, &fd);

  tv.tv_sec  = 5;
  tv.tv_usec = 0;

  while(1)
  {
    if (IO == SOCK_WRITE)
      ret = select(sock+1, (fd_set *)NULL, &fd, (fd_set *)NULL, &tv);
    else
      ret = select(sock+1, &fd, (fd_set *)NULL, (fd_set *)NULL, &tv);

    if (ret < 0)
      slog(2, "select: ", strerror(errno));

    else if (ret == 0)
      continue;

    else
      if(FD_ISSET(sock, &fd)) {
        if (IO == SOCK_WRITE)
          len = send(sock, data, len_IO, 0);
        else
          len = recv(sock, data, len_IO, 0);
        break;
      }
  }
  return len;
}


/*
 *  The communication between the sender and receiver is intended to
 *  be an alternating dialogue, controlled by the sender.  As such,
 *  the sender issues a command and the receiver responds with a
 *  reply.  The sender must wait for this response before sending
 *  further commands.
 *  More info: http://www.ietf.org/rfc/rfc821.txt
 */
int
check_status(char *recv_str)
{
  char status[4] = {0};
  strncpy(status, recv_str, 3);

  switch (atoi(status)) {
    case 220:  break; /* Service ready */
    case 221:  break; /* Service closing transmission channel */
    case 250:  break; /* Requested mail action okay, completed */
    case 251:  break; /* User not local; will forward to <forward-path> */
    case 354:  break; /* Start mail input; end with <CRLF>.<CRLF> */
    default:
    {
      slog(2, "error MTA reply: ", recv_str);
      return -1;
    }
  }

  debug_int(atoi(status), " successfully returned from mail server");
  return 0;
}


int
send_email(int sock, char *from, char *to, char *mail, int mail_len)
{
  int ret, err = 0;
  char data[SMTP_MTU] = {0};

  /* === MAIL FROM ======================================== */
  memset(&data, 0, SMTP_MTU);
  sprintf(data, "MAIL FROM:<%s>\r\n", from);
  socket_io(SOCK_WRITE, sock, data, strlen(data));

  memset(&data, 0, SMTP_MTU);
  socket_io(SOCK_READ, sock, data, SMTP_MTU);

  debug(2, "MAIL FROM answer: ", data);
  if ((ret = check_status(data)) == -1)
    err = ret;


  /* === RCPT TO ========================================== */
  memset(&data, 0, SMTP_MTU);
  sprintf(data, "RCPT TO:<%s>\r\n", to);
  socket_io(SOCK_WRITE, sock, data, strlen(data));

  memset(&data, 0, SMTP_MTU);
  socket_io(SOCK_READ, sock, data, SMTP_MTU);

  debug(2, "RCPT TO answer: ", data);
  if ((ret = check_status(data)) == -1)
    err = ret;

  /* === DATA ============================================= */
  memset(&data, 0, SMTP_MTU);
  socket_io(SOCK_WRITE, sock, "DATA\r\n", strlen("DATA\r\n"));

  memset(&data, 0, SMTP_MTU);
  socket_io(SOCK_READ, sock, data, SMTP_MTU);

  debug(2, "DATA answer: ", data);
  if ((ret = check_status(data)) == -1)
    err = ret;

  /* === MAIL TEXT ======================================== */
  socket_io(SOCK_WRITE, sock, mail, mail_len);

  memset(&data, 0, SMTP_MTU);
  socket_io(SOCK_READ, sock, data, SMTP_MTU);

  debug(2, "MAIL answer: ", data);
  if ((ret = check_status(data)) == -1)
    err = ret;

  /* === QUIT ============================================= */
  memset(&data, 0, SMTP_MTU);
  socket_io(SOCK_WRITE, sock, "QUIT\r\n", strlen("QUIT\r\n"));

  memset(&data, 0, SMTP_MTU);
  socket_io(SOCK_READ, sock, data, SMTP_MTU);

  debug(2, "QUIT answer: ", data);
  if ((ret = check_status(data)) == -1)
    err = ret;

  return err;
}

int
email_login_notify(char *server, char *to, char *host, char *user, char *service)
{
  int  sock  = 0;
  char *mail = NULL;
  char *subj = NULL;
  char *body = NULL;
  char *from = NULL;

  char hostnm[HOSTLEN];
  gethostname(hostnm, HOSTLEN);
  char *hostname = hostnm;

  asprintf(&from, "pam2control@%s", hostname);
  asprintf(&subj, "[p2c] %s login on %s", service, hostname);
  asprintf(&body,
    "*** Security notification ***\nSource:  %s\nTarget:  %s\nService: %s\nUser:   %s\n\nSuccessfully logged in",
    host, hostname, service, user);
  asprintf(&mail, "Subject: %s\r\n%s\r\n.\r\n", subj, body);

  debug(2, "server = ", server);
  if ((sock = connect_smtp(server, SMTP_PORT)) == -1)
    slog(1, "connect to mail server FAILED");
  else
    debug(1, "successfully connected to mail server");

  if (send_email(sock, from, to, mail, strlen(mail)) == -1)
    slog(1, "something goes wrong by sending mail");
  else
    debug(1, "mail successfully sent");

  free(mail);
  free(subj);
  free(body);
  free(from);

  return 0;
}
