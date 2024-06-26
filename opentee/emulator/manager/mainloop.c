﻿/*****************************************************************************
** Copyright (C) 2013 Brian McGillion                                       **
**                                                                          **
** Licensed under the Apache License, Version 2.0 (the "License");          **
** you may not use this file except in compliance with the License.         **
** You may obtain a copy of the License at                                  **
**                                                                          **
**      http://www.apache.org/licenses/LICENSE-2.0                          **
**                                                                          **
** Unless required by applicable law or agreed to in writing, software      **
** distributed under the License is distributed on an "AS IS" BASIS,        **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. **
** See the License for the specific language governing permissions and      **
** limitations under the License.                                           **
*****************************************************************************/

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h> // RDWR

#include "core_control_resources.h"
#include "epoll_wrapper.h"
#include "extern_resources.h"
#include "io_thread.h"
#include "logic_thread.h"
#include "ta_dir_watch.h"
#include "tee_logging.h"

#ifdef ANDROID
#include "android_defines.h"
#endif

/* Maximum epoll events */
#define MAX_CURR_EVENTS 5

/* These are for tasks received from the caller going to the logic thread */
struct list_head inbound_queue_list;

/* These are for tasks that are complete and need to send out */
struct list_head outbound_queue_list;

/* Socket need to be closed by IO thread */
struct list_head socks_to_close_list;

/* Client connections */
struct list_head ca_list;

/* Loaded TAs (ready accept open sessions) */
struct list_head ta_list;

pthread_mutex_t CA_table_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t TA_table_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t inbound_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t outbound_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t socks_to_close_mutex = PTHREAD_MUTEX_INITIALIZER;

/* IO thead "signaling": wake up logic thread */
pthread_cond_t inbound_queue_cond = PTHREAD_COND_INITIALIZER;

/* Launcher process fd */
int launcher_fd;

/* Done queue have something in */
int event_out_queue_fd;

/* Close queue have something to process */
int event_close_sock;

/*!
 * \brief init_sock
 * Initialize the daemons main public socket and listen for inbound connections
 * \param pub_sockfd The main socket to which clients connect
 * \return 0 on success -1 otherwise
 */
static int init_sock(int *pub_sockfd)
{
	struct sockaddr_un sock_addr;

	/* Try to get socket path from environment variable, otherwise fallback to hardcoded one. */
	char *known_socket_path = getenv("OPENTEE_SOCKET_FILE_PATH");
	if (known_socket_path == NULL)
		known_socket_path = WELL_KNOWN_PUBLIC_SOCK_PATH;
	if (remove(known_socket_path) == -1 && errno != ENOENT) {
		OT_LOG(LOG_ERR, "Failed to remove %s : %s",
		       known_socket_path, strerror(errno));
		return -1;
	}

	*pub_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (*pub_sockfd == -1) {
		OT_LOG(LOG_ERR, "Create socket %s", strerror(errno));
		return -1;
	}

	memset(&sock_addr, 0, sizeof(struct sockaddr_un));
	strncpy(sock_addr.sun_path, known_socket_path, sizeof(sock_addr.sun_path) - 1);
	sock_addr.sun_family = AF_UNIX;

	if (bind(*pub_sockfd, (struct sockaddr *)&sock_addr, sizeof(struct sockaddr_un)) == -1) {
		OT_LOG(LOG_ERR, "Error %s", strerror(errno));
		goto err_out;
	}

	if (listen(*pub_sockfd, SOMAXCONN) == -1) {
		OT_LOG(LOG_ERR, "Listen socket %s", strerror(errno));
		goto err_out;
	}

	return 0;

err_out:
	close(*pub_sockfd);
	return -1;
}

static int init_extern_res(int launcher_proc_fd)
{
	/* Linked lists */
	INIT_LIST(&inbound_queue_list);
	INIT_LIST(&outbound_queue_list);
	INIT_LIST(&socks_to_close_list);

	/* CA and TA hashtables */
	INIT_LIST(&ca_list);
	INIT_LIST(&ta_list);

	/* Launcher fd */
	launcher_fd = launcher_proc_fd;

	/* Done queue event is used in semaphore style */
	event_out_queue_fd = eventfd(0, EFD_SEMAPHORE);
	if (event_out_queue_fd == -1) {
		OT_LOG(LOG_ERR, "Failed to init event_out_queue_fd: %s", strerror(errno));
		return 1;
	}

	/* Close socket is only zeroed */
	event_close_sock = eventfd(0, 0);
	if (event_close_sock == -1) {
		OT_LOG(LOG_ERR, "Failed to init event_close_sock: %s", strerror(errno));
		close(event_out_queue_fd);
		return 1;
	}

	return 0;
}

int lib_main_loop(struct core_control *control_params)
{
	int public_sockfd, i, event_count, event_ta_dir_watch_fd;
	struct epoll_event cur_events[MAX_CURR_EVENTS];
	pthread_t logic_thread;
	pthread_attr_t attr;
	sigset_t sig_empty_set;

	if (init_extern_res(control_params->comm_sock_fd))
		return -1; /* err msg logged */

	if (sigemptyset(&sig_empty_set)) {
		OT_LOG(LOG_ERR, "Sigempty set failed");
		return -1;
	}

	if (init_epoll())
		return -1; /* err msg logged */

	if (ta_dir_watch_init(control_params, &event_ta_dir_watch_fd))
		return -1; /* err msg logged */

	if (init_sock(&public_sockfd))
		return -1; /* err msg logged */

	/* listen to inbound connections from userspace clients */
	if (epoll_reg_fd(public_sockfd, EPOLLIN))
		return -1; /* err msg logged */

	/* Done queue event fd */
	if (epoll_reg_fd(event_out_queue_fd, EPOLLIN))
		return -1; /* err msg logged */

	/* Socket(s) need to be closed */
	if (epoll_reg_fd(event_close_sock, EPOLLIN))
		return -1; /* err msg logged */

	/* Singnal handling */
	if (epoll_reg_fd(control_params->self_pipe_fd, EPOLLIN))
		return -1; /* err msg logged */

	/* Init logic thread */
	if (pthread_attr_init(&attr)) {
		OT_LOG(LOG_ERR, "Failed to create attr for thread in : %s\n", strerror(errno));
		return -1;
	}

	/* Logic thread is detached thread */
	if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
		OT_LOG(LOG_ERR, "Failed set DETACHED for : %s\n", strerror(errno));
		return -1;
	}

	/* Note: Logic thread is not accepting any signals. All signals has been blocked */
	if (pthread_create(&logic_thread, &attr, logic_thread_mainloop, NULL)) {
		OT_LOG(LOG_ERR, "Failed launch thread for : %s\n", strerror(errno));
		return -1;
	}

	/* NB everything after this point must be thread safe
	 * NB Mainloop is executed as IO thread */

	/* Allow signal delivery */
	if (pthread_sigmask(SIG_SETMASK, &sig_empty_set, NULL)) {
		OT_LOG(LOG_ERR, "Failed to allow signal delivery");
		return -1;
	}

	OT_LOG(LOG_ERR, "Entering the Manager mainloop");

	for (;;) {
		/* Block and wait for a one of the monitored I/Os to become available */
		event_count = wrap_epoll_wait(cur_events, MAX_CURR_EVENTS);
		if (event_count == -1) {
			if (errno == EINTR) {
				manager_check_signal(control_params, NULL);
				continue;
			}

			/* Log error and hope the error clears itself */
			OT_LOG(LOG_ERR, "Failed return from epoll_wait\n");
			continue;
		}

		for (i = 0; i < event_count; i++) {

			if (cur_events[i].data.fd == public_sockfd) {
				// OT_LOG(LOG_DEBUG, "[Manager] received |^ handle_public_fd ^|");
				handle_public_fd(&cur_events[i]);

			} else if (cur_events[i].data.fd == event_out_queue_fd) {
				// OT_LOG(LOG_DEBUG, "[Manager] received |^ handle_out_queue ^|");
				handle_out_queue(&cur_events[i]); // event saying msg needs to be sent out 

			} else if (cur_events[i].data.fd == control_params->self_pipe_fd) {
				// OT_LOG(LOG_DEBUG, "[Manager] received |^ manager_check_signal ^|");
				manager_check_signal(control_params, &cur_events[i]);

			} else if(cur_events[i].data.fd == event_close_sock) {
				// OT_LOG(LOG_DEBUG, "[Manager] received |^ handle_close_sock ^|");
				handle_close_sock(&cur_events[i]);

			} else if(cur_events[i].data.fd == event_ta_dir_watch_fd) {
				// OT_LOG(LOG_DEBUG, "[Manager] received |^ ta_dir_watch_event ^|");
				ta_dir_watch_event(&cur_events[i], &event_ta_dir_watch_fd);

			} else {
				// OT_LOG(LOG_DEBUG, "[Manager] received  |^ read_fd_and_add_inbound_queue ^|");
				read_fd_and_add_inbound_queue(&cur_events[i]); // read received msg & add it to logic thread queue for processing the job
			}
		}
	}

	OT_LOG(LOG_ERR, "Something is very wrong");
	return -1;
}
