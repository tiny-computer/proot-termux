/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * Copyright (C) 2015 STMicroelectronics
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include <string.h>    /* str*(3), */
#include <assert.h>    /* assert(3), */
#include <stdio.h>     /* printf(3), fflush(3), */
#include <unistd.h>    /* write(2), */
#include <errno.h>     /* errno, */
#include <stdlib.h>   /* realpath(3), */
#include <pthread.h>   /* pthread_create(3), */
#include <sys/socket.h>/* socket(2), */
#include <sys/un.h>    /* struct sockaddr_un */
#include <sys/queue.h> /* CIRCLEQ_* */

#include "cli/cli.h"
#include "cli/note.h"
#include "extension/extension.h"
#include "extension/sysvipc/sysvipc.h"
#include "path/binding.h"
#include "path/canon.h"
#include "path/temp.h"  /* get_temp_directory() */
#include "attribute.h"

/* These should be included last.  */
#include "build.h"
#include "cli/proot.h"

static int handle_option_r(Tracee *tracee, const Cli *cli UNUSED, const char *value)
{
	Binding *binding;

	/* ``chroot $PATH`` is semantically equivalent to ``mount
	 * --bind $PATH /``.  */
	binding = new_binding(tracee, value, "/", true);
	if (binding == NULL)
		return -1;

	return 0;
}

static int handle_option_b(Tracee *tracee, const Cli *cli UNUSED, const char *value)
{
	char *host;
	char *guest;

	host = talloc_strdup(tracee->ctx, value);
	if (host == NULL) {
		note(tracee, ERROR, INTERNAL, "can't allocate memory");
		return -1;
	}

	guest = strchr(host, ':');
	if (guest != NULL) {
		*guest = '\0';
		guest++;
	}

	new_binding(tracee, host, guest, true);
	return 0;
}

static int handle_option_q(Tracee *tracee, const Cli *cli UNUSED, const char *value)
{
	const char *ptr;
	size_t nb_args;
	bool last;
	size_t i;

	nb_args = 0;
	ptr = value;
	while (1) {
		nb_args++;

		/* Keep consecutive non-space characters.  */
		while (*ptr != ' ' && *ptr != '\0')
			ptr++;

		/* End-of-string ?  */
		if (*ptr == '\0')
			break;

		/* Skip consecutive space separators.  */
		while (*ptr == ' ' && *ptr != '\0')
			ptr++;

		/* End-of-string ?  */
		if (*ptr == '\0')
			break;
	}

	tracee->qemu = talloc_zero_array(tracee, char *, nb_args + 1);
	if (tracee->qemu == NULL)
		return -1;
	talloc_set_name_const(tracee->qemu, "@qemu");

	i = 0;
	ptr = value;
	do {
		const void *start;
		const void *end;
		last = true;

		/* Keep consecutive non-space characters.  */
		start = ptr;
		while (*ptr != ' ' && *ptr != '\0')
			ptr++;
		end = ptr;

		/* End-of-string ?  */
		if (*ptr == '\0')
			goto next;

		/* Remove consecutive space separators.  */
		while (*ptr == ' ' && *ptr != '\0')
			ptr++;

		/* End-of-string ?  */
		if (*ptr == '\0')
			goto next;

		last = false;
	next:
		tracee->qemu[i] = talloc_strndup(tracee->qemu, start, end - start);
		if (tracee->qemu[i] == NULL)
			return -1;
		i++;
	} while (!last);
	assert(i == nb_args);

	new_binding(tracee, "/", HOST_ROOTFS, true);
	new_binding(tracee, "/dev/null", "/etc/ld.so.preload", false);

	return 0;
}

static int handle_option_w(Tracee *tracee, const Cli *cli UNUSED, const char *value)
{
	tracee->fs->cwd = talloc_strdup(tracee->fs, value);
	if (tracee->fs->cwd == NULL)
		return -1;
	talloc_set_name_const(tracee->fs->cwd, "$cwd");
	return 0;
}

static int handle_option_k(Tracee *tracee, const Cli *cli UNUSED, const char *value)
{
	void *extension;
	int status;

	extension = get_extension(tracee, kompat_callback);
	if (extension != NULL) {
		note(tracee, WARNING, USER, "option -k was already specified");
		note(tracee, INFO, USER, "only the last -k option is enabled");
		TALLOC_FREE(extension);
	}

	status = initialize_extension(tracee, kompat_callback, value);
	if (status < 0)
		note(tracee, WARNING, INTERNAL, "option \"-k %s\" discarded", value);

	return 0;
}

static int handle_option_i(Tracee *tracee, const Cli *cli UNUSED, const char *value)
{
	void *extension;

	extension = get_extension(tracee, fake_id0_callback);
	if (extension != NULL) {
		note(tracee, WARNING, USER, "option -i/-0/-S was already specified");
		note(tracee, INFO, USER, "only the last -i/-0/-S option is enabled");
		TALLOC_FREE(extension);
	}

	(void) initialize_extension(tracee, fake_id0_callback, value);
	return 0;
}

static int handle_option_0(Tracee *tracee, const Cli *cli, const char *value UNUSED)
{
	return handle_option_i(tracee, cli, "0:0");
}

static int handle_option_kill_on_exit(Tracee *tracee, const Cli *cli UNUSED, const char *value UNUSED)
{
	tracee->killall_on_exit = true;
	return 0;
}

static int handle_option_v(Tracee *tracee, const Cli *cli UNUSED, const char *value)
{
	int status;

	status = parse_integer_option(tracee, &tracee->verbose, value, "-v");
	if (status < 0)
		return status;

	global_verbose_level = tracee->verbose;
	return 0;
}

extern unsigned char WEAK _binary_licenses_start;
extern unsigned char WEAK _binary_licenses_end;

static int handle_option_V(Tracee *tracee UNUSED, const Cli *cli, const char *value UNUSED)
{
	size_t size;

	print_version(cli);
	printf("\n%s\n", cli->colophon);
	fflush(stdout);

	size = &_binary_licenses_end - &_binary_licenses_start;
	if (size > 0)
		write(1, &_binary_licenses_start, size);

	exit_failure = false;
	return -1;
}

static int handle_option_h(Tracee *tracee, const Cli *cli, const char *value UNUSED)
{
	print_usage(tracee, cli, true);
	exit_failure = false;
	return -1;
}

static void new_bindings(Tracee *tracee, const char *bindings[], const char *value)
{
	int i;

	for (i = 0; bindings[i] != NULL; i++) {
		const char *path;

		path = (strcmp(bindings[i], "*path*") != 0
			? expand_front_variable(tracee->ctx, bindings[i])
			: value);

		new_binding(tracee, path, NULL, false);
	}
}

static int handle_option_R(Tracee *tracee, const Cli *cli, const char *value)
{
	int status;

	status = handle_option_r(tracee, cli, value);
	if (status < 0)
		return status;

	new_bindings(tracee, recommended_bindings, value);

	return 0;
}

static int handle_option_S(Tracee *tracee, const Cli *cli, const char *value)
{
	int status;

	status = handle_option_0(tracee, cli, value);
	if (status < 0)
		return status;

	status = handle_option_r(tracee, cli, value);
	if (status < 0)
		return status;

	new_bindings(tracee, recommended_su_bindings, value);

	return 0;
}

static int handle_option_link2symlink(Tracee *tracee, const Cli *cli UNUSED, const char *value UNUSED)
{
	int status;

	/* Initialize the link2symlink extension.  */
	status = initialize_extension(tracee, link2symlink_callback, NULL);
	if (status < 0)
		note(tracee, WARNING, INTERNAL, "link2symlink not initialized");

	return 0;
}

static int handle_option_ashmem_memfd(Tracee *tracee, const Cli *cli UNUSED, const char *value UNUSED)
{
	int status;

	/* Initialize the ashmem-memfd extension.  */
	status = initialize_extension(tracee, ashmem_memfd_callback, NULL);
	if (status < 0)
		note(tracee, WARNING, INTERNAL, "ashmem-memfd not initialized");

	return 0;
}

static int handle_option_sysvipc(Tracee *tracee, const Cli *cli UNUSED, const char *value UNUSED)
{
	int status;

	/* Initialize the sysvipc extension.  */
	status = initialize_extension(tracee, sysvipc_callback, NULL);
	if (status < 0)
		note(tracee, WARNING, INTERNAL, "sysvipc not initialized");

	return 0;
}

static int handle_option_L(Tracee *tracee, const Cli *cli UNUSED, const char *value UNUSED)
{
        (void) initialize_extension(tracee, fix_symlink_size_callback, NULL);
        return 0;
}

static int handle_option_H(Tracee *tracee, const Cli *cli UNUSED, const char *value UNUSED)
{
        (void) initialize_extension(tracee, hidden_files_callback, NULL);
        return 0;
}

static int handle_option_p(Tracee *tracee, const Cli *cli UNUSED, const char *value UNUSED)
{
        (void) initialize_extension(tracee, port_switch_callback, NULL);
        return 0;
}

#include "execve/binfmt.h"

static int handle_option_binfmt(int pos, const char *value) {
	strcpy(default_binfmt_entries[pos].interpreter, value);
	binfmt_max_magic_length = default_binfmt_entries[pos].length > binfmt_max_magic_length ? default_binfmt_entries[pos].length : binfmt_max_magic_length;
	return 0;
}

static int handle_option_binfmt_x86(Tracee *tracee, const Cli *cli, const char *value)
{
	return handle_option_binfmt(2, value);
}

static int handle_option_binfmt_x64(Tracee *tracee, const Cli *cli, const char *value)
{
	return handle_option_binfmt(1, value);
}

static int handle_option_binfmt_wine(Tracee *tracee, const Cli *cli, const char *value)
{
	return handle_option_binfmt(0, value);
}

/**
 * Initialize @tracee->qemu.
 */
static int post_initialize_exe(Tracee *tracee, const Cli *cli UNUSED,
			size_t argc UNUSED, char *const argv[] UNUSED, size_t cursor UNUSED)
{
	char path[PATH_MAX];
	int status;

	/* Nothing else to do ?  */
	if (tracee->qemu == NULL)
		return 0;

	/* Resolve the full guest path to tracee->qemu[0].  */
	status = which(tracee->reconf.tracee, tracee->reconf.paths, path, tracee->qemu[0]);
	if (status < 0)
		return -1;

	/* Actually tracee->qemu[0] has to be a host path from the tracee's
	 * point-of-view, not from the PRoot's point-of-view.  See
	 * translate_execve() for details.  */
	if (tracee->reconf.tracee != NULL) {
		status = detranslate_path(tracee->reconf.tracee, path, NULL);
		if (status < 0)
			return -1;
	}

	tracee->qemu[0] = talloc_strdup(tracee->qemu, path);
	if (tracee->qemu[0] == NULL)
		return -1;

	return 0;
}

/**
 * Initialize @tracee's fields that are mandatory for PRoot but that
 * are not required on the command line, i.e.  "-w" and "-r".
 */
static int pre_initialize_bindings(Tracee *tracee, const Cli *cli,
			size_t argc UNUSED, char *const argv[] UNUSED, size_t cursor)
{
	int status;

	/* Default to "." if no CWD were specified.  */
	if (tracee->fs->cwd == NULL) {
		status = handle_option_w(tracee, cli, ".");
		if (status < 0)
			return -1;
	}

	 /* The default guest rootfs is "/" if none was specified.  */
	if (get_root(tracee) == NULL) {
		status = handle_option_r(tracee, cli, "/");
		if (status < 0)
			return -1;
	}

	return cursor;
}

/**
 * Handle --assured-path: resolve the given host path via realpath(3),
 * lstat(2) it, and cache the result globally for reuse during
 * path canonicalisation.
 */
static int handle_option_assured_path(Tracee *tracee, const Cli *cli UNUSED, const char *value)
{
	char resolved[PATH_MAX];
	struct stat statl;
	int status;

	if (realpath(value, resolved) == NULL) {
		note(tracee, WARNING, USER,
			"--assured-path '%s': realpath: %s", value, strerror(errno));
		return 0;
	}

	status = lstat(resolved, &statl);
	if (status < 0) {
		note(tracee, WARNING, USER,
			"--assured-path '%s': lstat: %s", value, strerror(errno));
		memset(&statl, 0, sizeof(statl));
		status = -errno;
	}

	assured_path_cache_add(resolved, &statl, status);
	return 0;
}

/**
 * Handle --tiny-storage: create a Unix-domain socket server
 * at $PROOT_TMP_DIR/.tiny.storage and spawn a thread that listens for
 * dynamic bind/unbind messages from the Android TinyStorage service.
 *
 * Protocol (binary, fixed-size struct):
 *
 *   #define SM_PATH_MAX 512
 *   #define SM_NAME_MAX 128
 *
 *   typedef struct {
 *       uint8_t  action;              // 'A' = add, 'R' = remove
 *       char     path[SM_PATH_MAX];   // host device path
 *       char     name[SM_NAME_MAX];   // mount-name under /mnt/
 *   } storage_msg_t;
 *
 * Must stay in sync with tiny_storage_jni.c.
 */
#define SM_PATH_MAX  512
#define SM_NAME_MAX  128

typedef struct {
	uint8_t  action;
	char     path[SM_PATH_MAX];
	char     name[SM_NAME_MAX];
} storage_msg_t;

static void *storage_listen_thread(void *arg)
{
	Tracee *tracee = (Tracee *)arg;
	const char *tmp_dir = get_temp_directory();
	char socket_path[PATH_MAX];
	int fd, client;
	struct sockaddr_un addr;
	storage_msg_t msg;

	snprintf(socket_path, sizeof(socket_path), "%s/.tiny.storage", tmp_dir);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		note(tracee, WARNING, SYSTEM,
			"--tiny-storage: socket() failed");
		return NULL;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

	unlink(socket_path);
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		note(tracee, WARNING, SYSTEM,
			"--tiny-storage: bind(%s) failed", socket_path);
		close(fd);
		return NULL;
	}
	chmod(socket_path, 0666);

	if (listen(fd, 5) < 0) {
		note(tracee, WARNING, SYSTEM,
			"--tiny-storage: listen() failed");
		unlink(socket_path);
		close(fd);
		return NULL;
	}

	note(tracee, INFO, USER,
		"--tiny-storage: listening on %s", socket_path);

	for (;;) {
		client = accept(fd, NULL, NULL);
		if (client < 0) {
			if (errno == EINTR) continue;
			note(tracee, WARNING, SYSTEM,
				"--tiny-storage: accept() failed");
			break;
		}

		/* Read messages until client disconnects or error */
		while (1) {
			ssize_t n = read(client, &msg, sizeof(msg));
			if (n <= 0) {
				if (n < 0 && errno == EINTR) continue;
				break; /* EOF or error */
			}
			if ((size_t)n < sizeof(msg)) {
				/* short read – client misbehaving, skip rest */
				note(tracee, WARNING, USER,
					"storage: short msg %zd/%zu bytes", n, sizeof(msg));
				break;
			}

			if (msg.action == 'A') {
				/* add binding: equivalent to
				 *   handle_option_b → new_binding →
				 *   initialize_bindings → initialize_binding
				 */
				Binding *binding;
				char host[PATH_MAX];
				char guest[PATH_MAX];
				int status;

				snprintf(guest, sizeof(guest), "/mnt/%s", msg.name);

				/* Canonicalize host path (same as new_binding). */
				status = realpath2(NULL, host, msg.path, true);
				if (status < 0) {
					note(tracee, WARNING, SYSTEM,
						"storage: realpath(%s) failed", msg.path);
					continue;
				}

				binding = talloc_zero(tracee->ctx, Binding);
				if (binding == NULL)
					continue;

				strcpy(binding->host.path, host);
				binding->host.length = strlen(host);
				strcpy(binding->guest.path, guest);

				pthread_mutex_lock(&tracee->fs->bindings.lock);
				initialize_binding(tracee, binding);
				pthread_mutex_unlock(&tracee->fs->bindings.lock);

				note(tracee, INFO, USER,
					"storage: bind %s → %s", host, guest);
			}
			else if (msg.action == 'R') {
				char guest[PATH_MAX];
				Binding *b, *to_remove = NULL;
				const char *guest_root;

				snprintf(guest, sizeof(guest), "/mnt/%s", msg.name);
				note(tracee, INFO, USER,
					"storage: unbind %s", guest);

				pthread_mutex_lock(&tracee->fs->bindings.lock);
				CIRCLEQ_FOREACH(b, tracee->fs->bindings.guest, link.guest) {
					if (strcmp(b->guest.path, guest) == 0) {
						to_remove = b;
						break;
					}
				}
				if (to_remove) {
					remove_binding_from_all_lists(tracee, to_remove);
				}
				pthread_mutex_unlock(&tracee->fs->bindings.lock);

				/* Remove the build_glue() placeholder directory
				 * (mkdir(…, 0) – rmdir does not check target permissions). */
				guest_root = get_root(tracee);
				if (guest_root && to_remove) {
					char placeholder[PATH_MAX];
					snprintf(placeholder, sizeof(placeholder),
						"%s%s", guest_root, guest);
					rmdir(placeholder);
				}
			}
		}
		close(client);
	}

	close(fd);
	unlink(socket_path);
	return NULL;
}

/**
 * Handle --tiny-storage: record that the option was requested.
 * The actual socket listener is spawned later from
 * post_initialize_storage(), after initialize_bindings() has
 * set up tracee->fs->bindings.host/guest.
 */
static int handle_option_external_storage(
	Tracee *tracee, const Cli *cli UNUSED, const char *value UNUSED)
{
	tracee->external_storage_enabled = true;
	note(tracee, INFO, USER, "--tiny-storage requested");
	return 0;
}

/**
 * post_initialize_bindings hook – called after initialize_bindings()
 * has populated tracee->fs->bindings.{host,guest}, so the socket
 * listener thread can safely call insort_binding3() and iterate
 * bindings.
 */
static int post_initialize_storage(
	Tracee *tracee, const Cli *cli UNUSED,
	size_t argc UNUSED, char *const argv[] UNUSED, size_t cursor)
{
	pthread_t tid;

	if (!tracee->external_storage_enabled)
		return (int)cursor;

	note(tracee, INFO, USER, "--tiny-storage: starting socket listener");

	if (pthread_create(&tid, NULL, storage_listen_thread, tracee) != 0) {
		note(tracee, WARNING, SYSTEM,
			"--tiny-storage: pthread_create() failed");
		return -1;
	}
	pthread_detach(tid);
	return (int)cursor;
}

const Cli *get_proot_cli(TALLOC_CTX *context UNUSED)
{
	global_tool_name = proot_cli.name;
	return &proot_cli;
}
