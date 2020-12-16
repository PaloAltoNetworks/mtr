/*
    mtr  --  a network diagnostic tool
    Copyright (C) 2016  Matt Kimball

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "config.h"

#include <errno.h>
#ifdef HAVE_ERROR_H
#include <error.h>
#else
#include "portability/error.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#ifdef HAVE_LIBCAP
#include <sys/capability.h>
#endif

#ifdef HAVE_GETOPT
#include <getopt.h>
#else
#include "portability/getopt.h"
#endif

#include "wait.h"

/*  Drop SUID privileges.  To be used after accquiring raw sockets.  */
static
int drop_elevated_permissions(
    void)
{
#ifdef HAVE_LIBCAP
    cap_t cap;
#endif

    /*  Drop any suid permissions granted  */
    if (setgid(getgid()) || setuid(getuid())) {
        return -1;
    }

    if (geteuid() != getuid() || getegid() != getgid()) {
        return -1;
    }

    /*
       Drop all process capabilities.
       This will revoke anything granted by a commandline 'setcap'
     */
#ifdef HAVE_LIBCAP
    cap = cap_get_proc();
    if (cap == NULL) {
        return -1;
    }
    if (cap_clear(cap)) {
        return -1;
    }
    if (cap_set_proc(cap)) {
        return -1;
    }
#endif

    return 0;
}

static void __attribute__ ((__noreturn__)) usage(FILE * out)
{
    fputs("\nUsage:\n", out);
    fputs(" mtr-packet [options]\n", out);
    fputs("\n", out);
    fputs(" -b, --bind-interface <IFNAME>  bind to a specific interface\n", out);
    fputs(" -h, --help                     display this help and exit\n", out);
    fputs("\n", out);
    fputs("See the 'man 8 mtr' for details.\n", out);
    exit(0);
}

int main(
    int argc,
    char **argv)
{
    bool command_pipe_open;
    struct command_buffer_t command_buffer;
    struct net_state_t net_state;

    char* bind_interface = NULL;
    int opt;
    static const struct option long_options[] = {
        /* option name, has argument, NULL, short name */
        {"help", 0, NULL, 'h'},
        {"bind-interface", 1, NULL, 'b'},
        {NULL, 0, NULL, 0}
    };
    enum { num_options = sizeof(long_options) / sizeof(struct option) };
    char short_options[num_options * 2];
    size_t n, p;

    for (n = p = 0; n < num_options; n++) {
        if (CHAR_MAX < long_options[n].val) {
            continue;
        }
        short_options[p] = long_options[n].val;
        p++;
        if (long_options[n].has_arg == 1) {
            short_options[p] = ':';
            p++;
        }
        /* optional options need two ':', but ignore them now as they are not in use */
    }

    opt = 0;
    while (1) {
        opt = getopt_long(argc, argv, short_options, long_options, NULL);
        if (opt == -1)
            break;

        switch (opt) {
        case 'b':
            bind_interface = optarg;
            break;
        case 'h':
            usage(stdout);
            break;
        default:
            usage(stderr);
        }
    }

    /*
       To minimize security risk, the only thing done prior to 
       dropping SUID should be opening the network state for
       raw sockets.
     */
    init_net_state_privileged(&net_state, bind_interface);
    if (drop_elevated_permissions()) {
        error(EXIT_FAILURE, errno, "Unable to drop elevated permissions");
    }
    init_net_state(&net_state);

    init_command_buffer(&command_buffer, fileno(stdin));

    command_pipe_open = true;

    /*
       Dispatch commands and respond to probe replies until the
       command stream is closed.
     */
    while (true) {
        /*  Ensure any responses are written before waiting  */
        fflush(stdout);
        wait_for_activity(&command_buffer, &net_state);

        /*
           Receive replies first so that the timestamps are as
           close to the response arrival time as possible.
         */
        receive_replies(&net_state);

        if (command_pipe_open) {
            if (read_commands(&command_buffer)) {
                if (errno == EPIPE) {
                    command_pipe_open = false;
                }
            }
        }

        check_probe_timeouts(&net_state);

        /*
           Dispatch commands late so that the window between probe
           departure and arriving replies is as small as possible.
         */
        dispatch_buffer_commands(&command_buffer, &net_state);

        /*
           If the command pipe has been closed, exit after all
           in-flight probes have reported their status.
         */
        if (!command_pipe_open) {
            if (net_state.outstanding_probe_count == 0) {
                break;
            }
        }
    }

    return 0;
}
