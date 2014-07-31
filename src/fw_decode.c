#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>
#include <errno.h>
#include "firmware_pack.h"

static void usage(void)
{
	static char *usage_str = 
		"Usage: fw_decode [OPTION] FILE\n"
		"  -d, --dest=DIR         destination directory to extract\n"
		"  -h, --help             display this help and exit\n"
		"  -l, --list             list the files in the firmware\n"
		"";
	puts(usage_str);
}

static int make_directory(char *path, long mode)
{
	mode_t cur_mask;
	mode_t org_mask;
	const char *fail_msg;
	char *s;
	char c;
	struct stat st;
	int retval = 0;

#define LONE_CHAR(s,c)     ((s)[0] == (c) && !(s)[1])
	if (LONE_CHAR(path, '.'))
		return 0;

	org_mask = cur_mask = (mode_t)-1L;
	s = path;
	while (1) {
		c = '\0';

		/* Bypass leading non-'/'s and then subsequent '/'s */
		while (*s) {
			if (*s == '/') {
				do {
					++s;
				} while (*s == '/');
				c = *s; /* Save the current char */
				*s = '\0'; /* and replace it with nul */
				break;
			}
			++s;
		}

		if (c != '\0') {
			/* Intermediate dirs: must have wx for user */
			if (cur_mask == (mode_t)-1L) { /* wasn't done yet? */
				mode_t new_mask;
				org_mask = umask(0);
				cur_mask = 0;
				/* Clear u=wx in umask - this ensures
				 * they won't be cleared on mkdir */
				new_mask = (org_mask & ~(mode_t)0300);
				//bb_error_msg("org_mask:%o cur_mask:%o", org_mask, new_mask);
				if (new_mask != cur_mask) {
					cur_mask = new_mask;
					umask(new_mask);
				}
			}
		} else {
			/* Last component: uses original umask */
			//bb_error_msg("1 org_mask:%o", org_mask);
			if (org_mask != cur_mask) {
				cur_mask = org_mask;
				umask(org_mask);
			}
		}

		if (mkdir(path, 0777) < 0) {
			/* If we failed for any other reason than the directory
			 * already exists, output a diagnostic and return -1 */
			if (errno != EEXIST
			 || ((stat(path, &st) < 0) || !S_ISDIR(st.st_mode))
			) {
				fail_msg = "create";
				break;
			}
			/* Since the directory exists, don't attempt to change
			 * permissions if it was the full target.  Note that
			 * this is not an error condition. */
			if (!c) {
				goto ret;
			}
		}

		if (!c) {
			/* Done.  If necessary, update perms on the newly
			 * created directory.  Failure to update here _is_
			 * an error. */
			if ((mode != -1) && (chmod(path, mode) < 0)) {
				fail_msg = "set permissions of";
				break;
			}
			goto ret;
		}

		/* Remove any inserted nul from the path (recursive mode) */
		*s = c;
	} /* while (1) */

	fprintf(stderr, "can't %s directory '%s'", fail_msg, path);
	retval = -1;
 ret:
	//bb_error_msg("2 org_mask:%o", org_mask);
	if (org_mask != cur_mask)
		umask(org_mask);
	return retval;
}

static FirmwarePackHead g_head;

int main(int argc, char ** argv)
{
	int c;
	struct stat st;
	char *destdir = NULL;

	while (1) {
		static struct option long_options[] = {
			{ "dest",       required_argument, 0, 'd' },
			{ "help",       no_argument,       0, 'h' }
		};

		int option_index = 0;

		c = getopt_long (argc, argv, "hd:", long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
			case 'h':
				usage();
				return -1;
			case 'd':
				destdir = optarg;
				break;
			case '?':
				break;
			default:
				usage();
				return -1;
		}
	}

	if (optind >= argc) {
		usage();
		return -1;
	}

	if (destdir && (stat(destdir, &st) < 0))
		make_directory(destdir, 0775);

    return firmware_pack_decode(argv[optind], destdir, &g_head);
}
