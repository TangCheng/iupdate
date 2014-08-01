#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include "firmware_pack.h"

static int32_t make_version(uint8_t major, uint8_t minor, uint8_t revision) {
    int32_t ver = major;
    ver = (ver<<8)|minor;
    ver = (ver<<8)|revision;
    ver = (ver<<8);
    return ver;
}


static void usage(void)
{
	static char *usage_str = 
		"Usage: fw_encode [OPTION] [<NAME FILE>]...\n"
		"  -h, --help             display this help and exit\n"
		"  -n, --note=NOTE        note of this firmware, can be any text\n"
		"  -o, --output=FILENAME  output file\n"
		"  -V, --version=VERSION  firmware version\n"
		"                         in maj.min.rev format\n"
		"For example:\n"
		"  fw_encode -n \"some note\" -V 1.0.0 -o firmware.bin \\\n"
		"            kernel ./uImage-initramfs rootfs \\\n"
		"            rootfs ./rootfs_64k.squashfs\n"
		"";
	puts(usage_str);
}

FirmwarePackHead g_head;

int main(int argc, char ** argv)
{
	int c;
	char *note = "";
	char *output = "output.bin";
    int fw_version = 0;

	/* Parse command line options */
	while (1) {
		int maj = 0;
		int min = 0;
		int rev = 0;

		static struct option long_options[] = {
			{ "help",    no_argument,       0, 'h' },
			{ "note",    required_argument, 0, 'n' },
			{ "output",  required_argument, 0, 'o' },
			{ "version", required_argument, 0, 'V' },
			{ 0, 0, 0, 0 }
		};

		int option_index = 0;

		c = getopt_long(argc, argv, "hn:o:V:", long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
			case 'h':
				usage();
				return -1;
			case 'n':
				note = optarg;
				break;
			case 'o':
				output = optarg;
				break;
			case 'V':
				if (sscanf(optarg, "%d.%d.%d", &maj, &min, &rev) != 3) {
					fprintf(stderr, "Invalid version format");
					usage();
					return -1;
				}
				fw_version = make_version(maj, min, rev);
				break;
			case '?':
				break;
			default:
				usage();
				return -1;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "file list must be specified\n");
		usage();
		return -1;
	}

	firmware_pack_encode(fw_version, (argc - optind) / 2,  
	                     (const char **)&argv[optind],
	                     note, output);

    return 0;
}
