// SPDX-License-Identifier: GPL-2.0
/*
 * tdx-attest-test.c - Utility to test TDX attestation feature.
 *
 * Copyright (C) 2021 - 2022 Intel Corporation. All rights reserved.
 *
 * Author: Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>
 *
 */

#include <linux/types.h>
#include <linux/ioctl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <getopt.h>
#include <stdint.h> /* uintmax_t */
#include <sys/mman.h>
#include <time.h>

#include "../../../../../include/uapi/misc/tdx.h"

#define devname		"/dev/tdx-attest"

/* version, status, in_len, out_len */
#define QUOTE_HEADER_SIZE	24

#define ATTESTATION_TEST_BIN_VERSION "0.1"

struct tdx_attest_args {
	bool is_get_tdreport;
	bool is_get_quote_size;
	bool is_gen_quote;
	bool debug_mode;
	char *out_file;
};

/*
 * Header format is defined in TDX Guest-Host Communication
 * Interface (GHCI) Specification, sec 3.3 "TDG.VP.VMCALL<GetQuote>"
 */
struct tdx_quote_blob {
	uint64_t version;
	uint64_t status;
	uint32_t in_len;
	uint32_t out_len;
	uint8_t data;
};

/*
 * Helper function to initalize report_data buffer with
 * random data. It is used when requesting TDREPORT via
 * TDX_CMD_GET_TDREPORT IOCTL.
 */
static void gen_report_data(__u8 *report_data)
{
	int i;

	srand(time(NULL));

	for (i = 0; i < TDX_REPORT_DATA_LEN; i++)
		report_data[i] = rand();
}

/*
 * Wrapper function for TDX_CMD_GET_TDREPORT IOCTL.
 * Generated TDREPORT data is copied back to the
 * report_data buffer.
 *
 * Returns 0 on success or error on failure.
 */
static int get_tdreport(int devfd, __u8 *report_data)
{
	__u8 tdrdata[TDX_TDREPORT_LEN] = {0};
	long ret, *err;

	if (!report_data)
		report_data = tdrdata;

	gen_report_data(report_data);

	ret = ioctl(devfd, TDX_CMD_GET_TDREPORT, report_data);
	if (ret) {
		err = (long *)report_data;
		printf("TDX_CMD_GET_TDREPORT ioctl() %ld failed, errno:%lx\n",
				ret, *err);
		return ret;
	}

	printf("TDX TDREPORT generation is successful\n");

	return 0;
}

/*
 * Wrapper function to get the quote data size. Used in
 * GetQuote IOCTL request to calculate the quote buffer
 * size.
 */
static __u64 get_quote_size(int devfd)
{
	int ret;
	__u64 quote_size;

	ret = ioctl(devfd, TDX_CMD_GET_QUOTE_SIZE, &quote_size);
	if (ret) {
		printf("TDX_CMD_GET_QUOTE_SIZE ioctl() %d failed\n", ret);
		return -EIO;
	}

	printf("Quote size: %lld\n", quote_size);

	return quote_size;
}

/* Wrapper function to submit GetQuote request to VMM */
static int gen_quote(int devfd)
{
	__u64 quote_data_size, quote_buf_size;
	struct tdx_quote_blob *quote_blob;
	struct tdx_gen_quote getquote_arg;
	__u8 *quote_buf;
	long ret, *err;

	quote_data_size = get_quote_size(devfd);

	/* Add size for quote header */
	quote_buf_size = sizeof(*quote_blob) + quote_data_size;

	/* Allocate quote buffer */
	quote_buf = malloc(quote_buf_size);
	if (!quote_buf) {
		printf("%s queue data alloc failed\n", devname);
		return -ENOMEM;
	}

	quote_blob = (struct tdx_quote_blob *)quote_buf;

	ret = get_tdreport(devfd, &quote_blob->data);
	if (ret)
		goto done;

	/* Initialize GetQuote header */
	quote_blob->version = 1;
	quote_blob->status  = 0;
	quote_blob->in_len  = TDX_TDREPORT_LEN;
	quote_blob->out_len = quote_buf_size - QUOTE_HEADER_SIZE;

	getquote_arg.buf = (__u64)quote_buf;
	getquote_arg.len = quote_buf_size;

	ret = ioctl(devfd, TDX_CMD_GEN_QUOTE, &getquote_arg);
	if (ret) {
		err = (long *)&getquote_arg;
		printf("TDX_CMD_GEN_QUOTE ioctl() %ld failed, errno:%lx\n",
				ret, *err);
		goto done;
	}

	printf("TDX GENQUOTE generation is successful\n");

done:
	free(quote_buf);

	return ret;
}

static void usage(void)
{
	puts("\nUsage:\n");
	puts("tdx_attest [options]\n");

	puts("Attestation device test utility.");

	puts("\nOptions:\n");
	puts(" -r, --get-tdreport        Get TDREPORT data");
	puts(" -g, --gen-quote           Generate TDQUOTE");
	puts(" -s, --get-quote-size      Get TDQUOTE size");
}

int main(int argc, char **argv)
{
	int ret, devfd;
	struct tdx_attest_args args = {0};

	static const struct option longopts[] = {
		{ "get-tdreport",   required_argument, NULL, 'r' },
		{ "gen-quote",      required_argument, NULL, 'g' },
		{ "gen-quote-size", required_argument, NULL, 's' },
		{ "version",        no_argument,       NULL, 'V' },
		{ NULL,             0, NULL, 0 }
	};

	while ((ret = getopt_long(argc, argv, "hdrgsV", longopts,
				  NULL)) != -1) {
		switch (ret) {
		case 'r':
			args.is_get_tdreport = true;
			break;
		case 'g':
			args.is_gen_quote = true;
			break;
		case 's':
			args.is_get_quote_size = true;
			break;
		case 'h':
			usage();
			return 0;
		case 'V':
			printf("Version: %s\n", ATTESTATION_TEST_BIN_VERSION);
			return 0;
		default:
			printf("Invalid options\n");
			usage();
			return -EINVAL;
		}
	}

	devfd = open(devname, O_RDWR | O_SYNC);
	if (devfd < 0) {
		printf("%s open() failed\n", devname);
		return -ENODEV;
	}

	if (args.is_get_quote_size)
		get_quote_size(devfd);

	if (args.is_get_tdreport)
		get_tdreport(devfd,  NULL);

	if (args.is_gen_quote)
		gen_quote(devfd);

	close(devfd);

	return 0;
}
