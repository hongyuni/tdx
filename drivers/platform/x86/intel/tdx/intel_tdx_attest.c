// SPDX-License-Identifier: GPL-2.0
/*
 * intel_tdx_attest.c - TDX guest attestation interface driver.
 *
 * Implements user interface to trigger attestation process and
 * read the TD Quote result.
 *
 * Copyright (C) 2021-2022 Intel Corporation
 *
 * Author:
 *     Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>
 */

#define pr_fmt(fmt) "x86/tdx: attest: " fmt

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/set_memory.h>
#include <linux/dma-mapping.h>
#include <linux/platform_device.h>
#include <linux/jiffies.h>
#include <linux/io.h>
#include <asm/apic.h>
#include <asm/tdx.h>
#include <asm/irq_vectors.h>
#include <uapi/misc/tdx.h>

#define DRIVER_NAME "tdx-attest"

/* Used in Quote memory allocation */
#define QUOTE_SIZE			(2 * PAGE_SIZE)
/* Used in Get Quote request memory allocation */
#define GET_QUOTE_MAX_SIZE		(4 * PAGE_SIZE)
/* Get Quote timeout in msec */
#define GET_QUOTE_TIMEOUT		(5000)

struct attest_dev {
	/* Mutex to serialize attestation requests */
	struct mutex lock;
	/* Completion object to track GetQuote completion status */
	struct completion req_compl;
	/* Buffer used to copy report data in attestation handler */
	u8 report_buf[TDX_REPORT_DATA_LEN] __aligned(64);
	/* Data pointer used to get TD Quote data in attestation handler */
	void *tdquote_buf;
	/* Data pointer used to get TDREPORT data in attestation handler */
	void *tdreport_buf;
	/* DMA handle used to allocate and free tdquote DMA buffer */
	dma_addr_t handle;
	struct miscdevice miscdev;
};

static struct platform_device *pdev;

static void attestation_callback_handler(void)
{
	struct attest_dev *adev = platform_get_drvdata(pdev);

	complete(&adev->req_compl);
}

static long tdx_attest_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	struct attest_dev *adev = platform_get_drvdata(pdev);
	void __user *argp = (void __user *)arg;
	struct tdx_gen_quote tdquote_req;
	long ret = 0, err;

	mutex_lock(&adev->lock);

	switch (cmd) {
	case TDX_CMD_GET_TDREPORT:
		if (copy_from_user(adev->report_buf, argp,
					TDX_REPORT_DATA_LEN)) {
			ret = -EFAULT;
			break;
		}

		/* Generate TDREPORT_STRUCT */
		err = tdx_mcall_tdreport(adev->tdreport_buf, adev->report_buf);
		if (err) {
			ret = put_user(err, (long __user *)argp);
			ret = -EIO;
			break;
		}

		if (copy_to_user(argp, adev->tdreport_buf, TDX_TDREPORT_LEN))
			ret = -EFAULT;
		break;
	case TDX_CMD_GEN_QUOTE:
		reinit_completion(&adev->req_compl);

		/* Copy TDREPORT data from user buffer */
		if (copy_from_user(&tdquote_req, argp, sizeof(struct tdx_gen_quote))) {
			ret = -EFAULT;
			break;
		}

		if (tdquote_req.len <= 0 || tdquote_req.len > GET_QUOTE_MAX_SIZE) {
			ret = -EINVAL;
			break;
		}

		if (copy_from_user(adev->tdquote_buf, (void __user *)tdquote_req.buf,
					tdquote_req.len)) {
			ret = -EFAULT;
			break;
		}

		/* Submit GetQuote Request */
		err = tdx_hcall_get_quote(adev->tdquote_buf, GET_QUOTE_MAX_SIZE);
		if (err) {
			ret = put_user(err, (long __user *)argp);
			ret = -EIO;
			break;
		}

		/* Wait for attestation completion */
		ret = wait_for_completion_interruptible_timeout(
				&adev->req_compl,
				msecs_to_jiffies(GET_QUOTE_TIMEOUT));
		if (ret <= 0) {
			ret = -EIO;
			break;
		}

		/* ret will be positive if completed. */
		ret = 0;

		if (copy_to_user((void __user *)tdquote_req.buf, adev->tdquote_buf,
					tdquote_req.len))
			ret = -EFAULT;

		break;
	case TDX_CMD_GET_QUOTE_SIZE:
		ret = put_user(QUOTE_SIZE, (u64 __user *)argp);
		break;
	default:
		pr_err("cmd %d not supported\n", cmd);
		break;
	}

	mutex_unlock(&adev->lock);

	return ret;
}

static const struct file_operations tdx_attest_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= tdx_attest_ioctl,
	.llseek		= no_llseek,
};

/* Helper function to cleanup attestation related allocations */
static void _tdx_attest_remove(struct attest_dev *adev)
{
	misc_deregister(&adev->miscdev);

	tdx_remove_ev_notify_handler();

	if (adev->tdquote_buf)
		dma_free_coherent(&pdev->dev, GET_QUOTE_MAX_SIZE,
				adev->tdquote_buf, adev->handle);

	if (adev->tdreport_buf)
		free_pages((unsigned long)adev->tdreport_buf, 0);

	kfree(adev);
}

static int tdx_attest_probe(struct platform_device *attest_pdev)
{
	struct device *dev = &attest_pdev->dev;
	struct attest_dev *adev;
	long ret = 0;

	/* Only single device is allowed */
	if (pdev)
		return -EBUSY;

	adev = kzalloc(sizeof(*adev), GFP_KERNEL);
	if (!adev)
		return -ENOMEM;

	mutex_init(&adev->lock);
	init_completion(&adev->req_compl);
	pdev = attest_pdev;
	platform_set_drvdata(pdev, adev);

	/*
	 * tdreport_data needs to be 64-byte aligned.
	 * Full page alignment is more than enough.
	 */
	adev->tdreport_buf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
						      0);
	if (!adev->tdreport_buf) {
		ret = -ENOMEM;
		goto failed;
	}

	ret = dma_set_coherent_mask(dev, DMA_BIT_MASK(64));
	if (ret) {
		pr_err("dma set coherent mask failed\n");
		goto failed;
	}

	/* Allocate DMA buffer to get TDQUOTE data from the VMM */
	adev->tdquote_buf = dma_alloc_coherent(dev, GET_QUOTE_MAX_SIZE,
						&adev->handle,
						GFP_KERNEL | __GFP_ZERO);
	if (!adev->tdquote_buf) {
		ret = -ENOMEM;
		goto failed;
	}

	/* Register attestation event notify handler */
	tdx_setup_ev_notify_handler(attestation_callback_handler);

	adev->miscdev.name = DRIVER_NAME;
	adev->miscdev.minor = MISC_DYNAMIC_MINOR;
	adev->miscdev.fops = &tdx_attest_fops;
	adev->miscdev.parent = dev;

	ret = misc_register(&adev->miscdev);
	if (ret) {
		pr_err("misc device registration failed\n");
		goto failed;
	}

	pr_debug("module initialization success\n");

	return 0;

failed:
	_tdx_attest_remove(adev);

	pr_debug("module initialization failed\n");

	return ret;
}

static int tdx_attest_remove(struct platform_device *attest_pdev)
{
	struct attest_dev *adev = platform_get_drvdata(attest_pdev);

	mutex_lock(&adev->lock);
	_tdx_attest_remove(adev);
	mutex_unlock(&adev->lock);
	pr_debug("module is successfully removed\n");
	return 0;
}

static struct platform_driver tdx_attest_driver = {
	.probe		= tdx_attest_probe,
	.remove		= tdx_attest_remove,
	.driver		= {
		.name	= DRIVER_NAME,
	},
};

static int __init tdx_attest_init(void)
{
	int ret;

	/* Make sure we are in a valid TDX platform */
	if (!cpu_feature_enabled(X86_FEATURE_TDX_GUEST))
		return -EIO;

	ret = platform_driver_register(&tdx_attest_driver);
	if (ret) {
		pr_err("failed to register driver, err=%d\n", ret);
		return ret;
	}

	pdev = platform_device_register_simple(DRIVER_NAME, -1, NULL, 0);
	if (IS_ERR(pdev)) {
		ret = PTR_ERR(pdev);
		pr_err("failed to allocate device, err=%d\n", ret);
		platform_driver_unregister(&tdx_attest_driver);
		return ret;
	}

	return 0;
}

static void __exit tdx_attest_exit(void)
{
	platform_device_unregister(pdev);
	platform_driver_unregister(&tdx_attest_driver);
}

module_init(tdx_attest_init);
module_exit(tdx_attest_exit);

MODULE_AUTHOR("Kuppuswamy Sathyanarayanan <sathyanarayanan.kuppuswamy@linux.intel.com>");
MODULE_DESCRIPTION("TDX attestation driver");
MODULE_LICENSE("GPL v2");
