// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015 Google, Inc.
 * Copyright (C) 2021 XiaoMi, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": [%s %d] " fmt, __func__, __LINE__

#include "mitee_memlog.h"

#include <linux/delay.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/panic_notifier.h>
#include <linux/platform_device.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include <tee_drv.h>
#include "optee_ffa.h"
#include "optee_private.h"
#include "optee_smc.h"

#define SET_KEY_FILE "/data/vendor/mitee/key.log"
static bool g_read_b_buf;

static int log_read_line_internal(struct mitee_memlog_state *s, uint32_t put, uint32_t get,
					uint32_t rb_start, uint32_t rb_size)
{
	struct log_rb *log = s->log;
	int offset;
	int end;
	int i = 0;
	int j = 0;
	char c = '\0';
	size_t max_to_read;

	max_to_read = min((size_t)(put - get), sizeof(s->line_buffer) - 1);
	offset = get % rb_size;
	end = (get + max_to_read) % rb_size;

	if (offset < end) {
		for (i = 0; i < max_to_read && c != '\n'; i++)
			s->line_buffer[i] = c = log->data[rb_start + offset + i];
	} else {
		for (i = 0; i < (rb_size - offset) && c != '\n'; i++)
			s->line_buffer[i] = c = log->data[rb_start + offset + i];
		if (c == '\n')
			goto done;
		for (j = 0; j < end && c != '\n'; j++)
			s->line_buffer[i + j] = c = log->data[rb_start + j];
	}

done:
	s->line_buffer[i + j] = '\0';
	return (i + j);
}

static int log_read_line(struct mitee_memlog_state *s, uint32_t put, uint32_t get)
{
	struct log_rb *log = s->log;

	return log_read_line_internal(s, put, get, 0, log->sz);
}

static int log_read_b_line(struct mitee_memlog_state *s, uint32_t put, uint32_t get)
{
	struct log_rb *log = s->log;

	return log_read_line_internal(s, put, get, log->sz, log->b_sz);
}

#ifdef ENABLE_DUMP_MITEE_LOG
static void mitee_dump_logs(struct mitee_memlog_state *s)
{
	struct log_rb *log = s->log;
	uint32_t get, put, alloc;
	int read_chars;

	/*
	 * For this ring buffer, at any given point, alloc >= put >= get.
	 * The producer side of the buffer is not locked, so the put and alloc
	 * pointers must be read in a defined order (put before alloc) so
	 * that the above condition is maintained. A read barrier is needed
	 * to make sure the hardware and compiler keep the reads ordered.
	 */
	get = s->get;
	while ((put = log->put) != get) {
		/* Make sure that the read of put occurs before the read of log data */
		rmb();

		/* Read a line from the log */
		read_chars = log_read_line(s, put, get);

		/* Force the loads from log_read_line to complete. */
		rmb();
		alloc = log->alloc;

		/*
		 * Discard the line that was just read if the data could
		 * have been corrupted by the producer.
		 */
		if (alloc - get > log->sz) {
			pr_err("mitee: log overflow.");
			get = alloc - log->sz;
			continue;
		}
		pr_info("mitee: %s", s->line_buffer);
		get += read_chars;
	}
	s->get = get;
}
#endif

static int mitee_memlog_call_notify(struct notifier_block *nb,
				    unsigned long action, void *data)
{
	struct mitee_memlog_state *s;

	if (action != MITEE_CALL_RETURNED)
		return NOTIFY_DONE;

	s = container_of(nb, struct mitee_memlog_state, call_notifier);
#ifdef ENABLE_DUMP_MITEE_LOG
	pr_err("ststest: start dump log\n");
	spin_lock_irqsave(&s->lock, flags);
	mitee_dump_logs(s);
	spin_unlock_irqrestore(&s->lock, flags);
#endif
	atomic_inc(&s->mitee_log_event_count);
	wake_up_interruptible(&s->mitee_log_wq);
	return NOTIFY_OK;
}

static int mitee_memlog_notify(struct notifier_block *nb,
				     unsigned long action, void *data)
{
	struct mitee_memlog_state *s;

	/*
	 * Don't grab the spin lock to hold up the panic notifier, even
	 * though this is racy.
	 */
	s = container_of(nb, struct mitee_memlog_state, panic_notifier);
	pr_info("mitee-log notifier\n");
	/* mitee_dump_logs(s); */
	atomic_inc(&s->mitee_log_event_count);
	wake_up_interruptible(&s->mitee_log_wq);
	return NOTIFY_OK;
}

static int is_buf_empty(struct mitee_memlog_state *s)
{
	struct log_rb *log = s->log;
	uint32_t get, put;

	get = READ_ONCE(s->get);
	put = READ_ONCE(log->put);
	return (get == put);
}

static int do_mitee_memlog_read(struct mitee_memlog_state *s, char __user *buf,
				size_t size)
{
	struct log_rb *log = s->log;
	uint32_t get, put, alloc;
	int read_chars = 0, copy_chars = 0, tbuf_size, outbuf_size;
	char *psrc = NULL;

	if (!size)
		return 0;

	if (!READ_ONCE(g_read_b_buf)) {
		/*
		 * For this ring buffer, at any given point, alloc >= put >= get.
		 * The producer side of the buffer is not locked, so the put and alloc
		 * pointers must be read in a defined order (put before alloc) so
		 * that the above condition is maintained. A read barrier is needed
		 * to make sure the hardware and compiler keep the reads ordered.
		 */
		get = READ_ONCE(s->b_get);
		put = READ_ONCE(log->b_put);
		/* make sure the hardware and compiler reads the correct put & alloc*/
		rmb();
		alloc = READ_ONCE(log->b_alloc);

		/* the counters wrap, compare distances rather than positions */
		if (alloc - get > log->b_sz) {
			pr_notice_ratelimited("mitee: bootup log overflow, lose some msg.");
			get = alloc - log->b_sz;
		}

		if (put - get > log->b_sz)
			get = put;

		if (get == put) {
			WRITE_ONCE(s->b_get, get);
			WRITE_ONCE(g_read_b_buf, true);
			return 0;
		}

		outbuf_size = min_t(size_t, put - get, size);

		tbuf_size = (outbuf_size / MITEE_LINE_BUFFER_SIZE + 1) *
			    MITEE_LINE_BUFFER_SIZE;

		/* tbuf_size >= outbuf_size >= size */
		psrc = kzalloc(tbuf_size, GFP_KERNEL);

		if (!psrc)
			return -ENOMEM;

		while (get != put) {
			read_chars = log_read_b_line(s, put, get);
			/* Force the loads from log_read_line to complete. */
			rmb();
			read_chars = min(read_chars, outbuf_size - copy_chars);
			memcpy(psrc + copy_chars, s->line_buffer, read_chars);
			get += read_chars;
			copy_chars += read_chars;
			if (copy_chars == outbuf_size)
				break;
		}

		if (copy_to_user(buf, psrc, copy_chars)) {
			kfree(psrc);
			return -EFAULT;
		}
		kfree(psrc);

		WRITE_ONCE(s->b_get, get);

		return copy_chars;
	} else {
		/*
		 * For this ring buffer, at any given point, alloc >= put >= get.
		 * The producer side of the buffer is not locked, so the put and alloc
		 * pointers must be read in a defined order (put before alloc) so
		 * that the above condition is maintained. A read barrier is needed
		 * to make sure the hardware and compiler keep the reads ordered.
		 */
		get = READ_ONCE(s->get);
		put = READ_ONCE(log->put);
		/* make sure the hardware and compiler reads the correct put & alloc*/
		rmb();
		alloc = READ_ONCE(log->alloc);

		/* the counters wrap, compare distances rather than positions */
		if (alloc - get > log->sz) {
			pr_notice_ratelimited("mitee: runtime log overflow, lose some msg.");
			get = alloc - log->sz;
		}

		/*
		 * No committed bytes survived the overwrite. Catch up to put so
		 * poll does not keep returning the same unreadable data.
		 */
		if (put - get > log->sz)
			get = put;

		if (get == put) {
			WRITE_ONCE(s->get, get);
			return 0;
		}

		outbuf_size = min_t(size_t, put - get, size);

		tbuf_size = (outbuf_size / MITEE_LINE_BUFFER_SIZE + 1) *
			    MITEE_LINE_BUFFER_SIZE;

		/* tbuf_size >= outbuf_size >= size */
		psrc = kzalloc(tbuf_size, GFP_KERNEL);

		if (!psrc)
			return -ENOMEM;

		while (get != put) {
			read_chars = log_read_line(s, put, get);
			/* Force the loads from log_read_line to complete. */
			rmb();
			read_chars = min(read_chars, outbuf_size - copy_chars);
			memcpy(psrc + copy_chars, s->line_buffer, read_chars);
			get += read_chars;
			copy_chars += read_chars;
			if (copy_chars == outbuf_size)
				break;
		}

		if (copy_to_user(buf, psrc, copy_chars)) {
			kfree(psrc);
			return -EFAULT;
		}
		kfree(psrc);

		WRITE_ONCE(s->get, get);

		return copy_chars;
	}
}

static ssize_t mitee_memlog_read(struct file *file, char __user *buf,
				 size_t size, loff_t *ppos)
{
	struct mitee_memlog_state *s = pde_data(file_inode(file));
	int ret = 0;

	if (atomic_xchg(&s->readable, 0)) {
		WRITE_ONCE(s->poll_event, atomic_read(&s->mitee_log_event_count));
		ret = do_mitee_memlog_read(s, buf, size);
		atomic_set(&s->readable, 1);
	}
	return ret;
}

static int mitee_memlog_open(struct inode *inode, struct file *file)
{
	struct mitee_memlog_state *s = pde_data(inode);
	int ret;

	ret = nonseekable_open(inode, file);
	if (unlikely(ret))
		return ret;
	WRITE_ONCE(s->poll_event, atomic_read(&s->mitee_log_event_count));
	return 0;
}

static int mitee_memlog_release(struct inode *inode, struct file *file)
{
	return 0;
}

static unsigned int mitee_memlog_poll(struct file *file,
				      struct poll_table_struct *wait)
{
	struct mitee_memlog_state *s = pde_data(file_inode(file));
	int mask = 0;

	poll_wait(file, &s->mitee_log_wq, wait);

	if ((!READ_ONCE(g_read_b_buf) &&
	     READ_ONCE(s->b_get) != READ_ONCE(s->log->b_put)) ||
	    !is_buf_empty(s) ||
	    READ_ONCE(s->poll_event) != atomic_read(&s->mitee_log_event_count))
		mask |= POLLIN | POLLRDNORM;
	return mask;
}

static const struct proc_ops mitee_memlog_fops = {
	.proc_open = mitee_memlog_open,
	.proc_read = mitee_memlog_read,
	.proc_release = mitee_memlog_release,
	.proc_poll = mitee_memlog_poll,
};

static ssize_t mitee_memlog_key_read(struct file *file, char __user *buf,
				     size_t size, loff_t *ppos)
{
	struct mitee_memlog_state *s = pde_data(file_inode(file));
	int ret = 0;
	char *psrc = NULL;

	psrc = kzalloc(KEY_LENGTH, GFP_KERNEL);

	if (!psrc)
		return -ENOMEM;

	memcpy(psrc, (const void *)s->log->aeskey, KEY_LENGTH);
	if (copy_to_user(buf, psrc, KEY_LENGTH)) {
		kfree(psrc);
		pr_err("error miteelog %s\n", __func__);
		return -EFAULT;
	}
	kfree(psrc);
	ret = KEY_LENGTH;
	return ret;
}

static int mitee_memlog_key_open(struct inode *inode, struct file *file)
{
	int ret;

	ret = nonseekable_open(inode, file);
	if (unlikely(ret))
		return ret;
	return 0;
}

static int mitee_memlog_key_release(struct inode *inode, struct file *file)
{
	return 0;
}

static unsigned int mitee_memlog_key_poll(struct file *file,
					  struct poll_table_struct *wait)
{
	return 0;
}

static const struct proc_ops mitee_memlog_key_fops = {
	.proc_open = mitee_memlog_key_open,
	.proc_read = mitee_memlog_key_read,
	.proc_release = mitee_memlog_key_release,
	.proc_poll = mitee_memlog_key_poll,
};

static int mitee_call_notifier_register(struct notifier_block *n)
{
	struct optee *optee = get_optee_drv_state();

	if (!optee) {
		pr_err("mitee_driver_state is NULL\n");
		return -EFAULT;
	}

	return atomic_notifier_chain_register(&optee->notifier, n);
}

static int mitee_call_notifier_unregister(struct notifier_block *n)
{
	struct optee *optee = get_optee_drv_state();

	if (!optee) {
		pr_err("mitee_driver_state is NULL\n");
		return -EFAULT;
	}

	return atomic_notifier_chain_unregister(&optee->notifier, n);
}

union memlog_args {
	union common_args common;

	struct {
		u64 cmd;
	} in;

	struct {
		u64 paddr;
		u64 size;
	} out;
};

int mitee_memlog_probe(struct platform_device *pdev)
{
	struct mitee_memlog_state *s;
	struct optee *optee = get_optee_drv_state();
	int result = 0;
	phys_addr_t pa;
	phys_addr_t begin;
	phys_addr_t end;
	size_t size;
	void *va;
	union memlog_args args;
	int rc = 0;

	args.in.cmd = OPTEE_FFA_GET_MITEE_LOG_BUFFER;

	dev_dbg(&pdev->dev, "%s cmd = %llx\n", __func__, args.in.cmd);

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s) {
		result = -ENOMEM;
		goto error_alloc_state;
	}

	spin_lock_init(&s->lock);
	s->dev = &pdev->dev;
	s->mitee_dev = s->dev->parent;
	s->get = 0;
	s->b_get = 0;
	g_read_b_buf = false;

	rc = optee->comm_ops->call(&args.common);
	if (rc) {
		pr_err("miteelog service not available %d\n", rc);
		result = -EIO;
		goto error_alloc_log;
	}

	begin = roundup(args.out.paddr, PAGE_SIZE);
	end = rounddown(args.out.paddr + args.out.size, PAGE_SIZE);
	pa = begin;
	size = end - begin;

	pr_err("miteelog paddr=%#llx, size=%zu\n", (uint64_t)pa, size);
	va = memremap(pa, size, MEMREMAP_WB);
	if (!va) {
		pr_err("miteelog ioremap failed\n");
		result = -EFAULT;
		goto error_alloc_log;
	}
	s->log = va;

	s->call_notifier.notifier_call = mitee_memlog_call_notify;
	result = mitee_call_notifier_register(&s->call_notifier);
	if (result < 0) {
		dev_err(&pdev->dev, "failed to register mitee call notifier\n");
		goto error_call_notifier;
	}

	s->panic_notifier.notifier_call = mitee_memlog_notify;
	result = atomic_notifier_chain_register(&panic_notifier_list,
						&s->panic_notifier);
	if (result < 0) {
		dev_err(&pdev->dev,
			"failed to register mitee notifier\n");
		goto error_panic_notifier;
	}
	init_waitqueue_head(&s->mitee_log_wq);
	atomic_set(&s->mitee_log_event_count, 0);
	atomic_set(&s->readable, 1);
	platform_set_drvdata(pdev, s);

	/* create /proc/mitee_log */
	s->proc = proc_create_data("mitee_log", 0444, NULL, &mitee_memlog_fops,
				   s);
	if (!s->proc) {
		pr_info("mitee_log proc_create failed!\n");
		return -ENOMEM;
	}

	/* create /proc/mitee_log_key */
	s->proc_key = proc_create_data("mitee_log_key", 0444, NULL,
				       &mitee_memlog_key_fops, s);
	if (!s->proc_key) {
		pr_info("mitee_log proc_key_create failed!\n");
		return -ENOMEM;
	}

	return 0;

error_panic_notifier:
	mitee_call_notifier_unregister(&s->call_notifier);
error_call_notifier:
	/*
	 * TODO notify tee we failed register notifier
	 * trusty_std_call32(s->trusty_dev, SMC_SC_SHARED_LOG_RM,
	 * (u32)pa, (u32)((u64)pa >> 32), 0);
	 * error_std_call:
	 * __free_pages(s->log_pages, get_order(TRUSTY_LOG_SIZE));
	 */
error_alloc_log:
	kfree(s);
	s = NULL;
error_alloc_state:
	return result;
}

int mitee_memlog_remove(struct platform_device *pdev)
{
	/* int result; */
	struct mitee_memlog_state *s = platform_get_drvdata(pdev);
	/* phys_addr_t pa = page_to_phys(s->log_pages); */
	if (!s)
		return 0;

	dev_dbg(&pdev->dev, "%s get = %x\n", __func__, s->get);
	proc_remove(s->proc);
	proc_remove(s->proc_key);
	atomic_notifier_chain_unregister(&panic_notifier_list,
					 &s->panic_notifier);
	mitee_call_notifier_unregister(&s->call_notifier);
	/*
	 * TODO notify tee we failed register notifier
	 * result = trusty_std_call32(s->trusty_dev, SMC_SC_SHARED_LOG_RM,
	 * (u32)pa, (u32)((u64)pa >> 32), 0);
	 * if (result) {
	 * pr_err("trusty std call (SMC_SC_SHARED_LOG_RM) failed: %d\n", result);
	 * }
	 * __free_pages(s->log_pages, get_order(TRUSTY_LOG_SIZE));
	 */
	kfree(s);

	return 0;
}
