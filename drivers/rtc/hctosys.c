/*
 * RTC subsystem, initialize system time on startup
 *
 * Copyright (C) 2005 Tower Technologies
 * Author: Alessandro Zummo <a.zummo@towertech.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
*/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/rtc.h>
#include <linux/delay.h>

/* IMPORTANT: the RTC only stores whole seconds. It is arbitrary
 * whether it stores the most close value or the value with partial
 * seconds truncated. However, it is important that we use it to store
 * the truncated value. This is because otherwise it is necessary,
 * in an rtc sync function, to read both xtime.tv_sec and
 * xtime.tv_nsec. On some processors (i.e. ARM), an atomic read
 * of >32bits is not possible. So storing the most close value would
 * slow down the sync API. So here we have the truncated value and
 * the best guess is to add 0.5s.
 */

static int rtc_read_ts64(struct rtc_device *rtc, struct rtc_time *tm,
			 struct timespec64 *tv64)
{
	int err;

	err = rtc_read_time(rtc, tm);
	if (err) {
		dev_err(rtc->dev.parent,
			"hctosys: unable to read the hardware clock\n");
		return err;
	}

	tv64->tv_sec = rtc_tm_to_time64(tm);

	if (BITS_PER_LONG == 32 && tv64->tv_sec > INT_MAX)
		return -ERANGE;

	return 0;
}

int rtc_hctosys(struct rtc_device *rtc)
{
	struct timespec64 ts500 = { .tv_nsec = NSEC_PER_SEC >> 1 },
			  ts100 = { };
	struct rtc_time tm;
	int i, err;

	if (rtc_hctosys_ret == 0)
		return -EALREADY;

	err = rtc_read_ts64(rtc, &tm, &ts500);
	if (err)
		goto err_read;

	err = do_settimeofday64(&ts500);
	if (err)
		goto err_read;

	dev_info(rtc->dev.parent,
		"setting system clock to "
		"%d-%02d-%02d %02d:%02d:%02d UTC (%lld)\n",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec,
		(long long) ts500.tv_sec);

	for (i = 0; i < 10 ; i++) {
		if (rtc_read_ts64(rtc, &tm, &ts100))
			goto err_read;

		if (ts100.tv_sec != ts500.tv_sec) {
			do_settimeofday64(&ts100);
			goto err_read;
		}

		usleep_range(90 * USEC_PER_MSEC, 100 * USEC_PER_MSEC);
	}

err_read:
	rtc_hctosys_ret = err;
	return err;
}
