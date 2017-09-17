/*
 * max3191x.h - in-kernel API for Maxim MAX3191x industrial serializer
 *
 * Copyright (C) 2017 KUNBUS GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License (version 2) as
 * published by the Free Software Foundation.
 */

#ifndef _MAX3191X_H_
#define _MAX3191X_H_

#include <linux/device.h>

enum max3191x_mode {
	STATUS_BYTE_ENABLED,
	STATUS_BYTE_DISABLED,
};

int max3191x_set_mode(struct device *dev, enum max3191x_mode mode);
u8 max3191x_get_status(struct device *dev);

#endif
