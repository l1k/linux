// SPDX-License-Identifier: GPL-2.0-only
/*
 * Reset driver for Infineon SLB9670 Trusted Platform Module
 *
 * Copyright (C) 2022 KUNBUS GmbH
 */

#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/mod_devicetable.h>
#include <linux/platform_device.h>
#include <linux/reset-controller.h>

/*
 * Time intervals used in the reset sequence:
 *
 * RSTIN: minimum time to hold the reset line deasserted
 * WRST: minimum time to hold the reset line asserted
 */
#define SLB9670_TIME_RSTIN	60 /* msecs */
#define SLB9670_TIME_WRST	2  /* usecs */

struct reset_slb9670 {
	struct reset_controller_dev rcdev;
	struct gpio_desc *gpio;
	unsigned int already_reset:1;
};

static inline struct reset_slb9670 *
to_reset_slb9670(struct reset_controller_dev *rcdev)
{
	return container_of(rcdev, struct reset_slb9670, rcdev);
}

static int reset_slb9670_assert(struct reset_controller_dev *rcdev,
				unsigned long id)
{
	struct reset_slb9670 *reset_slb9670 = to_reset_slb9670(rcdev);

	gpiod_set_value(reset_slb9670->gpio, 1);
	return 0;
}

static int reset_slb9670_deassert(struct reset_controller_dev *rcdev,
				  unsigned long id)
{
	struct reset_slb9670 *reset_slb9670 = to_reset_slb9670(rcdev);

	/*
	 * Perform the reset sequence: Deassert and assert the reset line twice
	 * and wait the respective time intervals. After a last wait interval
	 * of RSTIN the chip is ready to receive the first command.
	 */
	gpiod_set_value(reset_slb9670->gpio, 0);
	msleep(SLB9670_TIME_RSTIN);
	gpiod_set_value(reset_slb9670->gpio, 1);
	udelay(SLB9670_TIME_WRST);
	gpiod_set_value(reset_slb9670->gpio, 0);
	msleep(SLB9670_TIME_RSTIN);
	gpiod_set_value(reset_slb9670->gpio, 1);
	udelay(SLB9670_TIME_WRST);
	gpiod_set_value(reset_slb9670->gpio, 0);
	msleep(SLB9670_TIME_RSTIN);

	return 0;
}

static int reset_slb9670_reset(struct reset_controller_dev *rcdev,
			       unsigned long id)
{
	struct reset_slb9670 *reset_slb9670 = to_reset_slb9670(rcdev);
	int ret;

	/* may only be reset once per boot */
	if (reset_slb9670->already_reset)
		return 0;

	ret = reset_slb9670_assert(rcdev, id);
	if (ret)
		return ret;

	ret = reset_slb9670_deassert(rcdev, id);
	if (ret)
		return ret;

	reset_slb9670->already_reset = true;
	return 0;
}

static int reset_slb9670_status(struct reset_controller_dev *rcdev,
				unsigned long id)
{
	struct reset_slb9670 *reset_slb9670 = to_reset_slb9670(rcdev);

	return gpiod_get_value(reset_slb9670->gpio);
}

static const struct reset_control_ops reset_slb9670_ops = {
	.assert		= reset_slb9670_assert,
	.deassert	= reset_slb9670_deassert,
	.reset		= reset_slb9670_reset,
	.status		= reset_slb9670_status,
};

static int reset_slb9670_of_xlate(struct reset_controller_dev *rcdev,
				  const struct of_phandle_args *reset_spec)
{
	return 0;
}

static int reset_slb9670_probe(struct platform_device *pdev)
{
	struct reset_slb9670 *reset_slb9670;
	struct device *dev = &pdev->dev;

	reset_slb9670 = devm_kzalloc(dev, sizeof(*reset_slb9670), GFP_KERNEL);
	if (!reset_slb9670)
		return -ENOMEM;

	reset_slb9670->gpio = devm_gpiod_get(dev, "reset", GPIOD_ASIS);
	if (IS_ERR(reset_slb9670->gpio))
		return dev_err_probe(dev, PTR_ERR(reset_slb9670->gpio),
				     "cannot get reset gpio\n");

	reset_slb9670->rcdev.nr_resets = 1;
	reset_slb9670->rcdev.owner = THIS_MODULE;
	reset_slb9670->rcdev.of_node = dev->of_node;
	reset_slb9670->rcdev.ops = &reset_slb9670_ops;
	reset_slb9670->rcdev.of_xlate = reset_slb9670_of_xlate;
	reset_slb9670->rcdev.of_reset_n_cells = 0;

	return devm_reset_controller_register(dev, &reset_slb9670->rcdev);
}

static const struct of_device_id reset_slb9670_dt_ids[] = {
	{ .compatible = "infineon,slb9670-reset" },
	{ /* sentinel */ },
};
MODULE_DEVICE_TABLE(of, reset_slb9670_dt_ids);

static struct platform_driver reset_slb9670_driver = {
	.probe	= reset_slb9670_probe,
	.driver = {
		.name		= "reset-slb9670",
		.of_match_table	= reset_slb9670_dt_ids,
	},
};
module_platform_driver(reset_slb9670_driver);

MODULE_DESCRIPTION("Infineon SLB9670 TPM Reset Driver");
MODULE_AUTHOR("Lino Sanfilippo <l.sanfilippo@kunbus.com>");
MODULE_LICENSE("GPL");
