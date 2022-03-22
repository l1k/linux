// SPDX-License-Identifier: GPL-2.0-only
/*
 * tpm_tis_spi_slb9670.c
 *
 * Copyright (C) 2022 KUNBUS GmbH
 *
 */

#include <linux/gpio/consumer.h>
#include <linux/spi/spi.h>
#include <linux/delay.h>

#include "tpm_tis_core.h"
#include "tpm_tis_spi.h"

/*
 * Time intervals used in the reset sequence.
 * RSTIN: minimum time to hold the reset line deasserted.
 * WRST: minimum time to hold the reset line asserted.
 */
#define SLB9670_TIME_RSTIN	60 /* time in ms */
#define SLB9670_TIME_WRST	2  /* time in usecs */

int slb9670_spi_unset_reset(struct tpm_tis_data *data)
{
	/*
	 * Perform the reset sequence: we have to deassert and assert the reset
	 * line two times and wait the respective time intervals.
	 * After a last wait interval of RSTIN the chip is ready to receive the
	 * first command.
	 */
	gpiod_set_value(data->reset_gpio, 0);
	msleep(SLB9670_TIME_RSTIN);
	gpiod_set_value(data->reset_gpio, 1);
	udelay(SLB9670_TIME_WRST);
	gpiod_set_value(data->reset_gpio, 0);
	msleep(SLB9670_TIME_RSTIN);
	gpiod_set_value(data->reset_gpio, 1);
	udelay(SLB9670_TIME_WRST);
	gpiod_set_value(data->reset_gpio, 0);
	msleep(SLB9670_TIME_RSTIN);

	return 0;
}

int slb9670_spi_set_reset(struct tpm_tis_data *data)
{
	gpiod_set_value(data->reset_gpio, 1);
	return 0;
}

static const struct tpm_tis_phy_ops slb9670_spi_phy_ops = {
	.read_bytes = tpm_tis_spi_read_bytes,
	.write_bytes = tpm_tis_spi_write_bytes,
	.read16 = tpm_tis_spi_read16,
	.read32 = tpm_tis_spi_read32,
	.write32 = tpm_tis_spi_write32,
	.set_reset = slb9670_spi_set_reset,
	.unset_reset = slb9670_spi_unset_reset,
};

int slb9670_spi_probe(struct spi_device *spi)
{
	struct tpm_tis_spi_phy *phy;
	int irq;

	phy = devm_kzalloc(&spi->dev, sizeof(struct tpm_tis_spi_phy),
			   GFP_KERNEL);
	if (!phy)
		return -ENOMEM;

	phy->flow_control = tpm_tis_spi_flow_control;

	/* If the SPI device has an IRQ then use that */
	if (spi->irq > 0)
		irq = spi->irq;
	else
		irq = -1;

	init_completion(&phy->ready);
	return tpm_tis_spi_init(spi, phy, irq, &slb9670_spi_phy_ops);
}
