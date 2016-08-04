/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Power down Thunderbolt controller on Macs when nothing is plugged in
 *
 * Copyright (C) 2019 Lukas Wunner <lukas@wunner.de>
 */

#ifndef THUNDERBOLT_PM_APPLE_H
#define THUNDERBOLT_PM_APPLE_H

#if IS_ENABLED(CONFIG_ACPI) && IS_ENABLED(CONFIG_PM)
void tb_pm_apple_init(struct tb *tb);
void tb_pm_apple_fini(struct tb *tb);
#else
static inline void tb_pm_apple_init(struct tb *tb) {}
static inline void tb_pm_apple_fini(struct tb *tb) {}
#endif

#endif
