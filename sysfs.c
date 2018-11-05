/*
 * Copyright (C) 2018, Laird Technologies.
 *
 * This software file (the "File") is distributed by Laird Technologies
 * under the terms of the GNU General Public License Version 2, June 1991
 * (the "License").  You may use, redistribute and/or modify this File in
 * accordance with the terms and conditions of the License, a copy of which
 * is available by writing to the Free Software Foundation, Inc.
 *
 * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE
 * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about
 * this warranty disclaimer.
 */

/* Description:  This file implements sysfs related functions. */

#include <linux/sysfs.h>

#include "sysadpt.h"
#include "dev.h"


static ssize_t radio_type_show(struct device *d, struct device_attribute *attr, char *buf)
{
	struct ieee80211_hw *hw = dev_get_drvdata(d);;

	if (hw && hw->priv) {
		struct mwl_priv *priv = hw->priv;

		return snprintf(buf, PAGE_SIZE, "%lx\n", priv->radio_caps & LRD_CAP_SU60);
	}

	return 0;
}
static DEVICE_ATTR(radio_type, 0444, radio_type_show, NULL);

static struct attribute *lrd_sys_status_entries[] = {
	&dev_attr_radio_type.attr,
	NULL
};

static const struct attribute_group lrd_attribute_group = {
	.name  = "lrd_info",
	.attrs = lrd_sys_status_entries,
};

void lrd_sysfs_init(struct ieee80211_hw *hw)
{
	struct mwl_priv *priv;
	int ret;

	if (!hw || !hw->priv ) {
		return;
	}

	priv = hw->priv;

	if (priv->dev) {
		ret = sysfs_create_group(&priv->dev->kobj, &lrd_attribute_group);
		if (ret)
			wiphy_err(priv->hw->wiphy, "%s: Unable to create attribute group!\n", __func__);
	}
}

void lrd_sysfs_remove(struct ieee80211_hw *hw)
{
	struct mwl_priv *priv;

	if (!hw || !hw->priv) {
		return;
	}

	priv = hw->priv;

	if (priv) {
		sysfs_remove_group(&priv->dev->kobj, &lrd_attribute_group);
	}
}
