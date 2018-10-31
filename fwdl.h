/*
 * Copyright (C) 2006-2017, Marvell International Ltd.
 *
 * This software file (the "File") is distributed by Marvell International
 * Ltd. under the terms of the GNU General Public License Version 2, June 1991
 * (the "License").  You may use, redistribute and/or modify this File in
 * accordance with the terms and conditions of the License, a copy of which
 * is available by writing to the Free Software Foundation, Inc.
 *
 * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE
 * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about
 * this warranty disclaimer.
 */

/* Description:  This file defines firmware download related
 * functions.
 */

#ifndef _FWDL_H_
#define _FWDL_H_

#define FW_CHECK_MSECS                  3
#define FW_MAX_NUM_CHECKS               0xffff
#define FW_DOWNLOAD_BLOCK_SIZE          256


int mwl_fwdl_download_firmware(struct ieee80211_hw *hw);

#endif /* _FWDL_H_ */
