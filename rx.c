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

/* Description:  This file implements receive related functions. */

#include <linux/etherdevice.h>
#include <linux/skbuff.h>

#include "sysadpt.h"
#include "dev.h"
#include "rx.h"


#define DECRYPT_ERR_MASK        0x80
#define GENERAL_DECRYPT_ERR     0xFF
#define TKIP_DECRYPT_MIC_ERR    0x02
#define WEP_DECRYPT_ICV_ERR     0x04
#define TKIP_DECRYPT_ICV_ERR    0x08

#define W836X_RSSI_OFFSET       8

/* Receive rate information constants */
#define RX_RATE_INFO_FORMAT_11A       0
#define RX_RATE_INFO_FORMAT_11B       1
#define RX_RATE_INFO_FORMAT_11N       2
#define RX_RATE_INFO_FORMAT_11AC      4

#define RX_RATE_INFO_HT20             0
#define RX_RATE_INFO_HT40             1
#define RX_RATE_INFO_HT80             2
#define RX_RATE_INFO_HT160            3

#define RX_RATE_INFO_LONG_INTERVAL    0
#define RX_RATE_INFO_SHORT_INTERVAL   1


void mwl_rx_prepare_status(struct mwl_rx_desc *pdesc,
					 struct ieee80211_rx_status *status)
{
	u16 rate, format, nss, bw, gi, rt;

	memset(status, 0, sizeof(*status));

	status->signal = -(pdesc->rssi + W836X_RSSI_OFFSET);

	rate = le16_to_cpu(pdesc->rate);
	format = rate & MWL_RX_RATE_FORMAT_MASK;
	nss = (rate & MWL_RX_RATE_NSS_MASK) >> MWL_RX_RATE_NSS_SHIFT;
	bw = (rate & MWL_RX_RATE_BW_MASK) >> MWL_RX_RATE_BW_SHIFT;
	gi = (rate & MWL_RX_RATE_GI_MASK) >> MWL_RX_RATE_GI_SHIFT;
	rt = (rate & MWL_RX_RATE_RT_MASK) >> MWL_RX_RATE_RT_SHIFT;

	switch (format) {
	case RX_RATE_INFO_FORMAT_11N:
		status->flag |= RX_FLAG_HT;
		if (bw == RX_RATE_INFO_HT40)
			status->flag |= RX_FLAG_40MHZ;
		if (gi == RX_RATE_INFO_SHORT_INTERVAL)
			status->flag |= RX_FLAG_SHORT_GI;
		break;
	case RX_RATE_INFO_FORMAT_11AC:
		status->flag |= RX_FLAG_VHT;
		if (bw == RX_RATE_INFO_HT40)
			status->flag |= RX_FLAG_40MHZ;
		if (bw == RX_RATE_INFO_HT80)
			status->vht_flag |= RX_VHT_FLAG_80MHZ;
		if (bw == RX_RATE_INFO_HT160)
			status->vht_flag |= RX_VHT_FLAG_160MHZ;
		if (gi == RX_RATE_INFO_SHORT_INTERVAL)
			status->flag |= RX_FLAG_SHORT_GI;
		status->vht_nss = (nss + 1);
		break;
	}

	status->rate_idx = rt;

	if (pdesc->channel > BAND_24_CHANNEL_NUM) {
		status->band = NL80211_BAND_5GHZ;
		if ((!(status->flag & RX_FLAG_HT)) &&
		    (!(status->flag & RX_FLAG_VHT))) {
			status->rate_idx -= 5;
			if (status->rate_idx >= BAND_50_RATE_NUM)
				status->rate_idx = BAND_50_RATE_NUM - 1;
		}
	} else {
		status->band = NL80211_BAND_2GHZ;
		if ((!(status->flag & RX_FLAG_HT)) &&
		    (!(status->flag & RX_FLAG_VHT))) {
			if (status->rate_idx >= BAND_24_RATE_NUM)
				status->rate_idx = BAND_24_RATE_NUM - 1;
		}
	}

	status->freq = ieee80211_channel_to_frequency(pdesc->channel,
						      status->band);

	/* check if status has a specific error bit (bit 7) set or indicates
	 * a general decrypt error
	 */
	if ((pdesc->status == GENERAL_DECRYPT_ERR) ||
	    (pdesc->status & DECRYPT_ERR_MASK)) {
		/* check if status is not equal to 0xFF
		 * the 0xFF check is for backward compatibility
		 */
		if (pdesc->status != GENERAL_DECRYPT_ERR) {
			if (((pdesc->status & (~DECRYPT_ERR_MASK)) &
			    TKIP_DECRYPT_MIC_ERR) && !((pdesc->status &
			    (WEP_DECRYPT_ICV_ERR | TKIP_DECRYPT_ICV_ERR)))) {
				status->flag |= RX_FLAG_MMIC_ERROR;
			}
		}
	}
}
EXPORT_SYMBOL_GPL(mwl_rx_prepare_status);

//#if KERNEL_VERSION(4, 6, 0) > LINUX_VERSION_CODE
void mwl_rx_enable_sta_amsdu(struct mwl_priv *priv,
					   u8 *sta_addr)
{
	struct mwl_sta *sta_info;
	struct ieee80211_sta *sta;

	spin_lock_bh(&priv->sta_lock);
	list_for_each_entry(sta_info, &priv->sta_list, list) {
		sta = container_of((char *)sta_info, struct ieee80211_sta,
				   drv_priv[0]);
		if (ether_addr_equal(sta->addr, sta_addr)) {
			sta_info->is_amsdu_allowed = true;
			break;
		}
	}
	spin_unlock_bh(&priv->sta_lock);
}
EXPORT_SYMBOL_GPL(mwl_rx_enable_sta_amsdu);
//#endif

struct mwl_vif *mwl_rx_find_vif_bss(struct mwl_priv *priv,
						  u8 *bssid)
{
	struct mwl_vif *mwl_vif;

	spin_lock_bh(&priv->vif_lock);
	list_for_each_entry(mwl_vif, &priv->vif_list, list) {
		if (ether_addr_equal(bssid, mwl_vif->bssid)) {
			spin_unlock_bh(&priv->vif_lock);
			return mwl_vif;
		}
	}
	spin_unlock_bh(&priv->vif_lock);

	return NULL;
}
EXPORT_SYMBOL_GPL(mwl_rx_find_vif_bss);

void mwl_rx_remove_dma_header(struct sk_buff *skb, __le16 qos)
{
	struct mwl_dma_data *tr;
	int hdrlen;

	tr = (struct mwl_dma_data *)skb->data;
	hdrlen = ieee80211_hdrlen(tr->wh.frame_control);

	if (hdrlen != sizeof(tr->wh)) {
		if (ieee80211_is_data_qos(tr->wh.frame_control)) {
			memmove(tr->data - hdrlen, &tr->wh, hdrlen - 2);
			*((__le16 *)(tr->data - 2)) = qos;
		} else {
			memmove(tr->data - hdrlen, &tr->wh, hdrlen);
		}
	}

	if (hdrlen != sizeof(*tr))
		skb_pull(skb, sizeof(*tr) - hdrlen);
}
EXPORT_SYMBOL_GPL(mwl_rx_remove_dma_header);

