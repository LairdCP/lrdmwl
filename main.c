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

/* Description:  This file implements main functions of this module. */

#include <linux/module.h>
#ifdef CONFIG_OF
#include <linux/of.h>
#endif

#include "sysadpt.h"
#include "dev.h"
#include "pcie.h"
#include "fwdl.h"
#include "fwcmd.h"
#include "tx.h"
#include "rx.h"
#include "isr.h"
#include "thermal.h"
#ifdef CONFIG_DEBUG_FS
#include "debugfs.h"
#endif

#include "main.h"
#include "vendor_cmd.h"
#define FILE_PATH_LEN    64

#define NOT_LRD_HW  0x214C5244

static const struct ieee80211_channel mwl_channels_24[] = {
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2412, .hw_value = 1, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2417, .hw_value = 2, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2422, .hw_value = 3, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2427, .hw_value = 4, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2432, .hw_value = 5, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2437, .hw_value = 6, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2442, .hw_value = 7, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2447, .hw_value = 8, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2452, .hw_value = 9, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2457, .hw_value = 10, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2462, .hw_value = 11, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2467, .hw_value = 12, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2472, .hw_value = 13, },
	{ .band = NL80211_BAND_2GHZ, .center_freq = 2484, .hw_value = 14, },
};

const struct ieee80211_rate mwl_rates_24[] = {
	{ .bitrate = 10, .hw_value = 2, },
	{ .bitrate = 20, .hw_value = 4, },
	{ .bitrate = 55, .hw_value = 11, },
	{ .bitrate = 110, .hw_value = 22, },
	{ .bitrate = 60, .hw_value = 12, },
	{ .bitrate = 90, .hw_value = 18, },
	{ .bitrate = 120, .hw_value = 24, },
	{ .bitrate = 180, .hw_value = 36, },
	{ .bitrate = 240, .hw_value = 48, },
	{ .bitrate = 360, .hw_value = 72, },
	{ .bitrate = 480, .hw_value = 96, },
	{ .bitrate = 540, .hw_value = 108, },
};

static const struct ieee80211_channel mwl_channels_50[] = {
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5180, .hw_value = 36, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5200, .hw_value = 40, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5220, .hw_value = 44, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5240, .hw_value = 48, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5260, .hw_value = 52, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5280, .hw_value = 56, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5300, .hw_value = 60, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5320, .hw_value = 64, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5500, .hw_value = 100, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5520, .hw_value = 104, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5540, .hw_value = 108, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5560, .hw_value = 112, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5580, .hw_value = 116, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5600, .hw_value = 120, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5620, .hw_value = 124, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5640, .hw_value = 128, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5660, .hw_value = 132, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5680, .hw_value = 136, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5700, .hw_value = 140, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5720, .hw_value = 144, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5745, .hw_value = 149, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5765, .hw_value = 153, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5785, .hw_value = 157, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5805, .hw_value = 161, },
	{ .band = NL80211_BAND_5GHZ, .center_freq = 5825, .hw_value = 165, },
};

const struct ieee80211_rate mwl_rates_50[] = {
	{ .bitrate = 60, .hw_value = 12, },
	{ .bitrate = 90, .hw_value = 18, },
	{ .bitrate = 120, .hw_value = 24, },
	{ .bitrate = 180, .hw_value = 36, },
	{ .bitrate = 240, .hw_value = 48, },
	{ .bitrate = 360, .hw_value = 72, },
	{ .bitrate = 480, .hw_value = 96, },
	{ .bitrate = 540, .hw_value = 108, },
};

static const struct ieee80211_iface_limit ap_if_limits[] = {
	{ .max = SYSADPT_NUM_OF_AP,	.types = BIT(NL80211_IFTYPE_AP) },
	{ .max = 1,	.types = BIT(NL80211_IFTYPE_STATION) |
							BIT(NL80211_IFTYPE_P2P_GO) |
							BIT(NL80211_IFTYPE_P2P_CLIENT)},
};

static const struct ieee80211_iface_combination ap_if_comb = {
	.limits = ap_if_limits,
	.n_limits = ARRAY_SIZE(ap_if_limits),
	.max_interfaces = SYSADPT_NUM_OF_AP,
	.num_different_channels = 1,
	.radar_detect_widths =	BIT(NL80211_CHAN_WIDTH_20_NOHT) |
				BIT(NL80211_CHAN_WIDTH_20) |
				BIT(NL80211_CHAN_WIDTH_40) |
				BIT(NL80211_CHAN_WIDTH_80) |
				BIT(NL80211_CHAN_WIDTH_160),
};

#ifdef CONFIG_PM
static const struct wiphy_wowlan_support lrd_wowlan_support = {
	.flags = WIPHY_WOWLAN_ANY        |
	         WIPHY_WOWLAN_DISCONNECT |
	         WIPHY_WOWLAN_NET_DETECT,
	.n_patterns = 0,
	.pattern_min_len = 0,
	.pattern_max_len = 0,
};
#endif

/* CAL data config file */
static char *cal_data_cfg;

/* WMM Turbo mode */
int wmm_turbo = 1;

/* EDMAC Control */
int EDMAC_Ctrl = 0x0;

/* Tx AMSDU control*/
int tx_amsdu_enable = 0;

int SISO_mode = 0;

int lrd_debug = 0;

static bool mwl_is_world_mode(struct mwl_priv *priv)
{
	if (priv->fw_alpha2[0] == '0' && priv->fw_alpha2[1] == '0') {
		return true;
	}

	return false;
}

bool mfg_mode = false;

static int mwl_init_firmware(struct mwl_priv *priv)
{
	int rc = 0;
	const char *fw_name;

	fw_name = priv->if_ops.mwl_chip_tbl.mfg_image;

	rc = request_firmware_direct((const struct firmware **)&priv->fw_ucode,
				      fw_name, priv->dev);

	if (rc) {
		rc = 0;

		fw_name = priv->if_ops.mwl_chip_tbl.fw_image;

		rc = request_firmware((const struct firmware **)&priv->fw_ucode,
				       fw_name, priv->dev);

		if (rc) {
			wiphy_err(priv->hw->wiphy,
				  "%s: cannot find firmware image <%s>\n",
				  MWL_DRV_NAME, fw_name);

			goto err_load_fw;
		}

	} else {
		mfg_mode = true;
	}

	wiphy_info(priv->hw->wiphy, "%s: found firmware image <%s>\n",
		   MWL_DRV_NAME, fw_name);

	rc = priv->if_ops.prog_fw(priv);
	if (rc) {
		wiphy_err(priv->hw->wiphy,
			  "%s: firmware download/init failed! <%s> %x\n",
			  MWL_DRV_NAME, fw_name, rc);
		goto err_download_fw;
	}

	if (cal_data_cfg) {

		wiphy_info(priv->hw->wiphy,
			"Looking for cal file <%s>\n", cal_data_cfg);

		if ((request_firmware((const struct firmware **)&priv->cal_data,
		     cal_data_cfg, priv->dev)) < 0)
			wiphy_info(priv->hw->wiphy,
				  "Cal data request_firmware() failed\n");
	}

	return rc;

err_download_fw:

	release_firmware(priv->fw_ucode);

err_load_fw:

	wiphy_err(priv->hw->wiphy, "firmware init fail\n");

	return rc;
}

static void mwl_reg_notifier(struct wiphy *wiphy,
			     struct regulatory_request *request)
{
	struct ieee80211_hw *hw;
	struct mwl_priv *priv;

	hw = (struct ieee80211_hw *)wiphy_priv(wiphy);
	priv = hw->priv;

	if (!priv->regulatory_set) {
		priv->regulatory_set = true;
		regulatory_hint(wiphy, priv->fw_alpha2);
	} else {
		if ( memcmp(priv->fw_alpha2, request->alpha2, 2) &&
			(request->initiator == NL80211_REGDOM_SET_BY_USER)) {
			regulatory_hint(wiphy, priv->fw_alpha2);
		}
	}

	priv->dfs_region = request->dfs_region;
}

static void mwl_set_ht_caps(struct mwl_priv *priv,
			    struct ieee80211_supported_band *band)
{
	struct ieee80211_hw *hw;

	hw = priv->hw;

	band->ht_cap.ht_supported = 1;

	band->ht_cap.cap |= IEEE80211_HT_CAP_LDPC_CODING;
	band->ht_cap.cap |= IEEE80211_HT_CAP_SUP_WIDTH_20_40;
	band->ht_cap.cap |= IEEE80211_HT_CAP_SM_PS;
	band->ht_cap.cap |= IEEE80211_HT_CAP_SGI_20;
	band->ht_cap.cap |= IEEE80211_HT_CAP_SGI_40;
	band->ht_cap.cap |= IEEE80211_HT_CAP_DSSSCCK40;

	if ((priv->chip_type == MWL8997) &&
		(priv->ant_tx_num > 1)){
		band->ht_cap.cap |= IEEE80211_HT_CAP_TX_STBC;
		band->ht_cap.cap |= (1 << IEEE80211_HT_CAP_RX_STBC_SHIFT);
	}

	ieee80211_hw_set(hw, AMPDU_AGGREGATION);
	ieee80211_hw_set(hw, SUPPORTS_AMSDU_IN_AMPDU);
	band->ht_cap.ampdu_factor = IEEE80211_HT_MAX_AMPDU_64K;
	band->ht_cap.ampdu_density = IEEE80211_HT_MPDU_DENSITY_4;

	band->ht_cap.mcs.rx_mask[0] = 0xff;

	if (priv->ant_rx_num > 1)
		band->ht_cap.mcs.rx_mask[1] = 0xff;

#if 0
	if (priv->antenna_rx == ANTENNA_RX_4_AUTO)
		band->ht_cap.mcs.rx_mask[2] = 0xff;
#endif
	band->ht_cap.mcs.rx_mask[4] = 0x01;

	band->ht_cap.mcs.tx_params = IEEE80211_HT_MCS_TX_DEFINED;
}

static void mwl_set_vht_caps(struct mwl_priv *priv,
			     struct ieee80211_supported_band *band)
{
	band->vht_cap.vht_supported = 1;

	band->vht_cap.cap |= IEEE80211_VHT_CAP_MAX_MPDU_LENGTH_3895;
	band->vht_cap.cap |= IEEE80211_VHT_CAP_RXLDPC;
	band->vht_cap.cap |= IEEE80211_VHT_CAP_SHORT_GI_80;
	band->vht_cap.cap |= IEEE80211_VHT_CAP_RXSTBC_1;

	if (priv->ant_tx_num > 1)
		band->vht_cap.cap |= IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE;

	band->vht_cap.cap |= IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE;
	band->vht_cap.cap |= IEEE80211_VHT_CAP_MAX_A_MPDU_LENGTH_EXPONENT_MASK;
	band->vht_cap.cap |= IEEE80211_VHT_CAP_RX_ANTENNA_PATTERN;
	band->vht_cap.cap |= IEEE80211_VHT_CAP_TX_ANTENNA_PATTERN;

	if (priv->chip_type == MWL8997) {
		if (priv->ant_tx_num > 1)
			band->vht_cap.cap |= IEEE80211_VHT_CAP_TXSTBC;
	}

	if (priv->chip_type == MWL8964) {
		band->vht_cap.cap |= IEEE80211_VHT_CAP_SHORT_GI_160;
		band->vht_cap.cap |= IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_160MHZ;
	}

	if (priv->ant_rx_num == 1)
		band->vht_cap.vht_mcs.rx_mcs_map = cpu_to_le16(0xfffe);
	else if (priv->ant_rx_num == 2)
		band->vht_cap.vht_mcs.rx_mcs_map = cpu_to_le16(0xfffa);
	else
		band->vht_cap.vht_mcs.rx_mcs_map = cpu_to_le16(0xffea);

	if (priv->ant_tx_num == 1) {
		band->vht_cap.vht_mcs.tx_mcs_map = cpu_to_le16(0xfffe);
	} else if (priv->ant_tx_num == 2) {
		band->vht_cap.vht_mcs.tx_mcs_map = cpu_to_le16(0xfffa);
	} else
		band->vht_cap.vht_mcs.tx_mcs_map = cpu_to_le16(0xffea);

	if (band->vht_cap.cap & (IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE |
	    IEEE80211_VHT_CAP_MU_BEAMFORMEE_CAPABLE)) {
		band->vht_cap.cap |=
			((priv->ant_tx_num - 1) <<
			IEEE80211_VHT_CAP_BEAMFORMEE_STS_SHIFT) &
			IEEE80211_VHT_CAP_BEAMFORMEE_STS_MASK;
	}

	if (band->vht_cap.cap & (IEEE80211_VHT_CAP_SU_BEAMFORMER_CAPABLE |
	    IEEE80211_VHT_CAP_MU_BEAMFORMER_CAPABLE)) {
		band->vht_cap.cap |=
			((priv->ant_tx_num - 1) <<
			IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_SHIFT) &
			IEEE80211_VHT_CAP_SOUNDING_DIMENSIONS_MASK;
	}
}

void mwl_set_caps(struct mwl_priv *priv)
{
	struct ieee80211_hw *hw;

	hw = priv->hw;

	memset(&priv->band_24, 0,
			sizeof(struct ieee80211_supported_band));
	memset(&priv->band_50, 0,
			sizeof(struct ieee80211_supported_band));

	/* set up band information for 2.4G */
	if (!priv->disable_2g) {
		BUILD_BUG_ON(sizeof(priv->channels_24) !=
			     sizeof(mwl_channels_24));
		memcpy(priv->channels_24, mwl_channels_24,
		       sizeof(mwl_channels_24));

		BUILD_BUG_ON(sizeof(priv->rates_24) != sizeof(mwl_rates_24));
		memcpy(priv->rates_24, mwl_rates_24, sizeof(mwl_rates_24));

		priv->band_24.band = NL80211_BAND_2GHZ;
		priv->band_24.channels = priv->channels_24;
		priv->band_24.n_channels = ARRAY_SIZE(mwl_channels_24);
		priv->band_24.bitrates = priv->rates_24;
		priv->band_24.n_bitrates = ARRAY_SIZE(mwl_rates_24);

		if (mwl_is_world_mode(priv)) {
			/* when configured for WW, firmware does not allow
			 * channels 12-14 to be configured, remove them here
			 * to keep ma80211 in synce with FW.
			 * TODO:  Revisit for Summit Radio */
			priv->band_24.n_channels -= 3;
		}

		mwl_set_ht_caps(priv, &priv->band_24);
		mwl_set_vht_caps(priv, &priv->band_24);

		hw->wiphy->bands[NL80211_BAND_2GHZ] = &priv->band_24;
	}

	/* set up band information for 5G */
	if (!priv->disable_5g) {
		BUILD_BUG_ON(sizeof(priv->channels_50) !=
			     sizeof(mwl_channels_50));
		memcpy(priv->channels_50, mwl_channels_50,
		       sizeof(mwl_channels_50));

		BUILD_BUG_ON(sizeof(priv->rates_50) != sizeof(mwl_rates_50));
		memcpy(priv->rates_50, mwl_rates_50, sizeof(mwl_rates_50));

		priv->band_50.band = NL80211_BAND_5GHZ;
		priv->band_50.channels = priv->channels_50;
		priv->band_50.n_channels = ARRAY_SIZE(mwl_channels_50);
		priv->band_50.bitrates = priv->rates_50;
		priv->band_50.n_bitrates = ARRAY_SIZE(mwl_rates_50);

		wiphy_info(hw->wiphy, "%s: Antcfg = %08x(%d) %08x(%d)\n",
		    __FUNCTION__, priv->ant_tx_bmp,  priv->ant_tx_num,
		    priv->ant_rx_bmp,  priv->ant_rx_num);

		mwl_set_ht_caps(priv, &priv->band_50);
		mwl_set_vht_caps(priv, &priv->band_50);

		hw->wiphy->bands[NL80211_BAND_5GHZ] = &priv->band_50;
	}
}

static void mwl_regd_init(struct mwl_priv *priv)
{
	struct mwl_region_mapping map;

	/* hook regulatory domain change notification */
	priv->hw->wiphy->reg_notifier = mwl_reg_notifier;

	if (mwl_fwcmd_get_region_mapping(priv->hw, &map)) {
		/* If we fail to retrieve mapping, default to WW */
		wiphy_err(priv->hw->wiphy,
			"failed to retrieve region mapping, using world mode\n");
		memset(map.cc,'0', sizeof(map));
	}

	memcpy(priv->fw_alpha2, map.cc, sizeof(priv->fw_alpha2));

	if (mwl_is_world_mode(priv)) {
		wiphy_debug(priv->hw->wiphy, "Setting strict regulatory");
		priv->hw->wiphy->regulatory_flags |= REGULATORY_STRICT_REG;
	}
}

static void remain_on_channel_expire(unsigned long data)
{
	struct ieee80211_hw *hw = (struct ieee80211_hw *)data;
	struct mwl_priv *priv = hw->priv;

	priv->roc.tmr_running = false;
	if (!priv->roc.in_progress)
		return;

	if ((priv->roc.type == IEEE80211_ROC_TYPE_MGMT_TX) &&
		(priv->roc.duration <= NL80211_MIN_REMAIN_ON_CHANNEL_TIME))
		ieee80211_remain_on_channel_expired(hw);
}

void timer_routine(unsigned long data)
{
	struct mwl_priv *priv = (struct mwl_priv *)data;
	struct mwl_ampdu_stream *stream;
	struct mwl_sta *sta_info;
	struct mwl_tx_info *tx_stats;
	int i;

	spin_lock_bh(&priv->stream_lock);
	for (i = 0; i < SYSADPT_TX_AMPDU_QUEUES; i++) {
		stream = &priv->ampdu[i];

		if (stream->state == AMPDU_STREAM_ACTIVE) {
			sta_info = mwl_dev_get_sta(stream->sta);
			tx_stats = &sta_info->tx_stats[stream->tid];

			if ((jiffies - tx_stats->start_time > HZ) &&
			    (tx_stats->pkts < SYSADPT_AMPDU_PACKET_THRESHOLD)) {
				ieee80211_stop_tx_ba_session(stream->sta,
							     stream->tid);
			}

			if (jiffies - tx_stats->start_time > HZ) {
				tx_stats->pkts = 0;
				tx_stats->start_time = jiffies;
			}
		}
	}
	spin_unlock_bh(&priv->stream_lock);

	mod_timer(&priv->period_timer, jiffies +
		  msecs_to_jiffies(SYSADPT_TIMER_WAKEUP_TIME));
}

static int mwl_wl_init(struct mwl_priv *priv)
{
	struct ieee80211_hw *hw;
	int rc;

	hw = priv->hw;
/*
	hw->extra_tx_headroom = SYSADPT_MIN_BYTES_HEADROOM;
	hw->queues = SYSADPT_TX_WMM_QUEUES;
*/
	/* Set rssi values to dBm */
	ieee80211_hw_set(hw, SIGNAL_DBM);
	ieee80211_hw_set(hw, HAS_RATE_CONTROL);

	if (priv->chip_type == MWL8997)
		if (priv->host_if != MWL_IF_USB)
			ieee80211_hw_set(hw, SUPPORTS_PS);

	/* Ask mac80211 not to trigger PS mode
	 * based on PM bit of incoming frames.
	 */
	ieee80211_hw_set(hw, AP_LINK_PS);

	ieee80211_hw_set(hw, SUPPORTS_PER_STA_GTK);
	ieee80211_hw_set(hw, MFP_CAPABLE);
	ieee80211_hw_set(hw, SPECTRUM_MGMT);

	hw->wiphy->flags |= WIPHY_FLAG_IBSS_RSN;
	hw->wiphy->flags |= WIPHY_FLAG_HAS_CHANNEL_SWITCH;

	hw->wiphy->flags |= WIPHY_FLAG_HAS_REMAIN_ON_CHANNEL;

	hw->wiphy->flags |= WIPHY_FLAG_SUPPORTS_TDLS;

	hw->wiphy->features |= NL80211_FEATURE_NEED_OBSS_SCAN;

	hw->wiphy->max_remain_on_channel_duration = 5000;

#ifdef CONFIG_PM
	if (priv->wow.capable) {
		hw->wiphy->wowlan = &lrd_wowlan_support;
		/* max number of SSIDs device can scan for */
		hw->wiphy->max_sched_scan_ssids = 1;
	}
#endif

	hw->vif_data_size = sizeof(struct mwl_vif);
	hw->sta_data_size = sizeof(struct mwl_sta);

	priv->ap_macids_supported = 0x0000ffff;
	priv->sta_macids_supported = 0x00010000;
	priv->macids_used = 0;
	INIT_LIST_HEAD(&priv->vif_list);
	INIT_LIST_HEAD(&priv->sta_list);

	/* Set default radio state, preamble and wmm */
	priv->radio_on = false;
	priv->radio_short_preamble = false;
	priv->wmm_enabled = false;

	priv->powinited = 0;

	priv->csa_active = false;
	priv->dfs_chirp_count_min = 5;
	priv->dfs_chirp_time_interval = 1000;
	priv->dfs_pw_filter = 0;
	priv->dfs_min_num_radar = 5;
	priv->dfs_min_pri_count = 4;

	/* Handle watchdog ba events */
	INIT_WORK(&priv->watchdog_ba_handle, mwl_watchdog_ba_events);
	INIT_WORK(&priv->chnl_switch_handle, mwl_chnl_switch_event);

	priv->is_tx_done_schedule = false;
	priv->is_qe_schedule = false;
	priv->qe_trigger_num = 0;
	priv->qe_trigger_time = jiffies;
	priv->txq_limit = SYSADPT_TX_QUEUE_LIMIT;
	priv->recv_limit = SYSADPT_RECEIVE_LIMIT;

	priv->is_rx_schedule = false;
	priv->cmd_timeout = false;

	mutex_init(&priv->fwcmd_mutex);
	spin_lock_init(&priv->tx_desc_lock);
	spin_lock_init(&priv->vif_lock);
	spin_lock_init(&priv->sta_lock);
	spin_lock_init(&priv->stream_lock);

	rc = mwl_thermal_register(priv);
	if (rc) {
		wiphy_err(hw->wiphy, "%s: fail to register thermal framework\n",
			  MWL_DRV_NAME);
		goto err_thermal_register;
	}

	if (priv->host_if == MWL_IF_SDIO) {
		/* Give SDIO interface some additional time before
		 * sending first command */
		msleep(1000);
	}

	rc = mwl_fwcmd_get_hw_specs(hw);
	if (rc) {
		wiphy_err(hw->wiphy, "%s: fail to get HW specifications\n",
			  MWL_DRV_NAME);
		goto err_wl_init;
	}
	else {
		if (priv->hw_data.fw_release_num == NOT_LRD_HW) {
			wiphy_err(hw->wiphy,
			     "Detected non Laird hardware: 0x%x\n", priv->hw_data.fw_release_num);
			rc = -ENODEV;
			goto err_wl_init;
		}
		else {
			wiphy_info(hw->wiphy,
			     "firmware version: 0x%x\n", priv->hw_data.fw_release_num);
		}
	}

	if (priv->if_ops.register_dev)
		rc = priv->if_ops.register_dev(priv);
	else
		rc = -ENXIO;

	if (rc) {
		wiphy_err(hw->wiphy, "%s: fail to register device\n",
			  MWL_DRV_NAME);
		goto err_wl_init;
	}

	rc = mwl_fwcmd_set_hw_specs(priv->hw);
	if (rc) {
		wiphy_err(priv->hw->wiphy, "%s: fail to set HW specifications\n",
			  MWL_DRV_NAME);
		goto err_wl_init;
	}

	SET_IEEE80211_PERM_ADDR(hw, priv->hw_data.mac_addr);

	rc = mwl_fwcmd_set_cfg_data(hw, cpu_to_le16(2));

	if(rc) {
		wiphy_err(hw->wiphy, "%s: fail to download calibaration data\n",
			MWL_DRV_NAME);
//		goto err_wl_init;
	}

	if (priv->chip_type == MWL8964)
		rc = mwl_fwcmd_get_fw_region_code_sc4(hw,
						      &priv->fw_region_code);
	else
		rc = mwl_fwcmd_get_fw_region_code(hw, &priv->fw_region_code);
	if (!rc) {
		priv->fw_device_pwrtbl = true;
		mwl_regd_init(priv);
		wiphy_info(hw->wiphy,
			   "firmware region code: %x\n", priv->fw_region_code);
	}

	rc = mwl_fwcmd_dump_otp_data(hw);
	if (rc) {
		wiphy_info(hw->wiphy, "OTP Dump failed\n");
	}


	mwl_fwcmd_radio_disable(hw);

	hw->wiphy->available_antennas_tx = MWL_8997_DEF_TX_ANT_BMP;
	hw->wiphy->available_antennas_rx = MWL_8997_DEF_RX_ANT_BMP;

	mwl_fwcmd_rf_antenna(hw, priv->ant_tx_bmp, priv->ant_rx_bmp);

	hw->wiphy->interface_modes = 0;
	hw->wiphy->interface_modes |= BIT(NL80211_IFTYPE_AP);
	hw->wiphy->interface_modes |= BIT(NL80211_IFTYPE_STATION);
	hw->wiphy->interface_modes |= BIT(NL80211_IFTYPE_P2P_GO);
	hw->wiphy->interface_modes |= BIT(NL80211_IFTYPE_P2P_CLIENT);

	hw->wiphy->iface_combinations = &ap_if_comb;
	hw->wiphy->n_iface_combinations = 1;

	mwl_set_caps(priv);

	rc = ieee80211_register_hw(hw);
	if (rc) {
		wiphy_err(hw->wiphy, "%s: fail to register hw\n",
			  MWL_DRV_NAME);
		goto err_wl_init;
	}

	setup_timer(&priv->roc.roc_timer, remain_on_channel_expire, (unsigned long)hw);

	setup_timer(&priv->period_timer, timer_routine, (unsigned long)priv);
	mod_timer(&priv->period_timer, jiffies +
		  msecs_to_jiffies(SYSADPT_TIMER_WAKEUP_TIME));

	return rc;

err_wl_init:
err_thermal_register:

	wiphy_err(hw->wiphy, "init fail %d\n", rc);

	return rc;
}

void mwl_wl_deinit(struct mwl_priv *priv)
{
	struct ieee80211_hw *hw = priv->hw;

	priv->shutdown = true;

	del_timer_sync(&priv->period_timer);

	ieee80211_unregister_hw(hw);

	mwl_thermal_unregister(priv);

	cancel_work_sync(&priv->watchdog_ba_handle);
	cancel_work_sync(&priv->chnl_switch_handle);

	cancel_work_sync(&priv->rx_defer_work);
	destroy_workqueue(priv->rx_defer_workq);
	skb_queue_purge(&priv->rx_defer_skb_q);

	mwl_fwcmd_reset(hw);
}
EXPORT_SYMBOL_GPL(mwl_wl_deinit);

void lrd_radio_recovery(struct mwl_priv *priv)
{
	struct ieee80211_hw *hw = priv->hw;
	int ret;

	wiphy_info(priv->hw->wiphy, "%s: Radio recovery requested!\n", __func__);
	if (priv->recovery_in_progress)
	{
		wiphy_info(priv->hw->wiphy, "recovery_in_progress, skipping\n");
		return;
	}

	priv->recovery_in_progress = 1;

	if (!priv->if_ops.hardware_reset)
	{
		wiphy_info(hw->wiphy, "%s: Radio recovery requested but no reset handler configured!\n", 
			MWL_DRV_NAME);
		return;
	}

	wiphy_info(hw->wiphy, "%s: Initiating radio recovery!!\n",
		  MWL_DRV_NAME);

	// Reset radio hardware
	// The assumption is this reset will also trigger an unload/reload
	// of the radio driver
	ret = priv->if_ops.hardware_reset(priv);
	if (!ret)
		wiphy_info(hw->wiphy, "%s: Radio reset complete...\n",
			MWL_DRV_NAME);
	else
		wiphy_err(hw->wiphy, "%s: Unable to reset radio!!\n",
			MWL_DRV_NAME);

}

int mwl_add_card(void *card, struct mwl_if_ops *if_ops)
{
	struct ieee80211_hw *hw;
	struct mwl_priv *priv;
	int rc = 0;

	hw = ieee80211_alloc_hw(sizeof(*priv), &mwl_mac80211_ops);
	if (!hw) {
		pr_err("%s: ieee80211 alloc failed\n",
		       MWL_DRV_NAME);
		rc = -ENOMEM;
		goto err_alloc_hw;
	}

	priv = hw->priv;
	priv->hw = hw;

	priv->fw_device_pwrtbl = false;
	priv->intf = card;

	priv->is_rx_defer_schedule = false;
	priv->rx_defer_workq = alloc_workqueue("mwlwifi-rx_defer_workq",
		WQ_HIGHPRI | WQ_MEM_RECLAIM | WQ_UNBOUND, 1);
	INIT_WORK(&priv->rx_defer_work, mwl_rx_defered_handler);
	skb_queue_head_init(&priv->rx_defer_skb_q);

	/* Save interface specific operations in adapter */
	memmove(&priv->if_ops, if_ops, sizeof(struct mwl_if_ops));

	/* card specific initialization has been deferred until now .. */
	if (priv->if_ops.init_if)
		if (priv->if_ops.init_if(priv))
			goto err_init_if;

	/* hook regulatory domain change notification */
	hw->wiphy->reg_notifier = mwl_reg_notifier;
	hw->extra_tx_headroom = SYSADPT_TX_MIN_BYTES_HEADROOM;
	hw->queues = SYSADPT_TX_WMM_QUEUES;
	INIT_LIST_HEAD(&priv->sta_list);

	lrd_set_vendor_commands(hw->wiphy);

	priv->forbidden_setting = false;
	priv->regulatory_set = false;
	priv->disable_2g = false;
	priv->disable_5g = false;

	if (!SISO_mode)
		priv->ant_tx_bmp = if_ops->mwl_chip_tbl.antenna_tx;
	else
		priv->ant_tx_bmp = SISO_mode & MWL_8997_DEF_TX_ANT_BMP;
	priv->ant_tx_num = MWL_TXANT_BMP_TO_NUM(priv->ant_tx_bmp);

	if (!SISO_mode)
		priv->ant_rx_bmp = if_ops->mwl_chip_tbl.antenna_rx;
	else
		priv->ant_rx_bmp = SISO_mode & MWL_8997_DEF_RX_ANT_BMP;
	priv->ant_rx_num = MWL_RXANT_BMP_TO_NUM(priv->ant_rx_bmp);

	SET_IEEE80211_DEV(hw, priv->dev);

	rc = mwl_init_firmware(priv);

	if (rc) {
		wiphy_err(hw->wiphy, "%s: fail to initialize firmware\n",
			  MWL_DRV_NAME);
		goto err_init_firmware;
	}

	/* firmware is loaded to H/W, it can be released now */
	release_firmware(priv->fw_ucode);
	rc = mwl_wl_init(priv);
	if (rc) {
		wiphy_err(hw->wiphy, "%s: fail to initialize wireless lan\n",
			  MWL_DRV_NAME);
		goto err_wl_init;
	}

	wiphy_info(priv->hw->wiphy, "2G %s, 5G %s\n",
		   priv->disable_2g ? "disabled" : "enabled",
		   priv->disable_5g ? "disabled" : "enabled");

	wiphy_info(priv->hw->wiphy, "%d TX antennas, %d RX antennas\n",
		   priv->ant_tx_num, priv->ant_rx_num);

#ifdef CONFIG_DEBUG_FS
	mwl_debugfs_init(hw);
#endif

	return rc;

err_wl_init:
err_init_firmware:
	priv->if_ops.cleanup_if(priv);

err_init_if:
	ieee80211_free_hw(hw);

err_alloc_hw:

	return rc;
}
EXPORT_SYMBOL_GPL(mwl_add_card);

#ifdef CONFIG_PM
void lrd_report_wowlan_wakeup(struct mwl_priv *priv)
{
	int x = 0;
	struct ieee80211_vif *vif;
	struct ieee80211_hw *hw = priv->hw;
	struct cfg80211_wowlan_wakeup    wakeup;
	struct cfg80211_wowlan_nd_info  *nd_info  = NULL;
	struct cfg80211_wowlan_nd_match *nd_match = NULL;;

	memset(&wakeup, 0, sizeof(wakeup));
	wakeup.pattern_idx = -1;

	switch( priv->wow.results.reason) {
		case MWL_RX_EVENT_WOW_LINKLOSS_DETECT:
			wiphy_info(hw->wiphy, "WOW link loss detected\n");
			wakeup.disconnect = true;
		break;

		case MWL_RX_EVENT_WOW_AP_DETECT:
			nd_info = kzalloc(sizeof(struct cfg80211_wowlan_nd_info)    +
			                  sizeof(struct cfg80211_wowlan_nd_match *) +
			                  sizeof(struct cfg80211_wowlan_nd_match)   +
			                  sizeof(u32) * priv->wow.results.n_channels,
			                  GFP_KERNEL);

			wiphy_info(hw->wiphy, "WOW AP in range detected\n");

			/* Fill in nd_info */
			nd_info->n_matches = 1;
			nd_match =  (struct cfg80211_wowlan_nd_match*)((u8*)nd_info->matches + sizeof(struct cfg80211_wowlan_nd_info*));
			nd_info->matches[0] = nd_match;

			/* nd_match -> ssid*/
			nd_match->ssid.ssid_len = min(priv->wow.ssidList[0].ssidLen, (u8)sizeof(nd_match->ssid.ssid));
			memcpy(nd_match->ssid.ssid, priv->wow.ssidList[0].ssid, nd_match->ssid.ssid_len);

			/* nd_match->channels */
			nd_match->n_channels = priv->wow.results.n_channels;
			for (x = 0; x < nd_match->n_channels; x++) {
				nd_match->channels[x] = priv->wow.results.channels[x];
			}

			wakeup.net_detect = nd_info;
		break;

		case MWL_RX_EVENT_WOW_RX_DETECT:
			/* We are treating the packet as a flag, rather than data */
			wiphy_info(hw->wiphy, "WOW rx packet detected\n");
			wakeup.packet = (void*)true;
			wakeup.packet_80211 = true;
			wakeup.packet_present_len = 0;
		break;
	}

	vif = priv->wow.results.mwl_vif->vif;
	ieee80211_report_wowlan_wakeup(vif, &wakeup, GFP_KERNEL);

	if (nd_info) {
		kfree(nd_info);
	}
}
#endif

module_param(cal_data_cfg, charp, 0);
MODULE_PARM_DESC(cal_data_cfg, "Calibration data file name");

module_param(wmm_turbo, int, 0);
MODULE_PARM_DESC(wmm_turbo, "WMM Turbo mode 0:Disable 1:Enable");

module_param(EDMAC_Ctrl, int, 0);
MODULE_PARM_DESC(EDMAC_Ctrl, "EDMAC CFG: BIT0:2G_enbl, BIT1:5G_enbl, " \
                             "BIT[4:11]: 2G_Offset, BIT[12:19]:5G_offset, " \
                             "BIT[20:27]:Queue_lock, BIT[28]: MCBC_QLock, " \
                             "BIT[29]: BCN_DSBL");


module_param(tx_amsdu_enable, int, 0);
MODULE_PARM_DESC(tx_amsdu_enable, "Tx AMSDU enable/disable");

module_param(SISO_mode, uint, 0444);
MODULE_PARM_DESC(SISO_mode, "SISO mode 0:Disable 1:Ant0 2:Ant1");

module_param(lrd_debug, uint, 0644);
MODULE_PARM_DESC(lrd_debug, "Debug mode 0:Disable 1:Enable");

MODULE_DESCRIPTION(LRD_DESC);
MODULE_VERSION(LRD_DRV_VERSION);
MODULE_AUTHOR(LRD_AUTHOR);
MODULE_LICENSE("GPL v2");

