#ifndef _MAIN_H_
#define _MAIN_H_

#define MWL_TXANT_BMP_TO_NUM(bmp)	\
(((bmp & MWL_8997_DEF_TX_ANT_BMP) == MWL_8997_DEF_TX_ANT_BMP)? 2 : 1)

#define MWL_RXANT_BMP_TO_NUM(bmp)	\
(((bmp & MWL_8997_DEF_RX_ANT_BMP) == MWL_8997_DEF_RX_ANT_BMP)? 2 : 1)


/* WMM Turbo mode */
extern int wmm_turbo;

extern int EDMAC_Ctrl;

int mwl_add_card(void *, struct mwl_if_ops *);
void mwl_wl_deinit(struct mwl_priv *);
void mwl_set_caps(struct mwl_priv *priv);
extern void timer_routine(unsigned long data);
extern void mwl_restart_ds_timer(struct mwl_priv *priv, bool force);
extern void mwl_delete_ds_timer(struct mwl_priv *priv);

#ifdef CONFIG_PM
extern void lrd_report_wowlan_wakeup(struct mwl_priv *priv);
#endif

void lrd_radio_recovery(struct mwl_priv *priv);
#endif
