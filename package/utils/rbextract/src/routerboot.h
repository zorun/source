/*
 *  RouterBoot/RBextract definitions
 *
 *  Copyright (C) 2012 Gabor Juhos <juhosg@openwrt.org>
 *	Copyright (C) 2019 Robert Marko <robimarko@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify it
 *  under the terms of the GNU General Public License version 2 as published
 *  by the Free Software Foundation.
 */

#ifndef _RBEXTRACT_H
#define _RBEXTRACT_H

static inline uint32_t get_u32(const void *buf);

void *rb_get_wlan_data(void);

void *rb_get_ext_wlan_data(uint16_t id);

int routerboot_find_tag(uint8_t *buf, unsigned int buflen, uint16_t tag_id,
			uint8_t **tag_data, uint16_t *tag_len);

static inline int
rb_find_hard_cfg_tag(uint16_t tag_id, uint8_t **tag_data, uint16_t *tag_len);

const uint8_t * rb_get_board_product_code(void);

uint32_t rb_get_board_mac(void);

const uint8_t * rb_get_board_serial(void);

const uint8_t * rb_get_board_identifier(void);

const uint8_t * rb_get_board_name(void);

uint32_t rb_get_hw_options(void);

int routerboot_find_magic(uint8_t *buf, unsigned int buflen, uint32_t *offset, bool hard);

/*
 * Magic numbers
 */
#define RB_MAGIC_HARD	0x64726148 /* "Hard" */
#define RB_MAGIC_SOFT	0x74666F53 /* "Soft" */
#define RB_ART_SIZE 	0x10000
#define RB_MAGIC_ERD	0x00455244	/* extended radio data */
#define RB_MAGIC_LZOR	0x524F5A4C

#define RB_ID_TERMINATOR	0

/*
 * ID values for Hardware settings
 */
#define RB_ID_HARD_01		1
#define RB_ID_HARD_02		2
#define RB_ID_FLASH_INFO	3
#define RB_ID_MAC_ADDRESS_PACK	4
#define RB_ID_BOARD_PRODUCT_CODE	5
#define RB_ID_BIOS_VERSION	6
#define RB_ID_HARD_07		7
#define RB_ID_SDRAM_TIMINGS	8
#define RB_ID_DEVICE_TIMINGS	9
#define RB_ID_SOFTWARE_ID	10
#define RB_ID_SERIAL_NUMBER	11
#define RB_ID_HARD_12		12
#define RB_ID_MEMORY_SIZE	13
#define RB_ID_MAC_ADDRESS_COUNT	14
#define RB_ID_HW_OPTIONS	21
#define RB_ID_WLAN_DATA		22
#define RB_ID_BOARD_IDENTIFIER	23
#define RB_ID_BOARD_NAME	33

#endif /* _RBEXTRACT_H */
