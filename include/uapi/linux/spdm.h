/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * DMTF Security Protocol and Data Model (SPDM)
 * https://www.dmtf.org/dsp/DSP0274
 *
 * Copyright (C) 2021-22 Huawei
 *     Jonathan Cameron <Jonathan.Cameron@huawei.com>
 *
 * Copyright (C) 2022-25 Intel Corporation
 */

#ifndef _UAPI_SPDM_H_
#define _UAPI_SPDM_H_

enum spdm_reqrsp_code {
	SPDM_DIGESTS			= 0x01,		/* 1.0 */
	SPDM_CERTIFICATE		= 0x02,		/* 1.0 */
	SPDM_CHALLENGE_AUTH		= 0x03,		/* 1.0 */
	SPDM_VERSION			= 0x04,		/* 1.0 */
	SPDM_CHUNK_SEND_ACK		= 0x05,		/* 1.2 */
	SPDM_CHUNK_RSP			= 0x06,		/* 1.2 */
	SPDM_ENDPOINT_INFO		= 0x07,		/* 1.3 */
	SPDM_SLOT_MANAGEMENT_RSP	= 0x08,		/* 1.4 */
	SPDM_MEASUREMENTS		= 0x60,		/* 1.0 */
	SPDM_CAPABILITIES		= 0x61,		/* 1.0 */
	SPDM_SUPPORTED_EVENTS		= 0x62,		/* 1.3 */
	SPDM_ALGORITHMS			= 0x63,		/* 1.0 */
	SPDM_KEY_EXCHANGE_RSP		= 0x64,		/* 1.1 */
	SPDM_FINISH_RSP			= 0x65,		/* 1.1 */
	SPDM_PSK_EXCHANGE_RSP		= 0x66,		/* 1.1 */
	SPDM_PSK_FINISH_RSP		= 0x67,		/* 1.1 */
	SPDM_HEARTBEAT_ACK		= 0x68,		/* 1.1 */
	SPDM_KEY_UPDATE_ACK		= 0x69,		/* 1.1 */
	SPDM_ENCAP_REQ			= 0x6a,		/* 1.1 */
	SPDM_ENCAP_RSP_ACK		= 0x6b,		/* 1.1 */
	SPDM_END_SESSION_ACK		= 0x6c,		/* 1.1 */
	SPDM_CSR			= 0x6d,		/* 1.2 */
	SPDM_SET_CERTIFICATE_RSP	= 0x6e,		/* 1.2 */
	SPDM_MEAS_EXT_LOG		= 0x6f,		/* 1.3 */
	SPDM_SUBSCRIBE_EVENTS_ACK	= 0x70,		/* 1.3 */
	SPDM_EVENT_ACK			= 0x71,		/* 1.3 */
	SPDM_KEY_PAIR_INFO		= 0x7c,		/* 1.3 */
	SPDM_SET_KEY_PAIR_INFO_ACK	= 0x7d,		/* 1.3 */
	SPDM_VENDOR_RSP			= 0x7e,		/* 1.0 */
	SPDM_ERROR			= 0x7f,		/* 1.0 */

	SPDM_REQ			= 0x80,

	SPDM_GET_DIGESTS		= 0x81,		/* 1.0 */
	SPDM_GET_CERTIFICATE		= 0x82,		/* 1.0 */
	SPDM_CHALLENGE			= 0x83,		/* 1.0 */
	SPDM_GET_VERSION		= 0x84,		/* 1.0 */
	SPDM_CHUNK_SEND			= 0x85,		/* 1.2 */
	SPDM_CHUNK_GET			= 0x86,		/* 1.2 */
	SPDM_GET_ENDPOINT_INFO		= 0x87,		/* 1.3 */
	SPDM_SLOT_MANAGEMENT		= 0x88,		/* 1.4 */
	SPDM_GET_MEASUREMENTS		= 0xe0,		/* 1.0 */
	SPDM_GET_CAPABILITIES		= 0xe1,		/* 1.0 */
	SPDM_GET_SUPP_EVENTS		= 0xe2,		/* 1.3 */
	SPDM_NEGOTIATE_ALGS		= 0xe3,		/* 1.0 */
	SPDM_KEY_EXCHANGE		= 0xe4,		/* 1.1 */
	SPDM_FINISH			= 0xe5,		/* 1.1 */
	SPDM_PSK_EXCHANGE		= 0xe6,		/* 1.1 */
	SPDM_PSK_FINISH			= 0xe7,		/* 1.1 */
	SPDM_HEARTBEAT			= 0xe8,		/* 1.1 */
	SPDM_KEY_UPDATE			= 0xe9,		/* 1.1 */
	SPDM_GET_ENCAP_REQ		= 0xea,		/* 1.1 */
	SPDM_DELIVER_ENCAP_RSP		= 0xeb,		/* 1.1 */
	SPDM_END_SESSION		= 0xec,		/* 1.1 */
	SPDM_GET_CSR			= 0xed,		/* 1.2 */
	SPDM_SET_CERTIFICATE		= 0xee,		/* 1.2 */
	SPDM_GET_MEAS_EXT_LOG		= 0xef,		/* 1.3 */
	SPDM_SUBSCRIBE_EVENTS		= 0xf0,		/* 1.3 */
	SPDM_SEND_EVENT			= 0xf1,		/* 1.3 */
	SPDM_GET_KEY_PAIR_INFO		= 0xfc,		/* 1.3 */
	SPDM_SET_KEY_PAIR_INFO		= 0xfd,		/* 1.3 */
	SPDM_VENDOR_REQ			= 0xfe,		/* 1.0 */
	SPDM_RESPOND_IF_READY		= 0xff,		/* 1.0 */
};

#endif /* _UAPI_SPDM_H_ */
