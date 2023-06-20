/****************************************************************************
 * apps/wireless/ieee802154/i8sniffer/libpcapng.c
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libpcapng.h"

size_t pcapng_shb_append(FILE* fd, PCAPNG_SHB_HDR_t* shb, void* options)
{
	size_t bytes;
	// const char *os_desc = "nuttx";
	// const char *hardware_desc = "cc2520 mc";
	// const char *user_app_desc = "sniffer";
	// const char *file_comment = "local home";


	// light_pcapng_file_info * info = light_create_file_info(os_desc, hardware_desc, user_app_desc, file_comment);


	shb->block_Type 		= PCAPNG_SECTION_HEADER_BLOCK;
	shb->byteorder_magic 	= PCAPNG_BYTE_ORDER_MAGIC;
	shb->major_version 		= 1;
	shb->minor_version 		= 0;
	shb->section_length 	= 0xFFFFFFFFFFFFFFFF;
	shb->block_TotalLength 	= sizeof(PCAPNG_SHB_HDR_t) + sizeof(shb->block_TotalLength);

	bytes = write(fileno(fd), shb, sizeof(PCAPNG_SHB_HDR_t));

	bytes += write(fileno(fd), &shb->block_TotalLength, sizeof(shb->block_TotalLength));
	//printf("write SHB bytes %ld\n", bytes);


	return bytes;
}

size_t pcapng_idb_append(FILE* fd, PCAPNG_IDB_HDR_t* idb, void* options)
{
	size_t bytes;


	idb->block_Type = PCAPNG_INTERFACE_BLOCK;
	idb->link_Type = LINKTYPE_IEEE802_15_4_TAP;
	idb->snapLen = 256;
	idb->block_TotalLength = sizeof(PCAPNG_IDB_HDR_t) + sizeof(idb->block_TotalLength);

	bytes = write(fileno(fd), idb, sizeof(PCAPNG_IDB_HDR_t));


	bytes += write(fileno(fd), &idb->block_TotalLength, sizeof(idb->block_TotalLength));
	//printf("write IDB bytes %ld\n", bytes);


	return bytes;
}


size_t pcapng_epb_append(FILE* fd, PCAPNG_EPB_HDR_t* epb, uint8_t* pkt_data, uint16_t pkt_len, void* options)
{
	size_t bytes;


	epb->block_Type = PCAPNG_ENHANCED_PACKET_BLOCK;
	epb->interface_ID = 0;
	epb->timestamp = 0;
	epb->captured_PktLen = pkt_len;
	epb->original_PktLen = pkt_len;
	epb->block_TotalLength = sizeof(PCAPNG_EPB_HDR_t) + pkt_len + sizeof(epb->block_TotalLength);

	bytes = write(fileno(fd), epb, sizeof(PCAPNG_EPB_HDR_t));

	bytes += write(fileno(fd), pkt_data, pkt_len);

	bytes += write(fileno(fd), &epb->block_TotalLength, sizeof(epb->block_TotalLength));


	return bytes;
}


size_t pcapng_ieee802154_tap_epb_append(FILE* fd, PCAPNG_EPB_HDR_t* epb, uint8_t* pkt_data, uint16_t pkt_len, PCAPNG_IEEE_802154_TAP_META_t* meta)
{
	size_t bytes;
	uint32_t i = 0;
	PCAPNG_IEEE_802154_TAP_HDR_t *tap_hdr;
	PCAPNG_Option_t *pOpt;
	uint8_t *pbuf;

	pbuf = (uint8_t*)epb + sizeof(PCAPNG_EPB_HDR_t);
	tap_hdr = (PCAPNG_IEEE_802154_TAP_HDR_t*)&pbuf[0];
	tap_hdr->version = 0;
	tap_hdr->padding = 0;
	tap_hdr->length = sizeof(PCAPNG_IEEE_802154_TAP_HDR_t);
	i += tap_hdr->length;

	
	pOpt = (PCAPNG_Option_t*)&pbuf[i];
	pOpt->type = FCS_TYPE;
	pOpt->len = 1;
	*(uint32_t*)pOpt->value = meta->fcs_type;
	tap_hdr->length += sizeof(PCAPNG_Option_t) + 4;
	i += sizeof(PCAPNG_Option_t) + 4;

	pOpt = (PCAPNG_Option_t*)&pbuf[i];
	pOpt->type = RSS;
	pOpt->len = 4;
	*(uint32_t*)pOpt->value = meta->rss;
	tap_hdr->length += sizeof(PCAPNG_Option_t) + 4;
	i += sizeof(PCAPNG_Option_t) + 4;

	pOpt = (PCAPNG_Option_t*)&pbuf[i];
	pOpt->type = CHANNEL_ASSIGNMEN;
	pOpt->len = 3;
	*(uint32_t*)pOpt->value = meta->chl_assign;
	tap_hdr->length += sizeof(PCAPNG_Option_t) + 4;
	i += sizeof(PCAPNG_Option_t) + 4;

	pOpt = (PCAPNG_Option_t*)&pbuf[i];
	pOpt->type = EOF_TIMESTAMP;
	pOpt->len = 8;
	*(uint64_t*)pOpt->value = meta->eof_timestamp;
	tap_hdr->length += sizeof(PCAPNG_Option_t) + 8;
	i += sizeof(PCAPNG_Option_t) + 8;

	memcpy(&pbuf[i], pkt_data, pkt_len);
	i += pkt_len;
	uint32_t padding_bytes = 4 - pkt_len % 4;
	if(padding_bytes < 4){
		for(int j = 0; j < padding_bytes; j++){
			pbuf[i++] = 0;
		}
	}

	bytes = pcapng_epb_append(fd, (PCAPNG_EPB_HDR_t *)epb, (uint8_t*)pbuf, i, 0);

	//printf("chl %ld write EPB bytes %ld\n", meta->chl_assign, bytes);

	return bytes;
}
