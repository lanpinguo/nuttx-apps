// light_special.h
// Created on: Jul 23, 2016

// Copyright (c) 2016 Radu Velea

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef LIBPCAPNG_H_
#define LIBPCAPNG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define PCAPNG_SECTION_HEADER_BLOCK  		0x0A0D0D0A
#define PCAPNG_INTERFACE_BLOCK       		0x00000001
#define PCAPNG_ENHANCED_PACKET_BLOCK 		0x00000006
#define PCAPNG_SIMPLE_PACKET_BLOCK   		0x00000003

#define PCAPNG_CUSTOM_DATA_BLOCK     		0xB16B00B5
#define PCAPNG_UNKNOWN_DATA_BLOCK    		0xDEADBEEF

// "Official" option codes
#define PCAPNG_OPTION_IF_TSRESOL            0x0009
#define PCAPNG_OPTION_COMMENT               0x0001
#define PCAPNG_OPTION_SHB_HARDWARE          0x0002
#define PCAPNG_OPTION_SHB_OS                0x0003
#define PCAPNG_OPTION_SHB_USERAPPL          0x0004
#define PCAPNG_OPTION_IF_TSRESOL            0x0009

// Custom option codes
#define PCAPNG_CUSTOM_OPTION_ADDRESS_INFO   0xADD4
#define PCAPNG_CUSTOM_OPTION_FEATURE_U64    0x0064

#define PCAPNG_BYTE_ORDER_MAGIC            	0x1A2B3C4D

#define PCAPNG_KEY_REJECTED          		0xFFFFFFFF


#define LINKTYPE_IEEE802_15_4_TAP			283


typedef struct PCAPNG_SHB_HDR_s
{
	uint32_t block_Type;
	uint32_t block_TotalLength;
	uint32_t byteorder_magic;
	uint16_t major_version;
	uint16_t minor_version;
	uint64_t section_length;

}__attribute__((packed, aligned(1))) PCAPNG_SHB_HDR_t;


typedef struct PCAPNG_IDB_HDR_s
{
	uint32_t block_Type;
	uint32_t block_TotalLength;
	uint16_t link_Type;
	uint16_t reserved;
	uint64_t snapLen;

}__attribute__((packed, aligned(1))) PCAPNG_IDB_HDR_t;

typedef struct PCAPNG_EPB_HDR_s
{
	uint32_t block_Type;
	uint32_t block_TotalLength;
	uint32_t interface_ID;
	uint64_t timestamp;
	uint32_t captured_PktLen;
	uint32_t original_PktLen;

}__attribute__((packed, aligned(1))) PCAPNG_EPB_HDR_t ;

typedef struct PCAPNG_SPB_HDR_s
{
	uint32_t block_Type;
	uint32_t block_TotalLength;
	uint32_t original_PktLen;

}__attribute__((packed, aligned(1))) PCAPNG_SPB_HDR_t;

enum TAP_TLV_TYPE_e{
	FCS_TYPE = 0,
	RSS,
	BIT_RATE,
	CHANNEL_ASSIGNMEN,
	PHY_ENCODING,
	SOF_TIMESTAMP,
	EOF_TIMESTAMP,
	ASN,
	SLOT_TIMESTAMP,
	TIMESLOT_LENGTH, 
};

typedef struct PCAPNG_Option_s
{
	uint16_t type;
	uint16_t len;
	uint8_t value[0]; 

}__attribute__((packed, aligned(1))) PCAPNG_Option_t;

typedef struct PCAPNG_IEEE_802154_TAP_HDR_s
{
	uint8_t version;
	uint8_t padding;
	uint16_t length; 

}__attribute__((packed, aligned(1))) PCAPNG_IEEE_802154_TAP_HDR_t;

typedef struct PCAPNG_IEEE_802154_TAP_META_s
{
	uint32_t fcs_type;
	uint32_t rss;
	uint32_t bitrate;
	uint32_t chl_assign; 
	uint64_t sof_timestamp; 
	uint64_t eof_timestamp; 

}__attribute__((packed, aligned(1))) PCAPNG_IEEE_802154_TAP_META_t;


size_t pcapng_shb_append(FILE* fd, PCAPNG_SHB_HDR_t* shb, void* options);

size_t pcapng_idb_append(FILE* fd, PCAPNG_IDB_HDR_t* idb, void* options);

size_t pcapng_epb_append(FILE* fd, PCAPNG_EPB_HDR_t* epb, uint8_t* pkt_data, uint16_t pkt_len, void* options);

size_t pcapng_ieee802154_tap_epb_append(FILE* fd, PCAPNG_EPB_HDR_t* epb, uint8_t* pkt_data, uint16_t pkt_len, PCAPNG_IEEE_802154_TAP_META_t* meta);

#ifdef __cplusplus
}
#endif

#endif /* LIBPCAPNG_H_ */
