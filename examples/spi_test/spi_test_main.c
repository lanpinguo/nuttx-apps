/****************************************************************************
 * apps/examples/hello/hello_main.c
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

#include <nuttx/config.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <sys/ioctl.h>

/****************************************************************************
 * Public Functions
 ****************************************************************************/
typedef enum OPT_TYPE_S{
    OPT_TYPE_NONE   = 0,
    OPT_TYPE_RD,
    OPT_TYPE_WR,
    OPT_TYPE_CFG,
} OPT_TYPE_t;


typedef enum CC2520_CFG_E{
    CC2520_CFG_CHL = 1,
    CC2520_CFG_PROMIS,
    CC2520_CFG_STROBE,
}CC2520_CFG_e;

/****************************************************************************
 * test_main
 ****************************************************************************/
void
dump_buffer(const uint8_t *_p, int len)
{
	char buf[128];
	int i, j, i0;
	const unsigned char *p = (const unsigned char *)_p;

	/* hexdump routine */
	for (i = 0; i < len; ) {
		memset(buf, 128, ' ');
		sprintf(buf, "%5d: ", i);
		i0 = i;
		for (j=0; j < 16 && i < len; i++, j++)
			sprintf(buf+7+j*3, "%02x ", (uint8_t)(p[i]));
		i = i0;
		for (j=0; j < 16 && i < len; i++, j++)
			sprintf(buf+7+j + 48, "%c",
				isprint(p[i]) ? p[i] : '.');
		printf("%s\n", buf);
	}
	
	printf("\r\n");
}


int main(int argc, FAR char *argv[])
{
    int32_t ret = 0;
	int32_t chr;
	char opts[] =  "s:m:v:l:h:cr:w:"; //If a short parameter has a value, it is required to be followed by a colon ':'.
    char *popt, *endptr;
    int this_option_optind = optind ? optind : 1;
    int option_index = 0;
    static struct option long_options[] = {
        {"minor",  required_argument,  0,  'm'},
        {"read",  required_argument,  0,  'r'},
        {"write", required_argument,  0,  'w'},
        {"cfg", required_argument,  0,  'c'},
        {"value", required_argument,  0,  'v'},
        {"len", required_argument,  0,  'l'},
        {"ch", required_argument,  0,  'h'},
        {"strobe",  required_argument,  0,  's'},
        {0,         0,                0,   0 }
    };
    OPT_TYPE_t opt_type = OPT_TYPE_NONE;

    uint8_t pkt_data[128] = {
        0x01, 0x08, 0x01, 0x34, 0x12, 0x78, 0x56, 0x60, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x11, 0x40, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x15, 0x04, 0x71, 0x00, 0x1e, 0xa0, 0x47, 0x74, 0x68, 0x69, 0x73, 0x20, 0x61, 0x20, 0x63, 0x63,
        0x32, 0x35, 0x32, 0x30, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x70, 0x6b, 0x74,
    };  

    uint16_t minor = 0;
    uint16_t addr = 0;
    uint16_t len = 1;
    uint16_t chl = 0;
    uint8_t strobe = 0;
    char devname[18] = {0};




    optind = 0;
	while ((chr = getopt_long(argc, argv, opts, 
            long_options, &option_index)) != -1) {
		switch (chr) {
        case 0:
            printf("option %s", long_options[option_index].name);
            if (optarg)
                printf(" with arg %s", optarg);
            printf("\n");

            break;
        case 's':
            strobe = strtol(optarg, &endptr, 16);
			break;
        case 'm':
            minor = strtol(optarg, &endptr, 10);
			break;
        case 'r':
            opt_type = OPT_TYPE_RD;
            addr = strtol(optarg, &endptr, 16);
			break;
        case 'w':
            opt_type = OPT_TYPE_WR;
            addr = strtol(optarg, &endptr, 16);
			break;
        case 'c':
            opt_type = OPT_TYPE_CFG;
			break;
        case 'v':
			break;
        case 'l':
            len = strtol(optarg, &endptr, 10);
        case 'h':
            chl = strtol(optarg, &endptr, 16);
		default:
            break;
		}
	}

    snprintf(devname, sizeof(devname), "/dev/snif%u", (unsigned int)minor);

    if(opt_type == OPT_TYPE_WR){

        /* Open SPI Test Driver */
        int fd = open(devname, O_RDWR);
        assert(fd >= 0);

        lseek(fd, addr, SEEK_SET);

        /* Read response from SPI Test Driver */
        int bytes_tx = write(fd, pkt_data, len);
        if(bytes_tx > 0){
            printf("write to addr 0x%04x, len=%d\r\n", addr, bytes_tx);
            dump_buffer(pkt_data, bytes_tx);
        }
        else{
            printf("read error\n");
        }

        /* Close SPI Test Driver */
        close(fd);
    }


    if(opt_type == OPT_TYPE_RD){

        /* Open SPI Test Driver */
        int fd = open(devname, O_RDWR);
        assert(fd >= 0);

        lseek(fd, addr, SEEK_SET);
        memset(pkt_data, 0, 128);
        /* Read response from SPI Test Driver */
        int bytes_read = read(fd, pkt_data, len);
        if(bytes_read > 0){
            printf("dump from addr 0x%04x, len=%d\r\n", addr, bytes_read);
            dump_buffer(pkt_data, bytes_read);
        }
        else{
            printf("read error\n");
        }

        /* Close SPI Test Driver */
        close(fd);
    }


    if(opt_type == OPT_TYPE_CFG){

        /* Open SPI Test Driver */
        int fd = open(devname, O_RDWR);
        assert(fd >= 0);

        if(chl >= 11 && chl <=26){
            ret = ioctl(fd, CC2520_CFG_CHL, chl);
            if(ret < 0){
                printf("ioctl error: %ld\n", ret);
            }
        }

        if(strobe){
            ret = ioctl(fd, CC2520_CFG_STROBE, strobe);
            if(ret < 0){
                printf("ioctl error: %ld\n", ret);
            }
        }

        /* Close SPI Test Driver */
        close(fd);
    }


    return 0;  
}
