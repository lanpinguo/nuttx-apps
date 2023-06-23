/****************************************************************************
 * apps/wireless/ieee802154/i8sniffer/i8sniffer_main.c
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.    See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.    The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.    You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.    See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <debug.h>
#include <getopt.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <nuttx/fs/ioctl.h>
#include <nuttx/wireless/ieee802154/ieee802154_mac.h>
#include <nuttx/wireless/ieee802154/ieee802154_device.h>

#include "netutils/netlib.h"
#include "wireless/ieee802154.h"

#include "libpcapng.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/
#ifndef CONFIG_IEEE802154_I8SNIFFER_DAEMON_PRIORITY
#    define CONFIG_IEEE802154_I8SNIFFER_DAEMON_PRIORITY SCHED_PRIORITY_DEFAULT
#endif

#ifndef CONFIG_IEEE802154_I8SNIFFER_DAEMON_STACKSIZE
#    define CONFIG_IEEE802154_I8SNIFFER_DAEMON_STACKSIZE 2048
#endif

#ifndef CONFIG_IEEE802154_I8SNIFFER_CHANNEL
#    define CONFIG_IEEE802154_I8SNIFFER_CHANNEL 11
#endif

#ifndef CONFIG_IEEE802154_I8SNIFFER_FORWARDING_IFNAME
#    define CONFIG_IEEE802154_I8SNIFFER_FORWARDING_IFNAME "eth0"
#endif

#define i8sniffer_MAX_DEVPATH 15

#define ZEP_MAX_HDRSIZE 32
#define I8SNIFFER__MAX_ZEPFRAME IEEE802154_MAX_PHY_PACKET_SIZE + ZEP_MAX_HDRSIZE


#define DEV_PATH_PREFIX                     "/dev/ieee"
/****************************************************************************
 * Private Types
 ****************************************************************************/
#define MAX_EVENTS        16
#define MAX_CHANNEL       16

struct i8sniffer_state_s
{
    bool initialized        : 1;
    bool daemon_started     : 1;
    bool daemon_shutdown    : 1;

    pid_t daemon_pid;

    /* User exposed settings */
    FAR char data_file[32];

};


struct i8node_s
{
    int id;
    int chnl;
    int fd;
    int valid;
};


/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static int i8sniffer_init(FAR struct i8sniffer_state_s *i8sniffer);
static int i8sniffer_daemon(int argc, FAR char *argv[]);

/****************************************************************************
 * Private Data
 ****************************************************************************/

static struct i8sniffer_state_s g_i8sniffer;

struct i8node_s nodes[MAX_CHANNEL] = {0};

/****************************************************************************
 * Public Data
 ****************************************************************************/

/****************************************************************************
 * Private Functions
 ****************************************************************************/
static int get_list_from_str(uint8_t* str, int32_t* list)
{
    uint32_t i = 0;
    char * token;
    char *endptr;
    
    token = strtok(str, ",");
    // loop through the string to extract all other tokens
    while( token != NULL ) {
        //printf( " %s\n", token ); 
        list[i] = strtol(token, &endptr, 10);
        token = strtok(NULL, ",");
        i++;
        if(i > MAX_CHANNEL){
            return i - 1;
        }
    }

    return i;
}


/****************************************************************************
 * Name: i8sniffer_init
 ****************************************************************************/

static int i8sniffer_init(FAR struct i8sniffer_state_s *i8sniffer)
{
    FILE *cfg_fd;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    int32_t list[16] = {0};
    int32_t num;
    char * token;
      
       
    if (i8sniffer->initialized)
    {
        return OK;
    }

    cfg_fd = fopen("/mnt/sniffer.cfg","r");
    if (cfg_fd == NULL)
    {
        fprintf(stderr,
                "ERROR: cannot open %s, errno=%d\n",
                "sniffer.cfg", errno);
    }
    else{
        while ((nread = getline(&line, &len, cfg_fd)) != -1) {
            printf("Retrieved cfg line : %s \n", line);
            token = strtok(line, "=");
            if(strncmp("nodes", token, strlen(token)) == 0){
                token = strtok(NULL, "");
                num = get_list_from_str(token, list);
                for(int i = 0; i < num; i++){
                    nodes[i].id = list[i];
                    //nodes[i].valid = 1;
                }
            }
            else if(strncmp("channels", token, strlen(token)) == 0){
                token = strtok(NULL, "");
                num = get_list_from_str(token, list);
                for(int i = 0; i < num; i++){
                    nodes[i].chnl = list[i];
                    nodes[i].valid = 1;
                }
            }
        }

        fclose(cfg_fd);
    }

    /* Set the default settings using config options */

    strlcpy(i8sniffer->data_file, "/mnt/data.pcapng",
                    sizeof(i8sniffer->data_file));

    /* Flags for synchronzing with daemon state */

    i8sniffer->daemon_started = false;
    i8sniffer->daemon_shutdown = false;
    i8sniffer->initialized = true;

    return OK;
}


static int i8sniffer_sendto( 
        int sockfd, 
        struct sockaddr * raddr,
        int addrlen,
        struct i8node_s *pNode,
        struct mac802154dev_rxframe_s *frame)
{
    enum ieee802154_frametype_e ftype;
    clock_t systime;
    int i = 0;
    int nbytes;

    uint8_t zepframe[I8SNIFFER__MAX_ZEPFRAME];
    /* First 2 bytes of packet represent preamble. For ZEP, "EX" */

    zepframe[i++] = 'E';
    zepframe[i++] = 'X';

    /* The next byte is the version. We are using V2 */

    zepframe[i++] = 2;


        /* Next byte is type. ZEP only differentiates between ACK and Data. My
    * assumption is that Data also includes MAC command frames and beacon
    * frames. So we really only need to check if it's an ACK or not.
    */

    ftype = ((*(uint16_t *)frame->payload) & IEEE802154_FRAMECTRL_FTYPE) >>
            IEEE802154_FRAMECTRL_SHIFT_FTYPE;

    if (ftype == IEEE802154_FRAME_ACK)
    {
        zepframe[i++] = 2;

        /* Not sure why, but the ZEP header allows for a 4-byte sequence
        * no. despite 802.15.4 sequence number only being 1-byte
        */

        zepframe[i] = frame->meta.dsn;
        i += 4;
    }
    else
    {
        zepframe[i++] = 1;

        /* Next bytes is the Channel ID */
        zepframe[i++] = pNode->chnl & 0xFF;

        /* For now, just hard code the device ID to an arbitrary value */

        zepframe[i++] = 0xfa;
        zepframe[i++] = 0xde;

        /* Not completely sure what LQI mode is. My best guess as of now
        * based on a few comments in the Wireshark code is that it
        * determines whether the last 2 bytes of the frame portion of the
        * packet is the CRC or the LQI.
        * I believe it is CRC = 1, LQI = 0. We will assume the CRC is the
        * last few bytes as that is what the MAC layer expects.
        * However, this may be a bad assumption for certain radios.
        */

        zepframe[i++] = 1;

        /* Next byte is the LQI value */

        zepframe[i++] = frame->meta.lqi;

        /* Need to use NTP to get time, but for now,
        * include the system time
        */

        systime = clock();
        memcpy(&zepframe[i], &systime, 8);
        i += 8;

        /* Not sure why, but the ZEP header allows for a 4-byte sequence
        * no. despite 802.15.4 sequence number only being 1-byte
        */

        zepframe[i]   = frame->meta.dsn;
        zepframe[i + 1] = 0;
        zepframe[i + 2] = 0;
        zepframe[i + 3] = 0;
        i += 4;

        /* Skip 10-bytes for reserved fields */

        i += 10;

        /* Last byte is the length */

#ifdef CONFIG_IEEE802154_I8SHARK_XBEE_APPHDR
        zepframe[i++] = frame->length - 2;
#else
        zepframe[i++] = frame->length;
#endif
    }

      /* The ZEP header is filled, now copy the frame in */

#ifdef CONFIG_IEEE802154_I8SHARK_XBEE_APPHDR
      memcpy(&zepframe[i], frame.payload, frame.offset);
      i += frame.offset;

      /* XBee radios use a 2 byte "application header" to support duplicate
       * packet detection.  Wireshark doesn't know how to handle this data,
       * so we provide a configuration option that drops the first 2 bytes
       * of the payload portion of the frame for all sniffed frames
       *
       * NOTE:
       * Since we remove data from the frame, the FCS is no longer valid
       * and Wireshark will fail to disect the frame.  Wireshark ignores a
       * case where the FCS is not included in the actual frame.  Therefore,
       * we subtract 4 rather than 2 to remove the FCS field so that the
       * disector will not fail.
       */

      memcpy(&zepframe[i], (frame.payload + frame.offset + 2),
             (frame.length - frame.offset - 2));
      i += frame.length - frame.offset - 4;
#else
      /* If FCS suppression is enabled, subtract the FCS length to reduce the
       * piece of the frame copied.
       */

#ifdef CONFIG_IEEE802154_I8SHARK_SUPPRESS_FCS
    {
        uint8_t fcslen;
        ieee802154_getfcslen(fd, &fcslen);
        frame.length -= fcslen;
    }
#endif

      memcpy(&zepframe[i], frame->payload, frame->length);
      i += frame->length;
#endif

      /* Send the encapsulated frame to Wireshark over UDP */

    nbytes = sendto(sockfd, zepframe, i, 0,
                    raddr, addrlen);
    if (nbytes < i)
    {
        fprintf(stderr,
                "ERROR: sendto() did not send all bytes. %d\n", errno);
    }

    return nbytes;
}

/****************************************************************************
 * Name : i8sniffer_daemon
 *
 * Description :
 *     This daemon reads all incoming IEEE 802.15.4 frames from a MAC802154
 *     character driver, packages the frames into a Wireshark Zigbee
 *     Encapsulate Protocol (ZEP) packet and sends it over Ethernet to the
 *     specified host machine running Wireshark.
 *
 ****************************************************************************/

static int i8sniffer_daemon(int argc, FAR char *argv[])
{
    int ret;
        FILE* datafile = NULL;
    int epfd;
    struct epoll_event event;
    struct epoll_event *events;
    struct i8node_s *pNode = NULL;

    struct sockaddr_in addr;
    struct sockaddr_in raddr;
    socklen_t addrlen;
    int sockfd;

    fprintf(stderr, "i8sniffer: daemon started\n");
    g_i8sniffer.daemon_started = true;

    events = calloc(MAX_EVENTS, sizeof(struct epoll_event));
    if(events == NULL){
        ret = errno;
        return ret;
    }

    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0)
        {
            fprintf(stderr,
                    "ERROR: cannot create epoll fd, errno=%d\n", errno);
            g_i8sniffer.daemon_started = false;
            ret = errno;
            goto EXIT;
        }

    for(int i = 0; i < 16 ; i++){
        pNode = &nodes[i];
        if(pNode->valid == 0){
            continue;
        }
        char devpath[i8sniffer_MAX_DEVPATH];
        sprintf(devpath, "%s%d", DEV_PATH_PREFIX, pNode->id);
        pNode->fd = open(devpath, O_RDWR | O_NONBLOCK);
        if (pNode->fd < 0)
        {
            fprintf(stderr,
                            "ERROR: cannot open %s, errno=%d\n",
                            devpath, errno);
            g_i8sniffer.daemon_started = false;
            ret = errno;
            goto EXIT;
        }
        event.events = EPOLLIN;
        event.data.ptr = pNode;
        ret = epoll_ctl(epfd, EPOLL_CTL_ADD, pNode->fd, &event);
        if (ret < 0)
        {
            fprintf(stderr,
                            "ERROR: cannot poll %d, errno=%d\n", pNode->fd, errno);
            g_i8sniffer.daemon_started = false;
            ret = errno;
            goto EXIT;
        }

        ieee802154_setchan(pNode->fd, pNode->chnl);

        /* Place the MAC into promiscuous mode */
        ieee802154_setpromisc(pNode->fd, true);

        /* Always listen */
        ieee802154_setrxonidle(pNode->fd, true);
    
    }

        uint8_t    *buf = calloc(1, 256);

        datafile = fopen(g_i8sniffer.data_file, "wb");
    if (datafile == NULL)
    {
        printf("Error occurred in opening data file\n");
        goto EXIT;
    }

        pcapng_shb_append(datafile, (PCAPNG_SHB_HDR_t *)buf, 0);

    for(int i = 0 ; i < 16; i++){
        pcapng_idb_append(datafile, (PCAPNG_IDB_HDR_t *)buf, 0);
    }


    /* Create a UDP socket to send the data to Wireshark */

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        fprintf(stderr, "ERROR: socket failure %d\n", errno);
        return -1;
    }

    /* We bind to the IP address of the outbound interface so that
     * the OS knows which interface to use to send the packet.
     */

    netlib_get_ipv4addr("eth0",
                                            &addr.sin_addr);
    addr.sin_port     = 0;
    addr.sin_family = AF_INET;
    addrlen = sizeof(struct sockaddr_in);

    if (bind(sockfd, (FAR struct sockaddr *)&addr, addrlen) < 0)
        {
            fprintf(stderr, "ERROR: Bind failure: %d\n", errno);
            return -1;
        }

    /* Setup our remote address.
     * Wireshark expects ZEP packets over UDP on port 17754
     */

    raddr.sin_family            = AF_INET;
    raddr.sin_port                = HTONS(17754);
    raddr.sin_addr.s_addr = HTONL(0x0a000001);


    /* Loop until the daemon is shutdown reading incoming IEEE 802.15.4 frames,
     * packing them into Wireshark "Zigbee Encapsulation Packets" (ZEP)
     * and sending them over UDP to Wireshark.
     */

    while (!g_i8sniffer.daemon_shutdown) {

            struct mac802154dev_rxframe_s frame;
            PCAPNG_IEEE_802154_TAP_META_t meta;
            // clock_t systime;
            int nr_events, i;

            nr_events = epoll_wait(epfd, events, MAX_EVENTS, 1000);

            for(i = 0; i < nr_events; i++){
                /* Get an incoming frame from the MAC character driver */
                // lseek(events[i].data.fd, 0x100, SEEK_SET);
                while (1)
                {
                    pNode = (struct i8node_s *)events[i].data.ptr;
                    ret = read(pNode->fd, &frame, sizeof(struct mac802154dev_rxframe_s));
                    if (ret < 0)
                    {
                        break;
                    }

                    meta.fcs_type = 0;
                    meta.rss = frame.meta.lqi;
                    meta.chl_assign = (2<<16) | pNode->chnl;
                    meta.eof_timestamp = frame.meta.timestamp;
                    //systime = clock();
                    /* write to sdcard */
                    uint32_t bytes;
                    bytes = pcapng_ieee802154_tap_epb_append(
                                datafile, (PCAPNG_EPB_HDR_t *)buf, frame.payload, frame.length, &meta);
                    fsync(fileno(datafile));
                    printf("chl %d write EPB bytes %ld\n", pNode->chnl, bytes);

                    i8sniffer_sendto(sockfd, (struct sockaddr *)&raddr, addrlen, pNode, &frame);

                }
            }

    }

EXIT:
    g_i8sniffer.daemon_started = false;
        free(buf);
        fclose(datafile);
    for(int i = 0; i < 16 ; i++){
        pNode = &nodes[i];
        if(pNode->valid == 0){
            continue;
        }
        close(pNode->fd);
    }
    free(events);
    close(epfd);
    printf("i8sniffer: daemon closing\n");
    return OK;
}


/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: i8sniffer_main
 ****************************************************************************/

int main(int argc, FAR char *argv[])
{
    int argind = 1;

    if (!g_i8sniffer.initialized)
    {
        i8sniffer_init(&g_i8sniffer);
    }

    if (argc > 1)
    {
        int32_t chr;
        int32_t list[16] = {0};
        int32_t num;

        /* If a short parameter has a value, it is required to be followed by a colon ':'. */
        char opts[] =  "N:H:s"; 
        char *popt, *endptr;
        int this_option_optind = optind ? optind : 1;
        int option_index = 0;
        static struct option long_options[] = {
            {"chnl",  required_argument,  0,  'H'},
            {"node",  required_argument,  0,  'N'},
            {0,         0,                0,   0 }
        };

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
            case 'H':
                num = get_list_from_str(optarg, list);
                for(int i = 0; i < num; i++){
                    nodes[i].chnl = list[i];
                    nodes[i].valid = 1;
                }
                break;
            case 'N':
                num = get_list_from_str(optarg, list);
                for(int i = 0; i < num; i++){
                    nodes[i].id = list[i];
                }
                break;
            default:
                break;
            }
        }


    }

    /* If the daemon is not running, start it. */

    g_i8sniffer.daemon_pid = task_create("i8sniffer",
            CONFIG_IEEE802154_I8SNIFFER_DAEMON_PRIORITY,
            CONFIG_IEEE802154_I8SNIFFER_DAEMON_STACKSIZE,
            i8sniffer_daemon, NULL);
    if (g_i8sniffer.daemon_pid < 0)
    {
        fprintf(stderr, "failed to start daemon\n");
        return ERROR;
    }

    return OK;
}
