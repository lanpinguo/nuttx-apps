/****************************************************************************
 * apps/wireless/ieee802154/i8sniffer/i8sniffer_main.c
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
#  define CONFIG_IEEE802154_I8SNIFFER_DAEMON_PRIORITY SCHED_PRIORITY_DEFAULT
#endif

#ifndef CONFIG_IEEE802154_I8SNIFFER_DAEMON_STACKSIZE
#  define CONFIG_IEEE802154_I8SNIFFER_DAEMON_STACKSIZE 2048
#endif

#ifndef CONFIG_IEEE802154_I8SNIFFER_CHANNEL
#  define CONFIG_IEEE802154_I8SNIFFER_CHANNEL 11
#endif

#ifndef CONFIG_IEEE802154_I8SNIFFER_FORWARDING_IFNAME
#  define CONFIG_IEEE802154_I8SNIFFER_FORWARDING_IFNAME "eth0"
#endif

#define i8sniffer_MAX_DEVPATH 15

#define ZEP_MAX_HDRSIZE 32
#define i8sniffer_MAX_ZEPFRAME IEEE802154_MAX_PHY_PACKET_SIZE + ZEP_MAX_HDRSIZE


#define DEV_PATH_PREFIX           "/dev/ieee"
/****************************************************************************
 * Private Types
 ****************************************************************************/
#define MAX_EVENTS    16
struct i8sniffer_state_s
{
  bool initialized      : 1;
  bool daemon_started   : 1;
  bool daemon_shutdown  : 1;

  pid_t daemon_pid;

  /* User exposed settings */

  FAR char devpath[i8sniffer_MAX_DEVPATH];

  FAR char data_file[32];

  FAR uint8_t dev_list[32];

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

/****************************************************************************
 * Public Data
 ****************************************************************************/

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: i8sniffer_init
 ****************************************************************************/

static int i8sniffer_init(FAR struct i8sniffer_state_s *i8sniffer)
{
  if (i8sniffer->initialized)
    {
      return OK;
    }

  /* Set the default settings using config options */

  strlcpy(i8sniffer->devpath, CONFIG_IEEE802154_I8SNIFFER_DEVPATH,
          sizeof(i8sniffer->devpath));

  strlcpy(i8sniffer->data_file, "/mnt/data.pcapng",
          sizeof(i8sniffer->data_file));

  /* Flags for synchronzing with daemon state */

  i8sniffer->daemon_started = false;
  i8sniffer->daemon_shutdown = false;
  i8sniffer->initialized = true;

  return OK;
}

/****************************************************************************
 * Name : i8sniffer_daemon
 *
 * Description :
 *   This daemon reads all incoming IEEE 802.15.4 frames from a MAC802154
 *   character driver, packages the frames into a Wireshark Zigbee
 *   Encapsulate Protocol (ZEP) packet and sends it over Ethernet to the
 *   specified host machine running Wireshark.
 *
 ****************************************************************************/

static int i8sniffer_daemon(int argc, FAR char *argv[])
{
  int ret;
  int fd;
	FILE* datafile = NULL;
  int epfd;
  struct epoll_event event;
  struct epoll_event *events;

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
              "ERROR: cannot open %s, errno=%d\n",
              g_i8sniffer.devpath, errno);
      g_i8sniffer.daemon_started = false;
      ret = errno;
      goto EXIT;
    }

  fd = open(g_i8sniffer.devpath, O_RDWR);
  if (fd < 0)
  {
    fprintf(stderr,
            "ERROR: cannot open %s, errno=%d\n",
            g_i8sniffer.devpath, errno);
    g_i8sniffer.daemon_started = false;
    ret = errno;
    goto EXIT;
  }
  event.events = EPOLLIN;
  event.data.fd = fd;
  ret = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event);
  if (ret < 0)
  {
    fprintf(stderr,
            "ERROR: cannot poll %d, errno=%d\n", fd, errno);
    g_i8sniffer.daemon_started = false;
    ret = errno;
    goto EXIT;
  }


  /* Place the MAC into promiscuous mode */

  ieee802154_setpromisc(fd, true);

  /* Always listen */

  ieee802154_setrxonidle(fd, true);

	uint8_t  *buf = calloc(1, 256);

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

  /* Loop until the daemon is shutdown reading incoming IEEE 802.15.4 frames,
   * packing them into Wireshark "Zigbee Encapsulation Packets" (ZEP)
   * and sending them over UDP to Wireshark.
   */

  while (!g_i8sniffer.daemon_shutdown) {

      struct mac802154dev_rxframe_s frame;
      PCAPNG_IEEE_802154_TAP_META_t meta;
      clock_t systime;
      int nr_events, i;

      nr_events = epoll_wait(epfd, events, MAX_EVENTS, 1000);

      for(i = 0; i < nr_events; i++){
        /* Get an incoming frame from the MAC character driver */
        lseek(events[i].data.fd, 0x100, SEEK_SET);
        ret = read(events[i].data.fd, &frame, sizeof(struct mac802154dev_rxframe_s));
        if (ret < 0)
        {
          continue;
        }

        meta.fcs_type = 0;
        meta.rss = 10;
        meta.chl_assign = (2<<16) | 17;
        systime = clock();
        /* write to sdcard */
        pcapng_ieee802154_tap_epb_append(datafile, (PCAPNG_EPB_HDR_t *)buf, frame.payload, frame.length, &meta);
        fsync(fileno(datafile));

      }

  }

EXIT:
  g_i8sniffer.daemon_started = false;
	free(buf);
	fclose(datafile);
  close(fd);
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
      /* If the first argument is an interface,
       * update our character device path
       */

      if (strncmp(argv[argind], "/dev/", 5) == 0)
        {
          /* Check if the name is the same as the current one */

          if (strcmp(g_i8sniffer.devpath, argv[argind]) != 0)
            {
              /* Adapter daemon can't be running when we change
               * device path
               */

              if (g_i8sniffer.daemon_started)
                {
                  printf("Can't change devpath when daemon is running.\n");
                  exit(1);
                }

              /* Copy the path into our state structure */

              strlcpy(g_i8sniffer.devpath, argv[1], sizeof(g_i8sniffer.devpath));
            }

          argind++;
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
