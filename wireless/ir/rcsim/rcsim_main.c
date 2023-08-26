/****************************************************************************
 * apps/wireless/ieee802154/i8shark/i8shark_main.c
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
#include <stdbool.h>
#include <sched.h>
#include <errno.h>

#include <nuttx/lirc.h>
#include <nuttx/input/buttons.h>
#include <nuttx/irq.h>
#include <nuttx/leds/userled.h>
#include <nuttx/power/relay.h>


/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/
#define CONFIG_BUTTONS_SIGNAL

#ifndef CONFIG_INPUT_BUTTONS
#  error "CONFIG_INPUT_BUTTONS is not defined in the configuration"
#endif

#ifndef CONFIG_INPUT_BUTTONS_NPOLLWAITERS
#  define CONFIG_INPUT_BUTTONS_NPOLLWAITERS 2
#endif

#ifndef CONFIG_BUTTONS_SIGNO
#  define CONFIG_BUTTONS_SIGNO 32
#endif

#ifndef CONFIG_INPUT_BUTTONS_POLL_DELAY
#  define CONFIG_INPUT_BUTTONS_POLL_DELAY 1000
#endif

#ifndef CONFIG_BUTTONS_NAME0
#  define CONFIG_BUTTONS_NAME0 "Human"
#endif

#ifndef CONFIG_BUTTONS_NAME1
#  define CONFIG_BUTTONS_NAME1 "BUTTON1"
#endif

#ifndef CONFIG_BUTTONS_NAME2
#  define CONFIG_BUTTONS_NAME2 "BUTTON2"
#endif

#ifndef CONFIG_BUTTONS_NAME3
#  define CONFIG_BUTTONS_NAME3 "BUTTON3"
#endif

#ifndef CONFIG_BUTTONS_NAME4
#  define CONFIG_BUTTONS_NAME4 "BUTTON4"
#endif

#ifndef CONFIG_BUTTONS_NAME5
#  define CONFIG_BUTTONS_NAME5 "BUTTON5"
#endif

#ifndef CONFIG_BUTTONS_NAME6
#  define CONFIG_BUTTONS_NAME6 "BUTTON6"
#endif

#ifndef CONFIG_BUTTONS_NAME7
#  define CONFIG_BUTTONS_NAME7 "BUTTON7"
#endif

#define BUTTON_MAX 8

#ifndef CONFIG_BUTTONS_QTD
#  define CONFIG_BUTTONS_QTD BUTTON_MAX
#endif

#if CONFIG_BUTTONS_QTD > 8
#  error "CONFIG_BUTTONS_QTD > 8"
#endif



/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/
#ifndef CONFIG_RCSIM_DAEMON_PRIORITY
#  define CONFIG_RCSIM_DAEMON_PRIORITY SCHED_PRIORITY_DEFAULT
#endif

#ifndef CONFIG_RCSIM_DAEMON_STACKSIZE
#  define CONFIG_RCSIM_DAEMON_STACKSIZE 2048
#endif



/****************************************************************************
 * Private Types
 ****************************************************************************/
#define  RC5HIGHSTATE     ((uint8_t )0x02)   /* RC5 high level definition*/
#define  RC5LOWSTATE      ((uint8_t )0x01)   /* RC5 low level definition*/

/**
  * @brief Definition of the RC5 Control bit value.
  */
typedef enum
{
  RC5_CTRL_RESET                        = ((uint16_t)0),
  RC5_CTRL_SET                          = ((uint16_t)0x0800)
}rc5_ctrl_t;

struct rc5_frame_s{
  uint32_t manchester_code;
  uint32_t idle[2];
};

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/
static uint16_t RC5_BinFrameGeneration(uint8_t RC5_Address, uint8_t RC5_Instruction, rc5_ctrl_t RC5_Ctrl);
static uint32_t RC5_ManchesterConvert(uint16_t RC5_BinaryFrameFormat);
static int ir_proc_main(void);
static int ir_proc_poll(void);


/****************************************************************************
 * Private Data
 ****************************************************************************/
static bool g_button_daemon_started;
#define CONFIG_PIR_DEVPATH   "/dev/buttons"
#define CONFIG_BUTTONS_NAMES

#ifdef CONFIG_BUTTONS_NAMES
static const char button_name[CONFIG_BUTTONS_QTD][16] =
{
  CONFIG_BUTTONS_NAME0
#if CONFIG_BUTTONS_QTD > 1
  , CONFIG_BUTTONS_NAME1
#endif
#if CONFIG_BUTTONS_QTD > 2
  , CONFIG_BUTTONS_NAME2
#endif
#if CONFIG_BUTTONS_QTD > 3
  , CONFIG_BUTTONS_NAME3
#endif
#if CONFIG_BUTTONS_QTD > 4
  , CONFIG_BUTTONS_NAME4
#endif
#if CONFIG_BUTTONS_QTD > 5
  , CONFIG_BUTTONS_NAME5
#endif
#if CONFIG_BUTTONS_QTD > 6
  , CONFIG_BUTTONS_NAME6
#endif
#if CONFIG_BUTTONS_QTD > 7
  , CONFIG_BUTTONS_NAME7
#endif
};
#endif



/****************************************************************************
 * Public Data
 ****************************************************************************/

/****************************************************************************
 * Private Functions
 ****************************************************************************/
/**
  * @brief Generate the binary format of the RC5 frame.
  * @param RC5_Address : Select the device address.
  * @param RC5_Instruction : Select the device instruction.
  * @param RC5_Ctrl : Select the device control bit status.
  * @retval Binary format of the RC5 Frame.
  */
static uint16_t RC5_BinFrameGeneration(uint8_t RC5_Address, uint8_t RC5_Instruction, rc5_ctrl_t RC5_Ctrl)
{
  uint16_t RC5BinaryFrameFormat = 0;
  uint16_t star1 = 0x2000;
  uint16_t star2 = 0x1000;
  uint16_t addr = 0;


  /* Check if Instruction is 128-bit length */
  if (RC5_Instruction >= 64)
  {
    /* Reset field bit: command is 7-bit length */
    star2 = 0;
    /* Keep the lowest 6 bits of the command */
    RC5_Instruction &= 0x003F;
  }
  else /* Instruction is 64-bit length */
  {
    /* Set field bit: command is 6-bit length */
    star2 = 0x1000;
  }

  RC5BinaryFrameFormat = 0;
  addr = ((uint16_t)(RC5_Address)) << 6;
  RC5BinaryFrameFormat =  (star1) | (star2) | (RC5_Ctrl) | (addr) | (RC5_Instruction);
  return (RC5BinaryFrameFormat);
}

/**
  * @brief Convert the RC5 frame from binary to Manchester Format.
  * @param RC5_BinaryFrameFormat : the RC5 frame in binary format.
  * @retval the RC5 frame in Manchester format.
  */
static uint32_t RC5_ManchesterConvert(uint16_t RC5_BinaryFrameFormat)
{
  uint8_t RC5RealFrameLength = 14;
  uint8_t i = 0;
  uint16_t Mask = 1;
  uint16_t bit_format = 0;
  uint32_t ConvertedMsg = 0;

  for (i = 0; i < RC5RealFrameLength; i++)
  {
    bit_format = ((((uint16_t)(RC5_BinaryFrameFormat)) >> i) & Mask) << i;
    ConvertedMsg = ConvertedMsg << 2;

    if (bit_format != 0 ) /* Manchester 1 -|_  */
    {
      ConvertedMsg |= RC5HIGHSTATE;
    }
    else /* Manchester 0 _|-  */
    {
      ConvertedMsg |= RC5LOWSTATE;
    }
  }
  return (ConvertedMsg);
}

/****************************************************************************
 * Name: button_daemon
 ****************************************************************************/

static int button_daemon(int argc, char *argv[])
{

#ifdef CONFIG_BUTTONS_SIGNAL
  struct btn_notify_s btnevents;
#endif

  btn_buttonset_t supported;
  btn_buttonset_t sample = 0;

#ifdef CONFIG_BUTTONS_NAMES
  btn_buttonset_t oldsample = 0;
#endif

  int ret;
  int fd;
  int i;

  UNUSED(i);

  /* Indicate that we are running */

  g_button_daemon_started = true;
  printf("button_daemon: Running\n");

  /* Open the BUTTON driver */

  printf("button_daemon: Opening %s\n", CONFIG_PIR_DEVPATH);
  fd = open(CONFIG_PIR_DEVPATH, O_RDONLY | O_NONBLOCK);
  if (fd < 0)
    {
      int errcode = errno;
      printf("button_daemon: ERROR: Failed to open %s: %d\n",
             CONFIG_PIR_DEVPATH, errcode);
      goto errout;
    }

  /* Get the set of BUTTONs supported */

  ret = ioctl(fd, BTNIOC_SUPPORTED,
              (unsigned long)((uintptr_t)&supported));
  if (ret < 0)
    {
      int errcode = errno;
      printf("button_daemon: ERROR: ioctl(BTNIOC_SUPPORTED) failed: %d\n",
             errcode);
      goto errout_with_fd;
    }

  printf("button_daemon: Supported BUTTONs 0x%02x\n",
         (unsigned int)supported);

#ifdef CONFIG_BUTTONS_SIGNAL
  /* Define the notifications events */

  btnevents.bn_press   = supported;
  btnevents.bn_release = supported;

  btnevents.bn_event.sigev_notify = SIGEV_SIGNAL;
  btnevents.bn_event.sigev_signo  = CONFIG_BUTTONS_SIGNO;

  /* Register to receive a signal when buttons are pressed/released */

  ret = ioctl(fd, BTNIOC_REGISTER,
              (unsigned long)((uintptr_t)&btnevents));
  if (ret < 0)
    {
      int errcode = errno;
      printf("button_daemon: ERROR: ioctl(BTNIOC_SUPPORTED) failed: %d\n",
             errcode);
      goto errout_with_fd;
    }

  /* Ignore the default signal action */

  signal(CONFIG_BUTTONS_SIGNO, SIG_IGN);
#endif

  /* Now loop forever, waiting BUTTONs events */

  for (; ; )
    {
#ifdef CONFIG_BUTTONS_SIGNAL
      struct siginfo value;
      sigset_t set;
#endif


#ifdef CONFIG_BUTTONS_SIGNAL
      /* Wait for a signal */

      sigemptyset(&set);
      sigaddset(&set, CONFIG_BUTTONS_SIGNO);
      ret = sigwaitinfo(&set, &value);
      if (ret < 0)
        {
          int errcode = errno;
          printf("button_daemon: ERROR: sigwaitinfo() failed: %d\n",
                 errcode);
          goto errout_with_fd;
        }

      sample = (btn_buttonset_t)value.si_value.sival_int;
#endif


#ifdef CONFIG_BUTTONS_NAMES
      /* Print name of all pressed/release button */

      for (i = 0; i < CONFIG_BUTTONS_QTD; i++)
        {
          if ((sample & (1 << i)) && !(oldsample & (1 << i)))
            {
              printf("%s detected\n", button_name[i]);
              // ir_proc_main();
              // ir_proc_poll();
            }

          if (!(sample & (1 << i)) && (oldsample & (1 << i)))
            {
              printf("%s disappear\n", button_name[i]);
            }
        }

      oldsample = sample;
#else
      printf("Sample = %jd\n", (intmax_t)sample);
#endif

      /* Make sure that everything is displayed */

      fflush(stdout);

      usleep(1000);
    }

errout_with_fd:
  close(fd);

errout:
  g_button_daemon_started = false;

  printf("button_daemon: Terminating\n");
  return EXIT_FAILURE;
}







/****************************************************************************
 * Name: rcsim_main
 ****************************************************************************/

static int ir_proc_main(void)
{
  int32_t ret = 0;
  char devname[18] = {0};
  uint32_t minor = 0;

  snprintf(devname, sizeof(devname), "/dev/lirc%u", (unsigned int)minor);

  /* Open lirc Driver */
  int fd = open(devname, O_RDWR);
  assert(fd >= 0);

  ret = ioctl(fd, LIRC_SET_SEND_MODE, LIRC_MODE_PULSE);
  if(ret < 0){
      printf("ioctl error: %ld\n", ret);
  }

#if 0
  struct rc5_frame_s ir_raw_data;

  memset(&ir_raw_data, 0, sizeof(struct rc5_frame_s));
  uint16_t sndCode = RC5_BinFrameGeneration(0x1, 0x5, RC5_CTRL_RESET);
  ir_raw_data.manchester_code = RC5_ManchesterConvert(sndCode);
  /* write ir command */
  int bytes_tx = write(fd, &ir_raw_data, sizeof(ir_raw_data));
  if(bytes_tx <= 0){
    printf("write error\n");
  }
  printf("write manchester_code: %08x\n", ir_raw_data.manchester_code);

#else
  uint32_t night_led_raw[5] = {
    0x00000fff, 0x0cccc330, 0x0c333333, 0xc30c3333, 0x004cc30c
  };
  /* write ir command */
  int bytes_tx = write(fd, &night_led_raw, sizeof(night_led_raw));
  if(bytes_tx <= 0){
    printf("write error\n");
  }
#endif
  /*  */
  close(fd);

  return OK;
}


static int ir_proc_poll(void)
{
  irqstate_t flags = 0;

  flags = enter_critical_section();


  leave_critical_section(flags);

  return 0;
}

int dump_sensors(void)
{
  int fd;
  int bytes_rd;
  uint8_t raw_data[16] = {0};


  printf("dump htu-21d \n");
  /* Open  Driver */
  fd = open("/dev/xht21", O_RDONLY);
  assert(fd >= 0);
  /* write ir command */
  bytes_rd = read(fd, raw_data, 16);
  if(bytes_rd <= 0){
    printf("read error\n");
  }
  printf("current Temp/RH : %s\n", raw_data);
  close(fd);


  printf("dump bh1750\n");
  uint16_t lux;
  /* Open  Driver */
  fd = open("/dev/bh1750", O_RDONLY);
  assert(fd >= 0);
  /* write ir command */
  bytes_rd = read(fd, &lux, 2);
  if(bytes_rd <= 0){
    printf("read error\n");
  }
  printf("current Lux : %d\n", lux);
  close(fd);

  return 0;
}

int light_leds(void)
{
  int fd;
  int bytes_rd;
  userled_set_t led_set = 0x0f;


  printf("light leds \n");
  /* Open  Driver */
  fd = open("/dev/userleds", O_WRONLY);
  assert(fd >= 0);
  /* write led value */
  bytes_rd = write(fd, &led_set, sizeof(userled_set_t));
  if(bytes_rd <= 0){
    printf("write error\n");
  }
  close(fd);

  return 0;
}

int operate_relay_io(bool value)
{
  int ret;
  int fd;
  int bytes_rd;
  bool setval = value;

  /* Open  Driver */
  fd = open("/dev/ac-10A", O_WRONLY);
  assert(fd >= 0);
  /* write relay  value */
  
  ret = ioctl(fd, RELAYIOC_SET, &setval);
  if(ret < 0){
      printf("ioctl error: %ld\n", ret);
  }
  close(fd);


  /* Open  Driver */
  fd = open("/dev/ac-16A", O_WRONLY);
  assert(fd >= 0);
  /* write relay  value */
  
  ret = ioctl(fd, RELAYIOC_SET, &setval);
  if(ret < 0){
      printf("ioctl error: %ld\n", ret);
  }
  close(fd);

  return 0;
}

/****************************************************************************
 * buttons_main
 ****************************************************************************/

int main(int argc, FAR char *argv[])
{
  int32_t ret = 0;
	int32_t chr;
	char opts[] =  "rsm:v:lh:cw:d"; //If a short parameter has a value, it is required to be followed by a colon ':'.
  char *popt, *endptr;
  int this_option_optind = optind ? optind : 1;
  int option_index = 0;
  static struct option long_options[] = {
      {"minor",     required_argument,    0,  'm'},
      {"read",      required_argument,    0,  'r'},
      {"write",     required_argument,    0,  'w'},
      {"cfg",       required_argument,    0,  'c'},
      {"value",     required_argument,    0,  'v'},
      {"len",       required_argument,    0,  'l'},
      {"ch",        required_argument,    0,  'h'},
      {"strobe",    required_argument,    0,  's'},
      {0,         0,                      0,   0 }
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
        case 'r':
            operate_relay_io(0);
            return 0;
        case 's':
            operate_relay_io(1);
            return 0;
        case 'd':
            dump_sensors();
            return;
        case 'l':
            light_leds();
            return 0;
		default:
            break;
		}
	}



  printf("buttons_main: Starting the button_daemon\n");
  if (g_button_daemon_started)
    {
      printf("buttons_main: button_daemon already running\n");
      return EXIT_SUCCESS;
    }

  ret = task_create("button_daemon", CONFIG_RCSIM_DAEMON_PRIORITY,
                    CONFIG_RCSIM_DAEMON_STACKSIZE, button_daemon,
                    NULL);
  if (ret < 0)
    {
      int errcode = errno;
      printf("buttons_main: ERROR: Failed to start button_daemon: %d\n",
             errcode);
      return EXIT_FAILURE;
    }

  printf("buttons_main: button_daemon started\n");
  return EXIT_SUCCESS;
}
