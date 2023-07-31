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

#include <nuttx/lirc.h>



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


/****************************************************************************
 * Private Data
 ****************************************************************************/


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
 * Name: rcsim_main
 ****************************************************************************/

int main(int argc, FAR char *argv[])
{
  int32_t ret = 0;
  uint32_t minor = 0;
  char devname[18] = {0};
	int32_t chr;
	char opts[] =  "s:m:v:l:h:cr:w:d"; //If a short parameter has a value, it is required to be followed by a colon ':'.
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
        case 's':
            break;
		default:
            break;
		}
	}



  snprintf(devname, sizeof(devname), "/dev/lirc%u", (unsigned int)minor);

  /* Open lirc Driver */
  int fd = open(devname, O_RDWR);
  assert(fd >= 0);

  ret = ioctl(fd, LIRC_SET_SEND_MODE, LIRC_MODE_PULSE);
  if(ret < 0){
      printf("ioctl error: %ld\n", ret);
  }


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

  /*  */
  close(fd);

  return OK;
}
