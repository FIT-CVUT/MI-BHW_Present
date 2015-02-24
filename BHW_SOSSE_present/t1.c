/*
	Simple Operating System for Smartcard Education
	Copyright (C) 2002  Matthias Bruestle <m@mbsks.franken.de>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
	This Project has been modified by Filip Stepanek <filip.stepanek@fit.cvut.cz>,
	FIT-CTU <www.fit.cvut.cz/en> for the purpose of smartcard education 
	using the SOSSE <http://www.mbsks.franken.de/sosse/html/index.html> 
	created by Matthias Bruestle and files 	from the Chair for Embedded Security (EMSEC), 
	Ruhr-University Bochum <http://www.emsec.rub.de/chair/home/>.
*/

/** @file	t1.c
 *
 *	@brief T=1 functions
 *
 */

#include "io.h"
#include "t1.h"
#include "types.h"

/**
 * 	@brief	Number of ATR bytes
 */
#define	ATR_SIZE				6
/**
 *	@brief	Number of ATR historical bytes
 */
#define ATR_HISTORICAL_SIZE		10

/**
 *	@brief	ATR definition
 */
const unsigned char ATR[ATR_SIZE] = { 0x3b, 0xba, 0x11, 0x00, 0x11, 0x81 };
/**
 *	@brief	ATR historical bytes definition
 */
const unsigned char ATR_HISTORICAL[ATR_HISTORICAL_SIZE] = { 0x2a, 0x46, 0x49, 0x54, 0x5f, 0x43, 0x56, 0x55, 0x54, 0x2a };

void t1_transmit_ATR( void )
{
  unsigned char pos, TCK;

  TCK = 0;

  /* calculate TCK */
  for (pos = 1; pos < ATR_SIZE; pos++) {
    TCK ^= ATR[pos];
  }
  for (pos = 0; pos < ATR_HISTORICAL_SIZE; pos++) {
    TCK ^= ATR_HISTORICAL[pos];
  }

  /* send ATR */
  for (pos = 0; pos < ATR_SIZE; pos++) {
    sendbytet0 (ATR[pos]);
  }
  for (pos = 0; pos < ATR_HISTORICAL_SIZE; pos++) {
    sendbytet0 (ATR_HISTORICAL[pos]);
  }

  sendbytet0 (TCK);

}
    
unsigned char t1_receive_APDU( str_command_APDU * command_APDU )
{
 /* init vars */
  unsigned char EDC, EDC_IN, NAD, PCB, LEN;
  int cnt;
  unsigned char APDU_buffer[INPUT_BUFFER_SIZE];

  EDC = 0;

  NAD = recbytet0 ();
  PCB = recbytet0 ();
  LEN = recbytet0 ();

  for (cnt = 0; cnt < LEN; cnt++) {
    APDU_buffer[cnt] = recbytet0 ();
  }
  EDC_IN = recbytet0 ();

  (*command_APDU).NAD = NAD;    /* Network address */
  EDC = EDC ^ NAD;
  (*command_APDU).PCB = PCB;    /* protocol byte */
  EDC = EDC ^ PCB;
  (*command_APDU).LEN = LEN;    /* length */
  EDC = EDC ^ LEN;

  for (cnt = 0; cnt < LEN; cnt++) {
    EDC = EDC ^ APDU_buffer[cnt];
  }

  /* extract APDU */
  (*command_APDU).CLA = APDU_buffer[0];
  (*command_APDU).INS = APDU_buffer[1];
  (*command_APDU).P1 = APDU_buffer[2];
  (*command_APDU).P2 = APDU_buffer[3];
  if ((*command_APDU).LEN == 5) {
    (*command_APDU).LE = APDU_buffer[4];    /* ISO7816 case 2 */
  }
  else if ((*command_APDU).LEN > 5) {
    (*command_APDU).LC = APDU_buffer[4];    /* ISO7816 case 3 or 4 */
    for (cnt = 0; cnt < (*command_APDU).LC; cnt++){
      (*command_APDU).data_field[cnt] = APDU_buffer[5 + cnt];
    }
    if ((*command_APDU).LEN > ((*command_APDU).LC + 5)){
      (*command_APDU).LE = APDU_buffer[(*command_APDU).LEN - 1];    /* ISO7816 case 4 */
    }
  }
  if (EDC != EDC_IN) {
    return ERROR;
  }
  else {
    return OK;
  }
}

void t1_send_APDU( str_response_APDU * response_APDU )
{
  /* init vars */
  unsigned char EDC, cnt;
  unsigned char APDU_buffer[INPUT_BUFFER_SIZE];


  /* process and transmit response APDU */
  if ((*response_APDU).PCB > 127) {    /* R- or S-Block */
    EDC = 0;
    APDU_buffer[0] = (*response_APDU).NAD;    /* Network address */
    EDC = EDC ^ (*response_APDU).NAD;
    APDU_buffer[1] = (*response_APDU).PCB;    /* protocol byte */
    EDC = EDC ^ (*response_APDU).PCB;
    APDU_buffer[2] = (*response_APDU).LEN;    /* length */
    EDC = EDC ^ (*response_APDU).LEN;
    APDU_buffer[3] = (*response_APDU).data_field[0];
    EDC = EDC ^ (*response_APDU).data_field[0];
    APDU_buffer[4] = EDC;
    for (cnt = 0; cnt < 5; cnt++) {
      sendbytet0 (APDU_buffer[cnt]);
    }

  }
  else {                        /* I-Block */

    EDC = 0;
    APDU_buffer[0] = (*response_APDU).NAD;    /* Network address */
    EDC = EDC ^ (*response_APDU).NAD;
    APDU_buffer[1] = (*response_APDU).PCB;    /* protocol byte */
    EDC = EDC ^ (*response_APDU).PCB;
    APDU_buffer[2] = (*response_APDU).LEN;    /* length */
    EDC = EDC ^ (*response_APDU).LEN;

    for (cnt = 0; cnt < (*response_APDU).LE; cnt++) {
      APDU_buffer[3 + cnt] = (*response_APDU).data_field[cnt];
      EDC = EDC ^ (*response_APDU).data_field[cnt];
    }
    APDU_buffer[3 + cnt] = (*response_APDU).SW1;    /* status word */
    EDC = EDC ^ (*response_APDU).SW1;
    APDU_buffer[4 + cnt] = (*response_APDU).SW2;
    EDC = EDC ^ (*response_APDU).SW2;
    APDU_buffer[5 + cnt] = EDC;

    for (cnt = 0; cnt < ((*response_APDU).LEN + 4); cnt++)
      sendbytet0 (APDU_buffer[cnt]);
  }
}

void t1_reset_command_APDU ( str_command_APDU * command_APDU )
{
	(*command_APDU).NAD = 0x00;
    (*command_APDU).PCB = 0x00;
    (*command_APDU).LEN = 0;
    (*command_APDU).LE = 0;
    (*command_APDU).LC = 0;
    (*command_APDU).CLA = 0x00;
    (*command_APDU).INS = 0x00;
}

void t1_reset_response_APDU ( str_response_APDU * response_APDU )
{
	(*response_APDU).NAD = 0x00;
    (*response_APDU).PCB = 0x00;
    (*response_APDU).LEN = 2;
    (*response_APDU).LE = 0;
    (*response_APDU).SW1 = 0x64;    /* error w/o changing EEPROM */
    (*response_APDU).SW2 = 0x00;
}

void t1_set_class_not_supported ( str_response_APDU * response_APDU )
{
	(*response_APDU).LEN = 2;
    (*response_APDU).LE = 0;
    (*response_APDU).SW1 = 0x6e;  /* class not supported */
    (*response_APDU).SW2 = 0x00;
}

void t1_set_instruction_not_supported ( str_response_APDU * response_APDU )
{
	(*response_APDU).LEN = 2;
    (*response_APDU).LE = 0;
    (*response_APDU).SW1 = 0x68;  /* instruction not supported */
    (*response_APDU).SW2 = 0x00;
}

void t1_set_unexpected_length ( str_response_APDU * response_APDU )
{
	(*response_APDU).LEN = 2;
    (*response_APDU).LE = 0;
    (*response_APDU).SW1 = 0x6a;  /* unexpected length */
    (*response_APDU).SW2 = 0x00;
}
 
