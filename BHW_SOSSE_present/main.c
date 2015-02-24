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


/** 
 *	@file	main.c
 *
 *	@brief 	main() function with command loop.
 *
 *	This file contains the main command loop that receives and sends back 
 *	appropriate APDUs.
 *
 *	Supported instructions: @a (ins byte)
 *	-	0x40	encryption using the ASM example
 *	-	0x42	decryption using the ASM example
 *	-	0x50	encryption using the C example
 *	-	0x52	decryption using the C example
 *	-	0x60	encryption using the AES
 *
 *	Supported return codes:	@a (SW1 & SW2)
 *	-	0x9000	command executed successfuly
 *	-	0x6700	LRC error
 *	-	0x6800	instruction of the command not supported
 *	-	0x6a00	unexpected length of the command or of the expected response
 *	-	0x6e00	class of the command not supported
 *
 */

#include "commands.h"
#include "types.h"
#include "t1.h"

/**
 * 	struct for command APDU 
 */
str_command_APDU command_APDU;        	
/** 
 *	pointer to a command APDU 
 */
str_command_APDU *p_command_APDU;     	
/** 
 *	struct for response APDU 
 */
str_response_APDU response_APDU;       	
/** 
 *	pointer to a command APDU 
 */
str_response_APDU *p_response_APDU;


/** 
 *	@brief	Main function containing command interpreter loop.
 *
 *	The function uses 2 data-structures for the Command and Response APDU.
 *	All operations done with APDU uses allocated pointers to parse
 *	the input data, execute the command and send back the response APDU.
 *
 *	- Command and response APDUs are initialized/reset,
 *	- ATR is sent (answer-to-reset),
 *	- loop:
 *		- receive C-APDU,
 *		- execute the command,
 *		- send back R-APDU,
 *	- goto loop.
 *
 *	This function never returns.
 */ 

int main( void )
{
	unsigned char len, result;		

  	p_command_APDU = &command_APDU;
  	p_response_APDU = &response_APDU;

	/* Reset C-APDU and R-APDU */
    t1_reset_command_APDU (p_command_APDU);
	t1_reset_response_APDU (p_response_APDU);
	

	for (len = 0; len < 50; len++) {
  	}; /* wait before transmitting ATR (at least 400 cycles) */

	/* Send ATR */
	t1_transmit_ATR();

	/* infinite command loop */
	while(1) {
		/* receive C-APDU according to T=1 */
    	result = t1_receive_APDU (p_command_APDU);    

    	if (result != OK) {            /* check for EDC checksum error */
			(*p_response_APDU).NAD = command_APDU.NAD;
    		(*p_response_APDU).PCB = command_APDU.PCB;
    		(*p_response_APDU).LEN = 2;
    		(*p_response_APDU).LE = 0;
    		(*p_response_APDU).SW1 = 0x67;    /* checksum error */
    		(*p_response_APDU).SW2 = 0x00;
    	}
    	else {
			 /* Call command handler  */
      		command_handler (p_command_APDU, p_response_APDU);
    	}
	
		/* transmit R-APDU according to T=1 */
		t1_send_APDU (p_response_APDU);        

    	/* Reset C-APDU and R-APDU */
		t1_reset_command_APDU (p_command_APDU);
		t1_reset_response_APDU (p_response_APDU);
  	}
}
 
