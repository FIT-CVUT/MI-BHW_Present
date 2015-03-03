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

#include "crypt.h"
#include "types.h"
#include "example_C.h"
#include "example_ASM.h"
#include "example_AES.h"

/**	
 * SECRET KEY 
 */
static unsigned char key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
/**
 *	Input buffer for the C-APDU
 *	BUG FIX Myslivec, Novy 26.02.2015 #buffer_overflow 
 */
/* static unsigned char input[16]; */
static unsigned char input[INPUT_DATA_SIZE];
/**
 *	Output buffer for the R-APDU
 *	BUG FIX Myslivec, Novy 26.02.2015 #buffer_overflow 
 */
/* static unsigned char output[16]; */
static unsigned char output[OUTPUT_DATA_SIZE];


void crypt_c_encrypt_16 ( str_command_APDU * com_APDU, str_response_APDU * resp_APDU )
{
	crypt_block_prepare_input(com_APDU);
	encrypt_c_16(&input[0], &output[0], &key[0]);
	crypt_block_prepare_output(resp_APDU, 16);
}

void crypt_c_decrypt_16 ( str_command_APDU * com_APDU, str_response_APDU * resp_APDU )
{
	crypt_block_prepare_input(com_APDU);
	decrypt_c_16(&input[0], &output[0], &key[0]);
	crypt_block_prepare_output(resp_APDU, 16);
}

void crypt_asm_encrypt_16 ( str_command_APDU * com_APDU, str_response_APDU * resp_APDU )
{
	crypt_block_prepare_input(com_APDU);
	encrypt_asm_16(&input[0], &output[0], &key[0]);
	crypt_block_prepare_output(resp_APDU, 16);
}

void crypt_asm_decrypt_16 ( str_command_APDU * com_APDU, str_response_APDU * resp_APDU )
{
	crypt_block_prepare_input(com_APDU);
	decrypt_asm_16(&input[0], &output[0], &key[0]);
	crypt_block_prepare_output(resp_APDU, 16);
}

void crypt_aes_encrypt_16 ( str_command_APDU * com_APDU, str_response_APDU * resp_APDU )
{
	crypt_block_prepare_input(com_APDU);
	encrypt_aes_16(&input[0], &output[0], &key[0]);
	crypt_block_prepare_output(resp_APDU, 16);
}

void crypt_block_prepare_input ( str_command_APDU * com_APDU )
{
	unsigned char len;
/**
 *  BUG FIX Myslivec, Novy 26.02.2015 #LC_LE
 */
 	/* for (len=0; len<(*com_APDU).LE; len++) */
	for (len=0; len<(*com_APDU).LC; len++)
	{
		input[len] = (*com_APDU).data_field[len];
	}
}

void crypt_block_prepare_output ( str_response_APDU * resp_APDU, unsigned char length )
{
	unsigned char len;

	(*resp_APDU).LEN = length + 2; 
	(*resp_APDU).LE = length;
  	(*resp_APDU).SW1 = SW1_SUCCESS;  
  	(*resp_APDU).SW2 = SW2_SUCCESS;

	for (len=0; len<(*resp_APDU).LE; len++)
	{
		(*resp_APDU).data_field[len] = output[len];
	}
}
