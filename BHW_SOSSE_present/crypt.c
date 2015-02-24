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
#include "example_PRESENT.h"

/**	
 * SECRET KEY 
 */
static unsigned char key[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11};
/**
 *	Input buffer for the C-APDU
 */
static unsigned char input[32];
/**
 *	Output buffer for the R-APDU
 */
static unsigned char output[16];


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

void crypt_present_encrypt_8 ( str_command_APDU * com_APDU, str_response_APDU * resp_APDU )
{
	crypt_block_prepare_input(com_APDU);
	encrypt_present_8( &input[0], &output[0], 0 );
	crypt_block_prepare_output(resp_APDU, 8);
}

void crypt_present_encrypt_8_key ( str_command_APDU * com_APDU, str_response_APDU * resp_APDU )
{
	crypt_block_prepare_input(com_APDU);
	encrypt_present_8( &input[0], &output[0], &(input[8]) );
	crypt_block_prepare_output(resp_APDU, 8);
}

void crypt_block_prepare_input ( str_command_APDU * com_APDU )
{
	unsigned char len;

	for (len=0; len<(*com_APDU).LE; len++)
	{
		input[len] = (*com_APDU).data_field[len];
	}
}

void crypt_block_prepare_output ( str_response_APDU * resp_APDU, unsigned char length )
{
	unsigned char len;

	(*resp_APDU).LEN = length + 2; 
	(*resp_APDU).LE = length;
  	(*resp_APDU).SW1 = 0x90;  
  	(*resp_APDU).SW2 = 0x00;

	for (len=0; len<(*resp_APDU).LE; len++)
	{
		(*resp_APDU).data_field[len] = output[len];
	}
}
