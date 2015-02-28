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

#include "commands.h"
#include "crypt.h"
#include "types.h"
#include "t1.h"

void command_handler (str_command_APDU * com_APDU, str_response_APDU * resp_APDU)
{
  (*resp_APDU).NAD = (*com_APDU).NAD;
  (*resp_APDU).PCB = (*com_APDU).PCB;

  if ((*com_APDU).PCB == 0xC1) {  /* S-Block Handling */

    (*resp_APDU).NAD = (*com_APDU).NAD;
    (*resp_APDU).PCB = 0xE1;
    (*resp_APDU).LEN = 1;
    (*resp_APDU).data_field[0] = (*com_APDU).CLA;
  }
  else {            /* I-Block Handling */

   switch ((*com_APDU).CLA) {	/* Determine the class of the command according to the CLA byte */
      case 0x80: {
         switch ((*com_APDU).INS) {	/* Determine the type of the instruction according to the INS byte*/
            case 0x40:	/* Call C-encryption example */
               if      ( command_verify_APDU_parameters( com_APDU, 0x00, 0x00 ) != OK ) {
                     t1_set_unexpected_parameters( resp_APDU );
               } 
               else if ( command_verify_APDU_length(     com_APDU, 0x10, 0x10 ) != OK ) {
                     t1_set_unexpected_length(resp_APDU);
               }
               else {
                     crypt_c_encrypt_16 (com_APDU, resp_APDU);
               }
               break;
            case 0x42:	/* Call C-decryption example */
               if      ( command_verify_APDU_parameters( com_APDU, 0x00, 0x00 ) != OK ) {
                     t1_set_unexpected_parameters( resp_APDU );
               } 
               else if ( command_verify_APDU_length(     com_APDU, 0x10, 0x10 ) != OK ) {
                     t1_set_unexpected_length(resp_APDU);
               }
               else {
                     crypt_c_decrypt_16 (com_APDU, resp_APDU);
               }
               break;
            case 0x50:	/* Call ASM-encryption */
               if      ( command_verify_APDU_parameters( com_APDU, 0x00, 0x00 ) != OK ) {
                     t1_set_unexpected_parameters( resp_APDU );
               } 
               else if ( command_verify_APDU_length(     com_APDU, 0x10, 0x10 ) != OK ) {
                     t1_set_unexpected_length(resp_APDU);
               }
               else {
                           crypt_asm_encrypt_16 (com_APDU, resp_APDU);
               }
               break;
            case 0x52:	/* Call ASM-decryption */
               if      ( command_verify_APDU_parameters( com_APDU, 0x00, 0x00 ) != OK ) {
                     t1_set_unexpected_parameters( resp_APDU );
               } 
               else if ( command_verify_APDU_length(     com_APDU, 0x10, 0x10 ) != OK ) {
                     t1_set_unexpected_length(resp_APDU);
               }
               else {
                     crypt_asm_decrypt_16 (com_APDU, resp_APDU);
               }
               break;
            case 0x60:	/* Call AES-encryption */
               if      ( command_verify_APDU_parameters( com_APDU, 0x00, 0x00 ) != OK ) {
                     t1_set_unexpected_parameters( resp_APDU );
               } 
               else if ( command_verify_APDU_length(     com_APDU, 0x10, 0x10 ) != OK ) {
                     t1_set_unexpected_length(resp_APDU);
               }
               else {
                     crypt_aes_encrypt_16 (com_APDU, resp_APDU);
               }
               break;
            default:
               t1_set_instruction_not_supported(resp_APDU);
               break;
         }
         break;
      }
      default: {
         t1_set_class_not_supported(resp_APDU);
         break;
      }
    }
  }
}

/**
 *	BUG FIX Myslivec, Novy 26.02.2015 #parameters_check
 */
unsigned char command_verify_APDU_parameters ( str_command_APDU * command_APDU, unsigned char APDU_P1, unsigned char APDU_P2 )
{
	if ( (*command_APDU).P1 == APDU_P1 && (*command_APDU).P2 == APDU_P2 )
	{
		return OK;
	}
	return ERROR;
}

unsigned char command_verify_APDU_length ( str_command_APDU * command_APDU, unsigned char APDU_LC, unsigned char APDU_LE )
{
	if ((*command_APDU).LC == APDU_LC && (*command_APDU).LE == APDU_LE)
	{
		return OK;
	}
	return ERROR;
}



