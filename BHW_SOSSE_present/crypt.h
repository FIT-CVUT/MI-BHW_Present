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
 *  @file 	crypt.h
 *	@brief 	Declaration of the encryption/decryption functions
 * 
 *  This file contains the declaration of the encryption and decryption functions. 
 *	Each new encryption or decryption algorithm/method should have its declaration here.
 *	This file also defines methods for parcing the input data from the C-APDU and 
 *	setting the output data to the R-ADPU.
 */

#ifndef SOSSE_CRYPT_H
#define SOSSE_CRYPT_H

#include "types.h"

/** 
 *	@brief Calls the basic C-encryption algorithm
 *	
 *	@param[in]	Pointer to the @a input C-APDU containing the plaintext
 *	@param[out]	Pointer to the @a output R-APDU containing the ciphertext
 *
 *	This method parses the input/output data and calls the encryption algorithm.
 *	.
 */
void crypt_c_encrypt_16 ( str_command_APDU * com_APDU, str_response_APDU * resp_APDU );

/** 
 *	@brief Calls the basic C-decryption algorithm
 *	
 *	@param[in]	Pointer to the @a input C-APDU containing the ciphertext
 *	@param[out]	Pointer to the @a output R-APDU containing the plaintext
 *
 *	This method parses the input/output data and calls the decryption algorithm.
 *	.
 */
void crypt_c_decrypt_16 ( str_command_APDU * com_APDU, str_response_APDU * resp_APDU );

/** 
 *	@brief Calls the basic ASM-encryption algorithm
 *	
 *	@param[in]	Pointer to the @a input C-APDU containing the plaintext
 *	@param[out]	Pointer to the @a output R-APDU containing the ciphertext
 *
 *	This method parses the input/output data and calls the encryption algorithm.
 *	.
 */
void crypt_asm_encrypt_16 ( str_command_APDU * com_APDU, str_response_APDU * resp_APDU );

/** 
 *	@brief Calls the basic ASM-decryption algorithm
 *	
 *	@param[in]	Pointer to the @a input C-APDU containing the ciphertext
 *	@param[out]	Pointer to the @a output R-APDU containing the plaintext
 *
 *	This method parses the input/output data and calls the decryption algorithm.
 *	.
 */
void crypt_asm_decrypt_16 ( str_command_APDU * com_APDU, str_response_APDU * resp_APDU );

/** 
 *	@brief Calls the AES-encryption algorithm
 *	
 *	@param[in]	Pointer to the @a input C-APDU containing the plaintext
 *	@param[out]	Pointer to the @a output R-APDU containing the ciphertext
 *
 *	This method parses the input/output data and calls the AES encryption algorithm.
 *	.
 */
void crypt_aes_encrypt_16 ( str_command_APDU * com_APDU, str_response_APDU * resp_APDU );

/** 
 *	@brief Parses the data from the C-APDU
 *
 *	@param[in]	Pointer to the @a input C-APDU containing the desired data
 *	
 *	Extracts the data from the C-APDU.
 *	
 */
void crypt_block_prepare_input ( str_command_APDU * com_APDU );

/** 
 *  @brief Parse the data for the R-APDU
 *	.
 *	@param[out]	Pointer to the @a output R-APDU
 *
 *	Prepares the R-APDU data of the given length after
 *	successful operation. Adds the correct header 
 *	and adds the output data.
 */
void crypt_block_prepare_output ( str_response_APDU * resp_APDU, unsigned char length );

#endif
 
