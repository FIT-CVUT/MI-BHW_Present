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
 *  @file 	example_C.h
 *	@brief 	@a Naive implementation of the NO-NAME encryption algorithm in C
 *
 *	The purpoase of this implementation is to show same basics in using the C programming 
 *	language in AVR Studio 4.
 */

#ifndef EXAMPLE_C_H
#define EXAMPLE_C_H

#include "types.h"

/**
 *	@brief	Calls the @a naive NO-NAME encryption algorithm implemented in C
 *
 *	@param[in]	Pointer to the begining of the plaintext
 *	@param[out]	Pointer to the desired @a output ciphertext
 *	@param[in]	Pointer to the @a secret key
 *
 */	
void encrypt_c_16( unsigned char * input, unsigned char * output, unsigned char * key );

/**
 *	@brief	Calls the @a naive NO-NAME decryption algorithm implemented in C
 *
 *	@param[in]	Pointer to the begining of the ciphertext
 *	@param[out]	Pointer to the desired @a output plaintext
 *	@param[in]	Pointer to the @a secret key
 *
 */
void decrypt_c_16( unsigned char * input, unsigned char * output, unsigned char * key );

#endif
 
