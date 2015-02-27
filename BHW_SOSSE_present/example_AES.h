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
 *  @file 	example_AES.h
 *	@brief 	@a Student implementation of the AES encryption algorithm
 */

#ifndef EXAMPLE_AES_H
#define EXAMPLE_AES_H

/**
 *	@brief	Call of the AES encryption algorithm
 *
 *	@param[in]	Pointer to the begining of the plaintext
 *	@param[out]	Pointer to the desired @a output ciphertext
 *	@param[in]	Pointer to the @a secret key
 *
 *	This algoritm must be implemented by the student.
 *
 */
void encrypt_aes_16(unsigned char *in, unsigned char *out, unsigned char *skey);

/* ... Add needed prototypes ... */
 
#endif
