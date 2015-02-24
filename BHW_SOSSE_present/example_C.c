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

#include "example_C.h"
#include <avr/io.h>

/**
 *	set the trigger PIN
 */
#define set_pin(port, value) ((port)|=(value))
/**
 *	clear the trigger PIN
 */
#define clear_pin(port, value) ((port)&=(value))

void encrypt_c_16( unsigned char * input, unsigned char * output, unsigned char * key )
{
	unsigned char i;

	// set trigger PIN
	set_pin(DDRB, 0b10100000);
	set_pin(PORTB, 0b10100000);

	for (i=0; i<16; i++)
	{
		output[15-i]=input[i] ^ key[i];
	}

	// clear trigger PIN
	clear_pin(PORTB, 0b01011111);
}

void decrypt_c_16( unsigned char * input, unsigned char * output, unsigned char * key )
{
	unsigned char i;

	// set trigger PIN
	set_pin(DDRB, 0b10100000);
	set_pin(PORTB, 0b10100000);

	for (i=0; i<16; i++)
	{
		output[i]=input[15-i] ^ key[i];
	}

	// clear trigger PIN
	clear_pin(PORTB, 0b01011111);
}


 
