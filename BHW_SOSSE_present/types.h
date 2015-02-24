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
 *	@file	types.h 
 *	@brief 	Type declarations.
 *
 */

#ifndef TYPES_H
#define TYPES_H

/** 
 *	@brief	Return code 
 */
#define FALSE	0
/** 
 *	@brief	Return code 
 */
#define TRUE	!FALSE

/** 
 *	@brief	Return code 
 */
#define OK			1
/** 
 *	@brief	Return code 
 */            
#define ERROR       -1

/**
 *	Maximmum Bytes reserved in the input Buffer 
 */
#define INPUT_BUFFER_SIZE 70

// Boolean data type.
//typedef unsigned char bool;

/**
 *	Structure represents the @a (command) C-APDU 
 */
typedef struct
{
	/*@{*/
  	unsigned char NAD;									/**< Node Address*/
  	unsigned char PCB;									/**< Protocol Control Byte*/
  	unsigned char LEN;									/**< Length Field*/
  	unsigned char CLA;									/**< Class Byte*/
  	unsigned char INS;									/**< Instruction Byte*/
  	unsigned char P1;									/**< Parameter Byte 1*/
  	unsigned char P2;									/**< Parameter Byte 2*/
  	unsigned char LC;									/**< Length Command*/
  	unsigned char LE;									/**< Length Expected*/
  	unsigned char data_field[INPUT_BUFFER_SIZE - 9];	/**< Data Field*/
	/*@}*/
}
str_command_APDU;

/**
 *	Structure represents the @a (response) R-APDU 
 */
typedef struct
{
	/*@{*/
  	unsigned char NAD;				/**< Node Address*/
  	unsigned char PCB;				/**< Protocol Control Byte*/
  	unsigned char LEN;				/**< Length Field*/
  	unsigned char SW1;				/**< Status Word 1*/
  	unsigned char SW2;				/**< Status Word 2*/
  	unsigned char LE;				/**< Length Expected*/
  	unsigned char data_field[32];	/**< Data Field*/
  	/*@}*/
}
str_response_APDU;


#endif /* TYPES_H */ 
