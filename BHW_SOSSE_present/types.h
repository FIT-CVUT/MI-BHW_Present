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
 *	Defined status words according to ISO
 *     ISO IEC 7816-4 (2005)
 *  BUG FIX Myslivec, Novy 26.02.2015 #return_types
 */
#define SW1_SUCCESS    0x90 /* Normal processing */
#define SW2_SUCCESS    0x00 /* No further qualification */

#define SW1_LRC        0x6a /* Wrong parameter(s) P1-P2 */
#define SW2_LRC        0x87 /* Lc inconsistent with P1-P2 */

#define SW1_PARAMETER_ERR   0x6a /* Wrong parameter(s) P1-P2 */
#define SW2_PARAMETER_ERR   0x80 /* Incorrect parameters in the command data field 1*/

#define SW1_EEPROM     0x62 /* State of non-volatile memory is unchanged */
#define SW2_EEPROM     0x86 /* No input data available from a sensor on the card */

#define SW1_CLASS_ERR  0x6e /* Class not supported */
#define SW2_CLASS_ERR  0x00

#define SW1_INSTR_ERR  0x6d /* Instruction code not supported or invalid */
#define SW2_INSTR_ERR  0x00

#define SW1_LENGTH_ERR 0x67 /* Wrong length */
#define SW2_LENGTH_ERR 0x00


#define SW1_UNDEFINED  0x42 /* This will never happen :) */
#define SW2_UNDEFINED  0x00
#define SW1_BUFFER_IN  0x66 /* Reserved for security-related issues */
#define SW2_BUFFER_IN  0x10 /* Insufficient memory for input data */
#define SW1_BUFFER_OUT 0x66 /* Reserved for security-related issues */
#define SW2_BUFFER_OUT 0x20 /* Insufficient memory for output data */

/**
 *  Size of header (and tail) for command APDU in bytes
 *	BUG FIX Myslivec, Novy 26.02.2015 #buffer_overflow 
 */
#define INPUT_HEADER_SIZE  9
/**
 *  Size of buffer for data in command APDU in bytes
 *	BUG FIX Myslivec, Novy 26.02.2015 #buffer_overflow 
 */
#define INPUT_DATA_SIZE   64

/**
 *	Maximum Bytes reserved in the input Buffer 
 *  BUG FIX Myslivec, Novy 26.02.2015 #buffer_overflow  
 */
/* #define INPUT_BUFFER_SIZE 70 */ 
#define INPUT_BUFFER_SIZE  INPUT_DATA_SIZE+INPUT_HEADER_SIZE

/**
 *  Size of buffer for data in response APDU in bytes
 *	BUG FIX Myslivec, Novy 26.02.2015 #buffer_overflow 
 */
#define OUTPUT_DATA_SIZE   32


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
  	unsigned char data_field[INPUT_DATA_SIZE];	        /**< Data Field*/
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
  	unsigned char data_field[OUTPUT_DATA_SIZE];	/**< Data Field*/
  	/*@}*/
}
str_response_APDU;


#endif /* TYPES_H */ 

