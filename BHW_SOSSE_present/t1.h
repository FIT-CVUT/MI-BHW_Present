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
 *	@file	t1.h
 *	@brief 	T=1 declarations.
 *
 *	T=1 is not implemented fully as library, but must be partly done in
 *	the commands itself. This reduces the RAM requirements. E.g. when
 *	doing an Update Binary the data must not be received in total before
 *	writing, but can be received and written in single bytes.
 *
 */

#ifndef SOSSE_T1_H
#define SOSSE_T1_H

#include "types.h"

/** 
 *	@brief	Transmits the ATR stored in T1.c
 */
void t1_transmit_ATR ( void );
    
/** 
 *	@brief	Processes incoming data corresponding to the T=1 protocol
 *
 *	@param[out]	command_APDU pointer to received command APDU 
 *	
 *	The function processes all incoming bytes expecting a correct T=1 transmission
 *	the received data is then passed on tho the main OS routine for further processing.
 *
 */
unsigned char t1_receive_APDU( str_command_APDU * command_APDU );

/** 
 *	@brief	Transmitting response APDUs corresponding to the T=1 protocol
 *
 *	@param[in] response_APDU pointer to response APDU to be transmitted
 *
 *	The function transmits a finished response APDU corresponding to the T=1 protocol.
 *
 */
void t1_send_APDU ( str_response_APDU * response_APDU );

/**
 *	@brief	Resets the content of the C-APDU
 *
 *	@param[out]	Pointer to the command_APDU structure
 *
 */
void t1_reset_command_APDU ( str_command_APDU * command_APDU );

/**
 *	@brief	Resets the content of the R-APDU
 *
 *	@param[out]	Pointer to the response_APDU structure
 *
 */
void t1_reset_response_APDU ( str_response_APDU * response_APDU );

/**
 *	@brief	Sets the class not supported error response into the R-APDU
 *
 *	@param[out]	Pointer to the response_APDU structure
 *
 */
void t1_set_class_not_supported ( str_response_APDU * response_APDU );

/**
 *	@brief	Sets the instruction not supported error response into the R-APDU
 *
 *	@param[out]	Pointer to the response_APDU structure
 *
 */void t1_set_instruction_not_supported ( str_response_APDU * response_APDU );

/**
 *	@brief	Sets the unexpected length error response into the R-APDU
 *
 *	@param[out]	Pointer to the response_APDU structure
 *
 */
void t1_set_unexpected_length ( str_response_APDU * response_APDU );

#endif /* SOSSE_T1_H */ 
