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
 *  @file 	commands.h
 *	@brief 	Command declarations
 * 
 *  The file contains declaration of the command functions.
 */
#ifndef SOSSE_COMMANDS_H
#define SOSSE_COMMANDS_H

#include "types.h"

/**
 *  constant ERROR and OK is used only in commands.c, moved from types.h here
 *  redefined to 1 resp. 0 because of using unsigned chars!
 *
 *	BUG FIX Myslivec, Novy 26.02.2015 #return_types 
 */
/** 
 *	@brief	Return code 
 */
#define OK     0
/** 
 *	@brief	Return code 
 */            
#define ERROR  1


/** 
 * 	@brief 	Determine the executable command
 *
 *	@param[in] 	Pointer to the @a input C-APDU
 *	@param[out]	Pointer to the @a output R-APDU
 */
void command_handler ( str_command_APDU * com_APDU, str_response_APDU * resp_APDU ); 

/** 
 * 	@brief 	Determines the correct length of the command
 *	@param[in] 	Pointer to the @a input C-APDU
 *	@param[in] 	Desired LC of the C-APDU
 *	@param[in] 	Desired LE of the C-APDU
 *
 *	@return OK when the C-APDU matches the desired lengths else ERROR
 */
unsigned char command_verify_APDU_length ( str_command_APDU * command_APDU, unsigned char APDU_LC, unsigned char APDU_LE );

/** 
 * 	@brief 	Determines the correct parameters of the command
 *	@param[in] 	Pointer to the @a input C-APDU
 *	@param[in] 	Desired LC of the C-APDU
 *	@param[in] 	Desired LE of the C-APDU
 *
 *	@return OK ehen the C-APDU matches the desired parameters else ERROR
 */
unsigned char command_verify_APDU_parameters ( str_command_APDU * command_APDU, unsigned char APDU_P1, unsigned char APDU_P2 );

#endif /* SOSSE_COMMANDS_H */ 
