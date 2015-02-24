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

#include "types.h"

#define SOSSE_COMMANDS_H

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
 *	@return 1 when the C-APDU matches the desired lengths else -1
 */
unsigned char command_verify_APDU_length ( str_command_APDU * command_APDU, unsigned char APDU_LC, unsigned char APDU_LE );


#endif /* SOSSE_COMMANDS_H */ 
