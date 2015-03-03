/*
	This Project has been modified by Filip Stepanek <filip.stepanek@fit.cvut.cz>,
	FIT-CTU <www.fit.cvut.cz/en> for the purpose of smartcard education 
	using the SOSSE <http://www.mbsks.franken.de/sosse/html/index.html> 
	created by Matthias Bruestle and files 	from the Chair for Embedded Security (EMSEC), 
	Ruhr-University Bochum <http://www.emsec.rub.de/chair/home/>.
*/
/*
 *	Cipher PRESENT implemented by Vojtech Myslivec <vojtech.myslivec@fit.cvut.cz>
 *	and Zdenek Novy <novyzde3@fit.cvut.cz> at FIT CVUT v Praze <www.fit.cvut.cz/en>.
 *	Project live at https://github.com/FIT-CVUT/MI-BHW_Present
 *
 *	References
 *		[1]		A. Bogdanov, C. Paar et al. PRESENT: An Ultra-Lightweight Block Cipher
 * 				in Cryptographic Hardware and Embedded Systems - CHES 2007
 * 				(9th International Workshop, Vienna, Austria, September 10-13, 2007. Proceedings).
 * 				Berlin (Germany): Springer Berlin Heidelberg, 2007.
 * 				Avaiable at http://link.springer.com/chapter/10.1007%2F978-3-540-74735-2_31
 * 		[2] 	Dirk Klose. C PRESENT Implementation (8 Bit) in Implementations (lightweightcrypto.org).
 * 				Avaiable at http://www.lightweightcrypto.org/implementations.php
 */

#include "example_PRESENT.h"
#include <avr/io.h>

/**
 *	set the trigger PIN
 */
#define set_pin(port, value) ((port)|=(value))
/**
 *	clear the trigger PIN
 */
#define clear_pin(port, value) ((port)&=(value))

/*...*/
#define BITU_POCET    64
#define KLIC_VELIKOST 10 /* 80 bit / 8 bit */
#define BLOK_VELIKOST  8 /* 64 bit / 8 bit */
#define SBOX_VELIKOST 16 /* 2^4 substituci (po 4 bitech) */
#define RUND_POCET    31

/* sBox je 4-bitovy, nesmi presahnout 0x0F jinak neni chovani definovano */
static const unsigned char sBox[SBOX_VELIKOST] = { 0x0C, 0x05, 0x06, 0x0B, 0x09, 0x00, 0x0A, 0x0D, 0x03, 0x0E, 0x0F, 0x08, 0x04, 0x07, 0x01, 0x02 };
/* tajny klic */
static unsigned char vychoziKlic[KLIC_VELIKOST] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
/* 
static unsigned char vychoziKlic[KLIC_VELIKOST] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 };
static unsigned char vychoziKlic[KLIC_VELIKOST] = { 0x7f, 0xf2, 0x38, 0xa4, 0x45, 0x39, 0x0d, 0x4e, 0x72, 0x3e };
static unsigned char vychoziKlic[KLIC_VELIKOST] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
*/

void pridejRundovniKlic( unsigned char * zprava, unsigned char * klic ) {
   unsigned char i;
   for ( i = 0 ; i < BLOK_VELIKOST ; i++ ) {
      /* xor s rund. klicem */
      /* index u klice je +2 protoze se z 80-ti bitu pouziva 64 nejvyznamnejsich */
      /* melo by byt + KLIC_VELIKOST - BLOK_VELIKOST ... */
      zprava[i] = zprava[i] ^ klic[i + 2];
   }
}

void substitucniVrstva( unsigned char * zprava ) {
   unsigned char i;
   unsigned char nibble1, nibble2;
   for ( i = 0 ; i < BLOK_VELIKOST ; i++ ) {
      /* mene vyznamne 4 bity */
      nibble1 = 0x0F & zprava[i];
      /* vice vyznamne 4 bity */
      nibble2 = 0x0F & ( zprava[i] >> 4 );  /* maskovani neni potreba, ale ... */

      /* 4-bitove vystupy sBoxu */
      nibble1 = sBox[nibble1] & 0x0F;        /* maskovani neni potreba, ale ... */
      nibble2 = sBox[nibble2] & 0x0F;        /* maskovani neni potreba, ale ... */

      /* rekonstrukce puvodniho bajtu zpravy -- substituce bajtu */
      nibble2 = ( nibble2 << 4 ) & 0xF0;     /* maskovani neni potreba, ale ... */
      zprava[i] = nibble2 | nibble1;
   }
}

void permutacniVrstva( unsigned char * zprava ) {
   unsigned char zdrojPozice, zdrojIndex, zdrojOffset;
   unsigned char   cilPozice,   cilIndex,   cilOffset;
   unsigned char i, bit, permutace[BLOK_VELIKOST];
   for ( i = 0 ; i < BLOK_VELIKOST ; i++ ) {
      permutace[i] = 0;
   }

   /* cyklus pres vsechny bity zpravy */
   /* TODO pro prehlednost pocitam rovnou s cislem 63 misto s konstantou BITU_POCET - 1  */
   for ( zdrojPozice = 0 ; zdrojPozice < BITU_POCET ; zdrojPozice++ ) {
      if ( zdrojPozice == 63 ) /* vyjimka */
         cilPozice = 63;
      else {
         /* algebraicke vyjadreni permutacni vrstvy, inspirovano z [2] */
         /* schvalne vypocet na dvakrat, aby bylo zajisteno, ze se vejde do 8-bitu  */
         cilPozice = ( 4 * zdrojPozice ) % 63;
         cilPozice = ( 4 *   cilPozice ) % 63;
      }
      zdrojIndex  = zdrojPozice / 8;
      zdrojOffset = zdrojPozice % 8;
      cilIndex    =   cilPozice / 8;
      cilOffset   =   cilPozice % 8;

      bit = ( zprava[zdrojIndex] >> zdrojOffset ) & 0x01;
      bit = bit << cilOffset;
      permutace[cilIndex] |= bit;
   }

   /* nahrada zpravy permutaci */
   for ( i = 0 ; i < BLOK_VELIKOST ; i++ ) {
      zprava[i] = permutace[i];
   }
}

void generujRundovniKlic( unsigned char * klic, unsigned char runda ) {
   unsigned char i, bajt1, bajt2, cast1, cast2;
   /* 61-bitovy posun doleva (rol) ----------------------------------------- */
   /* jedna se vlastne o 19-bitovy posun doprava (ror) */
   
   /* nejdriv posun klice o dva bajty = 16 bitu*/
   bajt1 = klic[0];
   bajt2 = klic[1];
   for ( i = 0 ; i < KLIC_VELIKOST - 2 ; i++ ) {
      klic[i] = klic[i + 2];
   }
   klic[KLIC_VELIKOST - 2] = bajt1;
   klic[KLIC_VELIKOST - 1] = bajt2;
   
   /* posun klice o dalsi 3 bity */
   bajt1 = klic[0];
   for ( i = 0 ; i < KLIC_VELIKOST - 1 ; i++ ) {
      cast1 = (     klic[i] >> 3 ) & 0x1F;  /* maskovani neni potreba, ale ... */
      cast2 = ( klic[i + 1] << 5 ) & 0xE0;  /* maskovani neni potreba, ale ... */
      klic[i] = cast1 | cast2;
   }
   cast1 = ( klic[KLIC_VELIKOST - 1] >> 3 ) & 0x1F;  /* maskovani neni potreba, ale ... */
   cast2 = (                   bajt1 << 5 ) & 0xE0;  /* maskovani neni potreba, ale ... */
   klic[KLIC_VELIKOST - 1] = cast1 | cast2;

   /* sBox substituce nejvyznamnejsi 4 bity -------------------------------- */
   /* nizsi 4 bity zustanou stejne */
   cast1 =   klic[KLIC_VELIKOST - 1] & 0x0F;
   /* vyssi 4 bity */
   cast2 = ( klic[KLIC_VELIKOST - 1] >> 4 ) & 0x0F;  /* maskovani neni potreba, ale ... */
   cast2 = sBox[cast2];
   cast2 = ( cast2 << 4 ) & 0xF0;     /* maskovani neni potreba, ale ... */

   klic[KLIC_VELIKOST - 1] = cast1 | cast2;
   
   /* xor cisla rundy ------------------------------------------------------ */
   /* (runda je cislovana dle C od 0, musi se tedy pricist 1 ) */
   cast1 = runda + 1;
   /* nejnizsi bit cisla rundy je xorovan s nejvyssim bitem 2. bajtu */
   if ( ( cast1 & 0x01 ) == 1 )
      klic[1] = klic[1] ^ 0x80; 

   /* 4 nejvyssi bity (tedy krome jednoho) cisla rundy jsou xorovany s 4-mi nizsimi bity 3. bajtu klice */
   cast1 = ( cast1 >> 1 ) & 0x0F;  /* maskovani neni potreba, ale ... */
   klic[2] = klic[2] ^ cast1;
}


void encrypt_present_8( unsigned char * otevrenyText, unsigned char * sifrovanyText, unsigned char * vstupniKlic )
{
   	unsigned char i, runda;
	unsigned char klic[KLIC_VELIKOST];
	unsigned char stav[KLIC_VELIKOST];
	unsigned char * zdroj;
	//... Initialize ...
	
	// set trigger PIN
	set_pin(DDRB, 0b10100000);
	set_pin(PORTB, 0b10100000);

 	/* zkopirovani vstupniho do pracovniho textu (v opacnem poradi) */
	for ( i = 0 ; i < BLOK_VELIKOST ; i++ ) {
		stav[i] = otevrenyText[BLOK_VELIKOST - 1 - i];
	}
	
	/* vychozi klic? */
	if ( vstupniKlic == 0 ) {
		zdroj = vychoziKlic;
	}
	else {
   		zdroj = vstupniKlic;
	}
    /* klic je v opacnem poradi */
	for ( i = 0 ; i < KLIC_VELIKOST ; i++ ) {
		klic[i] = zdroj[KLIC_VELIKOST - 1 - i];
	}


	//... Encrypt ...
	for ( runda = 0 ; runda < RUND_POCET; runda++ ) {
		pridejRundovniKlic( stav, klic );      /* addRoundKey( STATE, K[i] ) */
    	substitucniVrstva( stav );             /* sBoxLayer( STATE ) */
      	permutacniVrstva( stav );              /* pLayer( STATE ) */
      	generujRundovniKlic( klic, runda );    /* keySchedule( ) */
   	}
   	pridejRundovniKlic( stav, klic );
	
	/* vystup je v opacnem poradi */
	for ( i = 0 ; i < BLOK_VELIKOST ; i++ ) {
		sifrovanyText[i] = stav[BLOK_VELIKOST - 1 - i];
	}



	// clear trigger PIN
	clear_pin(PORTB, 0b01011111);

}


