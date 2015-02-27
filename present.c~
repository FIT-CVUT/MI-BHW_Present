/* present.c
 * 
 *   Popis:     Implementace blokove sifry PRESENT pro 8-bitovou AVR SmartCard
 *              Prace vznikla jako ukol do predmetu MI-BHW
 *   Autori:    Vojtech Myslivec a Zdenek Novy 
 *              FIT CVUT, unor 2015
 *
 *   Reference: Behem prece bylo cerpano z
 *              [1] A. Bogdanov, C. Paar a kol. PRESENT: An Ultra-Lightweight Block Cipher 
 *                  v Cryptographic Hardware and Embedded Systems - CHES 2007
 *                  (9th International Workshop, Vienna, Austria, September 10-13, 2007. Proceedings).
 *                  Berlin (Germany): Springer Berlin Heidelberg, 2007. 
 *                  Dostupne z http://link.springer.com/chapter/10.1007%2F978-3-540-74735-2_31
 *              [2] Dirk Klose. C PRESENT Implementation (8 Bit) v Implementations (lightweightcrypto.org).
 *                  Dostupne z http://www.lightweightcrypto.org/implementations.php
 *
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define true  0
#define false 1
typedef uint8_t bool;

#define PREPINAC_KLIC "-k"
#define USAGE  "USAGE: \n" \
               "   %s [ -k KEY ]\n" \
               "\n" \
               "      KEY   80-bit klic v hexa zapisu\n" \
               "            vychozi hodnota je 00 00 00 00 00 00 00 00 00 00\n    " \
               "\n" \
               "      Program cte zpravu ze stdin o velikost 64 bitu (1 blok)    n" \
               "      v hexa zapisu\n" \
               "\n" \
               "EXAMPLE\n" \
               "   echo \"FF FF FF FF FF FF FF FF\" | %s \n" \
               "   echo \"FF FF FF FF FF FF FF FF\" | %s -k \"FF FF FF FF FF F    F FF FF FF FF\"" \
               "\n"


#define BITU_POCET    64
#define KLIC_VELIKOST 10 /* 80 bit / 8 bit */
#define BLOK_VELIKOST  8 /* 64 bit / 8 bit */
#define SBOX_VELIKOST 16 /* 2^4 substituci (po 4 bitech) */

#define RUND_POCET    31

/* sBox je 4-bitovy, nesmi presahnout 0x0F jinak neni chovani definovano */
uint8_t sBox[SBOX_VELIKOST] = { 0x0C, 0x05, 0x06, 0x0B, 0x09, 0x00, 0x0A, 0x0D, 0x03, 0x0E, 0x0F, 0x08, 0x04, 0x07, 0x01, 0x02 };

uint8_t   klic[KLIC_VELIKOST] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t zprava[BLOK_VELIKOST] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

uint8_t runda = 0;

void vypisKlic( void ) {
   uint8_t i;
   for ( i = 0 ; i < KLIC_VELIKOST ; i++ ) {
      printf( "%02X ", klic[KLIC_VELIKOST - 1 - i] );
   }
   printf( "\n" );
}

void vypisZpravu( void ) {
   uint8_t i;
   for ( i = 0 ; i < BLOK_VELIKOST ; i++ ) {
      printf( "%02X ", zprava[BLOK_VELIKOST - 1 - i] );
   }
   printf( "\n" );
}


void pridejRundovniKlic( ) {
   uint8_t i;
   for ( i = 0 ; i < BLOK_VELIKOST ; i++ ) {
      /* xor s rund. klicem */
      /* index u klice je +2 protoze se z 80-ti bitu pouziva 64 nejvyznamnejsich */
      /* melo by byt + KLIC_VELIKOST - BLOK_VELIKOST ... */
      zprava[i] = zprava[i] ^ klic[i + 2];
   }
}

void substitucniVrstva( void ) {
   uint8_t i;
   uint8_t nibble1, nibble2;
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

void permutacniVrstva( void ) {
   uint8_t zdrojPozice, zdrojIndex, zdrojOffset;
   uint8_t   cilPozice,   cilIndex,   cilOffset;
   uint8_t i, bit, permutace[BLOK_VELIKOST];
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

void generujRundovniKlic( ) {
   uint8_t i, bajt1, bajt2, cast1, cast2;
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

void zasifruj( void ) {
   for ( runda = 0 ; runda < RUND_POCET; runda++ ) {
      pridejRundovniKlic( );      /* addRoundKey( STATE, K[i] ) */
      substitucniVrstva( );       /* sBoxLayer( STATE ) */
      permutacniVrstva( );        /* pLayer( STATE ) */
      generujRundovniKlic( );     /* keySchedule( ) */
   }
   pridejRundovniKlic( );
}


/* TODO staticke nacteni ze stringu! */
bool nactiKlic( const char * parametr ) {
   /* OK, tohle neni pekne a je to staticke pro 10 bajtu... se stringama nevim jak lepe */
   if ( 
        KLIC_VELIKOST != sscanf( parametr, "%hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx %hhx",
            &klic[9], &klic[8], &klic[7], &klic[6], &klic[5], &klic[4], &klic[3], &klic[2], &klic[1], &klic[0] ) 
        
      ) {
      printf( "nactiKlic(): chyba vstupu!\n" );
      return false;
   }
   return true;
}

bool nactiZpravu( void ) {
   uint8_t i;
   for ( i = 0 ; i < BLOK_VELIKOST ; i++ ) {
      if ( 1 != scanf( "%hhx", &zprava[BLOK_VELIKOST - 1 - i] ) ) {
         printf( "nactiZpravu(): chyba vstupu!\n" );
         return false;
      }
   }
   return true;
}

int main( int argc, char ** argv ) {
   if ( argc != 1 && argc != 3 ) {
      printf( USAGE, argv[0], argv[0], argv[0] );
      return 1;
   }
   if ( argc == 3 ) {
      if ( strncmp( PREPINAC_KLIC, argv[1], sizeof(PREPINAC_KLIC) ) == 0 ) {
         if ( nactiKlic( argv[2] ) != true ) {
            return 2;
         }
      }
      else {
         printf("Chybny prepinac\n" );
         return 2;
      }
   }

   if ( nactiZpravu( ) != true ) {
      return 3;
   }


   printf( "hello PRESENT!\n" );

   printf( "Zprava k sifrovani: " );
   vypisZpravu( );

   printf( "Sifruji klicem:     " );
   vypisKlic( );

   zasifruj( );

   printf( "Ciphertext:         " );
   vypisZpravu( );

/*   printf( "0x%02X ", byte );*/
   return 0;
}

