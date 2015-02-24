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
	FIT-CTU www.fit.cvut.cz/en for the purpose of smartcard education 
	using the SOSSE created by Matthias Bruestle and files 
	from the Chair for Embedded Security (EMSEC), Ruhr-University Bochum.
*/

.set xl,26
.set xh,27
.set yl,28
.set yh,29
.set zl,30
.set zh,31
.set sph,0x3e
.set spl,0x3d
.set ramend,0x45f

;--------------------------------------------------------------------
;begin encrypt
;Pointer to the input in the registers (r24 (lo),r25 (hi))
;Pointer to the output in the registers (r22 (lo),r23 (hi))
;Pointer to the key in the registers (r20 (lo),r21 (hi))

.global	encrypt_asm_16
.type	encrypt_asm_16,@function
encrypt_asm_16:

	push r2
	push r3
	push r4
	push r5
	push r6
	push r7
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
	push r16
	push r17
	push r28
	push r29
    push r30
    push r31

	; X
	mov r27, r25	; input HIGH
	mov r26, r24	; input LOW
	; Y
	mov r29, r23	; output HIGH
	mov r28, r22	; output LOW
	; Z
	mov r31, r21	; key HIGH
	mov	r30, r20	; key LOW

	; set trigger pin
	sbi 0x17,5
	sbi 0x17,7

	sbi 0x18,5
	sbi 0x18,7

	ldi	r16, 16
	clr	r17
	add	r28, r16
	adc	r29, r17
	ldi	r18, 16

encrypt_loop:
	ld		r16, X+
	ld		r17, Z+
	eor		r16, r17
	st		-Y, r16
	dec		r18
	brne	encrypt_loop

	; clear trigger pin
	cbi 0x18,5
	cbi 0x18,7

    pop r31
    pop r30
	pop r29
	pop r28
	pop r17
	pop r16
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop r7
	pop r6
	pop r5
	pop r4
	pop r3
	pop r2
	clr r1

    ret

;--------------------------------------------------------------------
;begin encrypt
;Pointer to the input in the registers (r24 (lo),r25 (hi))
;Pointer to the output in the registers (r22 (lo),r23 (hi))
;Pointer to the key in the registers (r20 (lo),r21 (hi))

.global	decrypt_asm_16
.type	decrypt_asm_16,@function
decrypt_asm_16:

	push r2
	push r3
	push r4
	push r5
	push r6
	push r7
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
	push r16
	push r17
	push r28
	push r29
    push r30
    push r31

	; X
	mov r26, r24	; input LOW
	mov r27, r25	; input HIGH
	; Y
	mov r28, r22	; output LOW
	mov r29, r23	; output HIGH
	; Z
	mov	r30, r20	; key LOW
	mov r31, r21	; key HIGH

	; set trigger pin
	sbi 0x17,5
	sbi 0x17,7

	sbi 0x18,5
	sbi 0x18,7


	ldi	r16, 16
	clr	r17
	add	r26, r16
	adc	r27, r17
	ldi	r18, 16

decrypt_loop:
	ld		r16, -X
	ld		r17, Z+
	eor		r16, r17
	st		Y+, r16
	dec		r18
	brne	decrypt_loop

	; clear trigger pin
	cbi 0x18,5
	cbi 0x18,7

    pop r31
    pop r30
	pop r29
	pop r28
	pop r17
	pop r16
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop r7
	pop r6
	pop r5
	pop r4
	pop r3
	pop r2
	clr r1

    ret
