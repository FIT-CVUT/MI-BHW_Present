###############################################################################
# Makefile for the project BHW_SOSSE
###############################################################################

## General Flags
PROJECT = BHW_SOSSE
MCU = atmega163
TARGET = BHW_SOSSE.elf
CC = avr-gcc

CPP = avr-g++

## Options common to compile, link and assembly rules
COMMON = -mmcu=$(MCU)

## Compile options common for all C compilation units.
CFLAGS = $(COMMON)
CFLAGS += -Wall -gdwarf-2 -Os -std=gnu99 -funsigned-char -funsigned-bitfields -fpack-struct -fshort-enums
CFLAGS += -MD -MP -MT $(*F).o -MF dep/$(@F).d 

## Assembly specific flags
ASMFLAGS = $(COMMON)
ASMFLAGS += $(CFLAGS)
ASMFLAGS += -x assembler-with-cpp -Wa,-gdwarf2

## Linker flags
LDFLAGS = $(COMMON)
LDFLAGS +=  -Wl,-Map=BHW_SOSSE.map


## Intel Hex file production flags
HEX_FLASH_FLAGS = -R .eeprom -R .fuse -R .lock -R .signature

HEX_EEPROM_FLAGS = -j .eeprom
HEX_EEPROM_FLAGS += --set-section-flags=.eeprom="alloc,load"
HEX_EEPROM_FLAGS += --change-section-lma .eeprom=0 --no-change-warnings


## Objects that must be built in order to link
OBJECTS = main.o commands.o io.o t1.o crypt.o example_C.o example_ASM.o example_PRESENT.o 

## Objects explicitly added by the user
LINKONLYOBJECTS = 

## Build
all: $(TARGET) BHW_SOSSE.hex BHW_SOSSE.eep BHW_SOSSE.lss## Compile
main.o: ../main.c
	$(CC) $(INCLUDES) $(CFLAGS) -c  $<

commands.o: ../commands.c
	$(CC) $(INCLUDES) $(CFLAGS) -c  $<

io.o: ../io.S
	$(CC) $(INCLUDES) $(ASMFLAGS) -c  $<

t1.o: ../t1.c
	$(CC) $(INCLUDES) $(CFLAGS) -c  $<

crypt.o: ../crypt.c
	$(CC) $(INCLUDES) $(CFLAGS) -c  $<

example_C.o: ../example_C.c
	$(CC) $(INCLUDES) $(CFLAGS) -c  $<

example_ASM.o: ../example_ASM.S
	$(CC) $(INCLUDES) $(ASMFLAGS) -c  $<

example_PRESENT.o: ../example_PRESENT.c
	$(CC) $(INCLUDES) $(CFLAGS) -c  $<

##Link
$(TARGET): $(OBJECTS)
	 $(CC) $(LDFLAGS) $(OBJECTS) $(LINKONLYOBJECTS) $(LIBDIRS) $(LIBS) -o $(TARGET)

%.hex: $(TARGET)
	avr-objcopy -O ihex $(HEX_FLASH_FLAGS)  $< $@

%.eep: $(TARGET)
	-avr-objcopy $(HEX_EEPROM_FLAGS) -O ihex $< $@ || exit 0

%.lss: $(TARGET)
	avr-objdump -h -S $< > $@

## Clean target
.PHONY: clean
clean:
	-rm -rf $(OBJECTS) BHW_SOSSE.elf dep/* BHW_SOSSE.hex BHW_SOSSE.eep BHW_SOSSE.lss BHW_SOSSE.map


## Other dependencies
-include $(shell mkdir dep 2>NUL) $(wildcard dep/*)

