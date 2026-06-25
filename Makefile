CC = x86_64-w64-mingw32-gcc
NASM = nasm
CFLAGS = -Wall -Wextra -O2 -Iinclude -m64 -fno-builtin -ffunction-sections -fdata-sections
LDFLAGS = -lkernel32 -luser32 -lntdll -ladvapi32 -Wl,--gc-sections
NASMFLAGS = -f win64 -g

TARGET = ShadowHook.exe
OBJDIR = obj

C_SOURCES = $(wildcard src/*.c)
C_OBJECTS = $(patsubst src/%.c,$(OBJDIR)/%.o,$(C_SOURCES))
ASM_SOURCES = $(wildcard asm/*.asm)
ASM_OBJECTS = $(patsubst asm/%.asm,$(OBJDIR)/%.o,$(ASM_SOURCES))

all: $(OBJDIR) $(TARGET)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/%.o: asm/%.asm
	$(NASM) $(NASMFLAGS) $< -o $@

$(TARGET): $(C_OBJECTS) $(ASM_OBJECTS)
	$(CC) $^ -o $@ $(LDFLAGS)

clean:
	rm -rf $(OBJDIR) $(TARGET)

run: $(TARGET)
	wine $(TARGET)

.PHONY: all clean run