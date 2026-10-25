# ============================================================
#  WatermarkGuard.dylib  编译脚本（必须在 macOS + Xcode 上执行）
#  用法：
#     make            # 生成 WatermarkGuard.dylib（arm64）
#     make sign       # 用 ldid / codesign 打 ad-hoc 签名
#     make clean
# ============================================================

TARGET_NAME := WatermarkGuard
OBJ         := $(TARGET_NAME).dylib
SRC         := WatermarkGuard.m
HDR         := WatermarkGuard.h

SDK_PATH := $(shell xcrun --sdk iphoneos --show-sdk-path)
CLANG    := xcrun --sdk iphoneos clang

ARCH      := -arch arm64
MIN_IOS   := -miphoneos-version-min=14.0
SYSROOT   := -isysroot $(SDK_PATH)

CFLAGS  := $(ARCH) $(MIN_IOS) $(SYSROOT) -fobjc-arc -O2 -fvisibility=hidden \
           -Wall -Wno-unused-function -Wno-unused-const-variable \
           -Wno-deprecated-declarations

LDFLAGS := -dynamiclib \
           -install_name @executable_path/Frameworks/$(OBJ) \
           -framework Foundation \
           -framework UIKit \
           -framework Security \
           -framework CFNetwork

.PHONY: all sign clean info

all: $(OBJ)

$(OBJ): $(SRC) $(HDR)
	@echo "==> SDK: $(SDK_PATH)"
	$(CLANG) $(CFLAGS) $(SRC) $(LDFLAGS) -o $@
	@echo "==> 生成: $(OBJ)"
	@file $(OBJ)
	@xcrun --sdk iphoneos otool -hv $(OBJ) | head -n 6

# ad-hoc 签名（重签名工具通常也会再签一次，这里只是保证本地可校验）
sign: $(OBJ)
	@if command -v ldid >/dev/null 2>&1; then \
		ldid -S $(OBJ); echo "==> ldid -S 完成"; \
	else \
		codesign -f -s - $(OBJ); echo "==> codesign ad-hoc 完成"; \
	fi

info:
	@echo "SDK_PATH = $(SDK_PATH)"
	@xcrun --sdk iphoneos clang --version

clean:
	rm -f $(OBJ)
