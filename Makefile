C=clang

FRAMEWORKS:= -framework Foundation
LIBRARIES:= -lobjc
SDK:=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk

SOURCE=hello3.m Talker.m
CFLAGS=-isysroot ${SDK} -Wall -arch armv7 -g -v $(SOURCE)
LDFLAGS=$(LIBRARIES) $(FRAMEWORKS)
OUT=-o hello

all:
	$(CC) $(CFLAGS) $(LDFLAGS) $(OUT)