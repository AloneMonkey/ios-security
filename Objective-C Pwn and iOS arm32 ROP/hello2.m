#import "Talker.h"
#include <dlfcn.h>
#include <mach-o/dyld_images.h>
#include <objc/runtime.h>

struct fake_structure_t
{
    uint32_t fake_objc_class_ptr;
}fake_structure;

struct fake_objc_class_t {
        char pad[0x8];            //从+0x8开始读取的
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