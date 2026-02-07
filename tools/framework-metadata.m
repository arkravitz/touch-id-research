#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>

// Inspect method names and addresses only; never instantiate private classes.
__attribute__((noinline)) void metadata_done(void) { __asm__ volatile(""); }

int main(void) {
    @autoreleasepool {
        const char *paths[] = {
            "/System/Library/PrivateFrameworks/BiometricKit.framework/BiometricKit",
            "/System/Library/PrivateFrameworks/BiometricSupport.framework/BiometricSupport",
            "/System/Library/PrivateFrameworks/TrustedAccessory.framework/TrustedAccessory"
        };
        for (int p = 0; p < 3; p++) {
            void *handle = dlopen(paths[p], RTLD_LAZY);
            if (!handle) { printf("dlopen failed: %s\n", dlerror()); continue; }
            unsigned int count = 0;
            const char **names = objc_copyClassNamesForImage(paths[p], &count);
            if (!count) {
                unsigned int allCount = 0;
                Class *all = objc_copyClassList(&allCount);
                names = malloc(sizeof(char *) * allCount);
                for (unsigned int k = 0; k < allCount; k++) {
                    const char *image = class_getImageName(all[k]);
                    if (image && strstr(image, p == 0 ? "BiometricKit.framework" : p == 1 ? "BiometricSupport.framework" : "TrustedAccessory.framework"))
                        names[count++] = class_getName(all[k]);
                }
                free(all);
            }
            printf("IMAGE %s classes=%u\n", paths[p], count);
            for (unsigned int i = 0; i < count; i++) {
                Class cls = objc_getClass(names[i]);
                printf("CLASS %s\n", names[i]);
                for (int meta = 0; meta < 2; meta++) {
                    unsigned int n = 0;
                    Method *methods = class_copyMethodList(meta ? object_getClass(cls) : cls, &n);
                    for (unsigned int j = 0; j < n; j++) {
                        Dl_info info = {0};
                        IMP imp = method_getImplementation(methods[j]);
                        dladdr((void *)imp, &info);
                        printf(" %c %s %s imageOffset=0x%lx\n", meta ? '+' : '-',
                            sel_getName(method_getName(methods[j])), method_getTypeEncoding(methods[j]),
                            (unsigned long)((uintptr_t)imp - (uintptr_t)info.dli_fbase));
                    }
                    free(methods);
                }
            }
            free(names);
        }
    }
    metadata_done();
    return 0;
}
