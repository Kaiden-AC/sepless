// sepless is part of seposfun (c) tools
// made by @exploit3dguy
// modified by @KaidenAC

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "../patchfinder64/patchfinder64.c"

#define GET_OFFSET(klen, x) (x - (uintptr_t) kbuf) // Thanks to @Ralph0045 for this 

addr_t xref_stuff;
void *str_stuff;
addr_t beg_func;

bool dev_kernel = false;
int version;
void* xnu;

int get_sep_patch(void* kbuf, size_t klen) {

    if (dev_kernel == true) {
        xnu = memmem(kbuf, klen, "root:xnu_", 9);
        version = atoi(xnu + 20);
    } else {
        xnu = memmem(kbuf, klen, "root:xnu-", 9);
        version = atoi(xnu + 9);
    }

    if (version <= 4570) {
        printf("getting %s()\n", __FUNCTION__);

        str_stuff = memmem(kbuf, klen, "IOReturn AppleSEPBooter::bootSEP", 32);
        if (!str_stuff) {
            printf("[-] Failed to find AppleSEPBooter bootSEP string\n");
            return -1;
        }
        xref_stuff = xref64(kbuf, 0, klen, (addr_t)GET_OFFSET(klen, str_stuff));
        
        beg_func = bof64(kbuf, 0, xref_stuff);

        *(uint32_t *) (kbuf + beg_func) = 0x52800000;
        *(uint32_t *) (kbuf + beg_func + 0x4) = 0xD65F03C0;

        printf("[+] Patched AppleSEPBooter bootSEP\n");
    
        printf("%s: quitting...\n", __FUNCTION__);
    }

    return 0;
}

int main(int argc, char* argv[]) {
   
   if(argc < 3) {
        printf("sepless - tool to patch 'AppleSEPBooter bootSEP' function in kernel, modified version by @KaidenAC, original by @exploit3dguy\n");
        printf("Usage: kcache.raw kcache.pwn [-d]\n");
        printf("       -d for dev kernels\n");
       
        return 0;
    }

    printf("%s: Starting...\n", __FUNCTION__);

    char *in = argv[1];
    char *out = argv[2];

    void* kbuf;
    size_t klen;

    FILE* fp = fopen(in, "rb");
    if (!fp) {
        printf("[-] Failed to open kernel\n");
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    klen = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    kbuf = (void*)malloc(klen);
    if(!kbuf) {
        printf("[-] Out of memory\n");
        fclose(fp);
        return -1;
    }

    fread(kbuf, 1, klen, fp);
    fclose(fp);

    for(int i = 1; i < argc; i++) {
        if(strncmp(argv[i],"-d",2) == 0) {
            printf("DEVELOPMENT kernelcache inputted\n");
            dev_kernel = true;
        }
    }

    get_sep_patch(kbuf, klen);

    fp = fopen(out, "wb+");

    fwrite(kbuf, 1, klen, fp);
    fflush(fp);
    fclose(fp);
    
    free(kbuf);

    printf("[*] Writing out patched file to %s\n", out);

    printf("%s: Quitting...\n", __FUNCTION__);

    return 0;
}
