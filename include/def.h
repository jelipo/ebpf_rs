
#ifndef memcpy
# define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
#define memmove(dest, src, n) __builtin_memmove((dest), (src), (n))
#endif

// 快速获取指针类型的参数
#ifndef BPF_PTR_ARG
#define BPF_PTR_ARG(ctx, index) ((void *) (ctx)->args[index])
#endif
