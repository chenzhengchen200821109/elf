#ifndef __LIBPTRACE_CONFIG_H
#define __LIBPTRACE_CONFIG_H

#include <stdint.h>
#include <sys/user.h>

struct ptrace_fpu_state {
	uint8_t __buf[sizeof(struct user_fpregs_struct)];
};

#endif	/* __LIBPTRACE_CONFIG_H */
