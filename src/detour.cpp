#include "detour.hpp"

#include <stack>
#include <iostream>
#include <list>

namespace KHook {

using namespace KHook::Asm;

#define STACK_SAFETY_BUFFER 112

#ifdef KHOOK_X64
#define FUNCTION_ATTRIBUTE_PREFIX(ret) ret
#define FUNCTION_ATTRIBUTE_SUFFIX

#ifdef _WIN32
// Save everything pertaining to Windows x86_64 callconv
static const x86_64_Reg reg[] = { rcx, rdx, r8, r9 }; // 32 bytes so 16 bytes aligned
// Save XMM0-XMM5
static const x8664FloatReg float_reg[] = { xmm0, xmm1, xmm2, xmm3 }; // Each register is 16 bytes
#else
// Save everything pertaining to Linux x86_64 callconv
static const x86_64_Reg reg[] = { rdi, rsi, rdx, rcx, r8, r9 }; // 48 bytes (so 16 bytes aligned)
// Save XMM0-XMM7
static const x8664FloatReg float_reg[] = { xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7 }; // Each register is 16 bytes
#endif
static constexpr auto reg_count = sizeof(reg) / sizeof(decltype(*reg));
static constexpr auto float_reg_count = sizeof(float_reg) / sizeof(decltype(*float_reg));
static_assert((reg_count * 8) % 16 == 0);
static_assert((float_reg_count * 16) % 16 == 0);
#else
#ifdef _WIN32
#define FUNCTION_ATTRIBUTE_PREFIX(ret) ret __cdecl
#define FUNCTION_ATTRIBUTE_SUFFIX
#else
#define FUNCTION_ATTRIBUTE_PREFIX(ret) __attribute__((cdecl)) ret
#define FUNCTION_ATTRIBUTE_SUFFIX
#endif

static const x86_Reg reg[] = { eax, ecx, edx, ebx, ebp, esi, edi, edi };
static constexpr auto reg_count = sizeof(reg) / sizeof(decltype(*reg));
static_assert((reg_count * 4) % 16 == 0);
#endif

#ifdef _WIN32
#define LINUX_ONLY(x)
#define WIN_ONLY(x) x
#else
#define LINUX_ONLY(x) x
#define WIN_ONLY(x)
#endif

template<typename T, typename Ret, typename... Args>
union MFP {
	MFP(Ret (T::*func)(Args...)) : mfp(func) {
#ifdef _WIN32
#else
		this->details.adjustor = 0;
#endif
	}
	Ret (T::*mfp)(Args...);
	struct {
		void *addr;
#ifdef _WIN32
#else
		intptr_t adjustor;
#endif
	} details;

	std::uintptr_t GetAddress() {
		return reinterpret_cast<std::uintptr_t>(this->details.addr);
	}
};

static FUNCTION_ATTRIBUTE_PREFIX(void) RecursiveLockUnlockShared(std::shared_mutex* mutex, bool lock) FUNCTION_ATTRIBUTE_SUFFIX {
	static thread_local std::unordered_map<std::shared_mutex*, std::uint32_t> lock_counts;

	auto it = lock_counts.find(mutex);
	if (it == lock_counts.end()) {
		it = lock_counts.insert_or_assign(mutex, 0).first;
	}

	if (lock) {
		it->second++;
		// First time lock
		if (it->second == 1) {
			mutex->lock_shared();
		}
	} else {
		if (it->second == 0) {
			std::abort();
		}

		it->second--;
		// No more locks, so unlock
		if (it->second == 0) {
			mutex->unlock_shared();
		}
	}
}

struct AsmLoopDetails {
	// Current iterated hook
	std::uintptr_t linked_list_it;
	std::uintptr_t pre_loop_started;
	std::uintptr_t pre_loop_over;
	std::uintptr_t original_call_over;
	std::uintptr_t post_loop_over;
	std::uintptr_t post_loop_started;
	std::uintptr_t recall_count;

	// Highest hook action so far
	std::uintptr_t action;
	// If Action::Override or higher
	// These will be used to perform the return
	std::uintptr_t fn_make_return;
	// The hook that performed the original call
	std::uintptr_t fn_make_call_original;
	// The original return value ptr
	std::uintptr_t original_return_ptr;
	// The current override return ptr
	std::uintptr_t override_return_ptr;

	// Where we saved the registers
	std::uintptr_t sp_saved_registers;
	std::uintptr_t sp_saved_stack;

	// For recall & hooks
	std::uintptr_t fn_original_function_ptr;
	std::uintptr_t fn_recall_function_ptr;
	DetourCapsule* capsule;
#ifndef KHOOK_X64
#ifndef _WIN64
	std::uint8_t pad[8];
#endif
#else
	std::uint8_t pad[8];
#endif
	static_assert(sizeof(std::uintptr_t) == sizeof(void*));
	static_assert(sizeof(std::uint32_t) >= sizeof(KHook::Action));
};
static constexpr auto local_params_size = sizeof(AsmLoopDetails);
static_assert(local_params_size % 16 == 0);

static thread_local std::stack<AsmLoopDetails*> g_saved_params;
static thread_local bool g_is_in_recall = false;
static thread_local void* g_original_return = nullptr;
static thread_local void* g_override_return = nullptr;
static thread_local std::shared_mutex* g_hook_mutex = nullptr;
static thread_local std::uintptr_t g_recall_count = 0;

static FUNCTION_ATTRIBUTE_PREFIX(void) EndDetour(AsmLoopDetails* loop, bool no_callback) FUNCTION_ATTRIBUTE_SUFFIX {
	if (g_saved_params.top() != loop || g_is_in_recall) {
		// Something went horribly wrong with the stack
		std::abort();
	}
	
	if (no_callback) {
		if (loop->recall_count != 0) {
			// If this is a recall, and we somehow have no callback then something horribly wrong happened
			// Terminate the program right now
			std::abort();
		}
		RecursiveLockUnlockShared(&loop->capsule->_detour_mutex, false);
		// Detour was early ended, unlock the mutex and pop the asm details
		g_saved_params.pop();
	} else {
		// Natural end of a detour, setup everything because AsmLoopDetails is about to go invalid (due to stack being freed)
		if (loop->recall_count == 0) {
			// Stack is about to freed, so everything
			g_original_return = reinterpret_cast<void*>(loop->original_return_ptr);
			g_override_return = reinterpret_cast<void*>(loop->override_return_ptr);
			g_recall_count = loop->recall_count;
			g_hook_mutex = &loop->capsule->_detour_mutex;
		} else {
			RecursiveLockUnlockShared(&loop->capsule->_detour_mutex, false);
		}
	}
}

static FUNCTION_ATTRIBUTE_PREFIX(AsmLoopDetails*) BeginDetour(
	AsmLoopDetails* new_loop,
	std::uintptr_t rsp_stack,
	std::uintptr_t rsp_regs,
	std::uintptr_t rsp_fake_stack,
	std::uint32_t stack_size,
	DetourCapsule* capsule) FUNCTION_ATTRIBUTE_SUFFIX {
#ifdef KHOOK_X64
	static constexpr auto regs_size = reg_count * 8 + float_reg_count * 16;
#else
	static constexpr auto regs_size = reg_count * 4;
#endif
	RecursiveLockUnlockShared(&capsule->_detour_mutex, true);

	if (g_is_in_recall) {
		// If we're in recall, update where we currently are
		auto loop = g_saved_params.top();
		loop->recall_count++;

		if (capsule != loop->capsule) {
			// Not the same detour somehow
			std::abort();
		}

		if (loop->pre_loop_over == false) {
			// Recall happened in a pre-loop, save what they sent
			auto hook = reinterpret_cast<DetourCapsule::LinkedList*>(loop->linked_list_it);
			if (*hook->hook_action > (KHook::Action)loop->action) {
				loop->fn_make_return = hook->fn_make_override_return;
				loop->override_return_ptr = hook->override_return_ptr;
				loop->action = (std::uintptr_t)*hook->hook_action;
			}
			loop->linked_list_it = reinterpret_cast<std::uintptr_t>(hook->next);

			if (loop->linked_list_it == 0x0) {
				loop->pre_loop_over = true;
			}
		} else if (loop->original_call_over == false) {
			// Recall happened in the original call, this is technically impossible
			// But we're going to support it anywways, this will avoid infinite-loops
			loop->original_call_over = true;
		} else if (loop->post_loop_over == false) {
			// Recall happened in a post-loop, save what they sent
			auto hook = reinterpret_cast<DetourCapsule::LinkedList*>(loop->linked_list_it);
			if (*hook->hook_action > (KHook::Action)loop->action) {
				loop->fn_make_return = hook->fn_make_override_return;
				loop->override_return_ptr = hook->override_return_ptr;
				loop->action = (std::uintptr_t)*hook->hook_action;
			}
			loop->linked_list_it = reinterpret_cast<std::uintptr_t>(hook->prev);

			if (loop->linked_list_it == 0x0) {
				loop->post_loop_over = true;
			}
		} else {
			// A recall happened outside of a hook
			std::abort();
		}


		// Copy the registers
		memcpy(reinterpret_cast<void*>(loop->sp_saved_registers), reinterpret_cast<void*>(rsp_regs), regs_size);
		// Copy the buffer stack
		memcpy(reinterpret_cast<void*>(loop->sp_saved_stack), reinterpret_cast<void*>(rsp_stack + sizeof(void*)), stack_size);

		// We are no longer in recall
		g_is_in_recall = false;
		return loop;
	}
	else
	{
		new_loop->linked_list_it = 0x0;
		new_loop->pre_loop_over = false;
		new_loop->pre_loop_started = false;
		new_loop->original_call_over = false;
		new_loop->post_loop_over = false;
		new_loop->post_loop_started = false;
		new_loop->recall_count = 0;

		new_loop->action = (std::uint32_t)KHook::Action::Ignore;
		new_loop->fn_make_return = 0x0;
		new_loop->fn_make_call_original = 0x42;
		new_loop->original_return_ptr = 0x0;
		new_loop->override_return_ptr = 0x0;

		new_loop->sp_saved_registers = rsp_regs;
		// Copy the stack to the fake stack
		memcpy(reinterpret_cast<void*>(rsp_fake_stack), reinterpret_cast<void*>(rsp_stack + sizeof(void*)), stack_size);
		new_loop->sp_saved_stack = rsp_fake_stack;
		new_loop->capsule = capsule;

		g_saved_params.push(new_loop);
		return new_loop;
	}
}

static thread_local std::stack<void*> g_current_hook;
static FUNCTION_ATTRIBUTE_PREFIX(void) PushPopCurrentHook(void* current_hook, bool push) FUNCTION_ATTRIBUTE_SUFFIX {
	if (push) {
		g_current_hook.push(current_hook);
	} else {
		g_current_hook.pop();
	}
}

static thread_local std::stack<std::uintptr_t> rsp_values;
static FUNCTION_ATTRIBUTE_PREFIX(void) PushRsp(std::uintptr_t rsp) FUNCTION_ATTRIBUTE_SUFFIX {
	//std::cout << "Saving RSP: 0x" << std::hex << rsp << std::endl;
	rsp_values.push(rsp);
}

static FUNCTION_ATTRIBUTE_PREFIX(std::uintptr_t) PeekRsp(std::uintptr_t rsp) FUNCTION_ATTRIBUTE_SUFFIX {
	auto internal_rsp = rsp_values.top();
	assert((internal_rsp + STACK_SAFETY_BUFFER) > rsp);
	return internal_rsp;
}

static FUNCTION_ATTRIBUTE_PREFIX(void) PopRsp() FUNCTION_ATTRIBUTE_SUFFIX {
	rsp_values.pop();
}

static FUNCTION_ATTRIBUTE_PREFIX(std::uintptr_t) PeekRbp(std::uintptr_t rsp) FUNCTION_ATTRIBUTE_SUFFIX {
	return reinterpret_cast<std::uintptr_t>(g_saved_params.top());
}

static FUNCTION_ATTRIBUTE_PREFIX(void) PrintRSP(std::uintptr_t rsp) FUNCTION_ATTRIBUTE_SUFFIX {
#ifdef KHOOK_X64
	printf("RSP/ESP : 0x%lX\n", rsp);
#else
	printf("RSP/ESP : 0x%X\n", rsp);
#endif
	/*for (int i = 0; i < 10; i++) {
		auto ptr = (((std::uint8_t*)rsp) + i * sizeof(void*));
		std::cout << "[0x" << std::hex << (rsp + (i * sizeof(void*))) << "](RSP + 0x" << i * sizeof(void*) << ") : 0x" << std::hex << *(std::uintptr_t*)ptr
		<< std::dec <<  " float(" << *(float*)ptr << ")"
		<< std::endl;
	}*/
}

static FUNCTION_ATTRIBUTE_PREFIX(void) PrintRegister(std::uintptr_t reg, const char* name) FUNCTION_ATTRIBUTE_SUFFIX {
#ifdef KHOOK_X64
	printf("%s : 0x%lX\n", name, reg);
#else
	printf("%s : 0x%X\n", name, reg);
#endif
}

static FUNCTION_ATTRIBUTE_PREFIX(void) PrintEntryExitRSP(std::uintptr_t rsp, bool entry) FUNCTION_ATTRIBUTE_SUFFIX {
#ifdef KHOOK_X64
	//printf("%s RSP/ESP : 0x%lX\n", (entry) ? "ENTRY" : "EXIT", rsp);
#else
	//printf("%s RSP/ESP : 0x%X\n", (entry) ? "ENTRY" : "EXIT", rsp);
#endif
}

KHOOK_API void* GetCurrent() {
	return g_current_hook.top();
}

KHOOK_API void* DoRecall(KHook::Action action, void** pointerToReturnValue) {
	g_is_in_recall = true;
	auto it = ((DetourCapsule::LinkedList*)g_saved_params.top()->linked_list_it);
	*(it->hook_action) = action;
	*pointerToReturnValue = reinterpret_cast<void*>(it->override_return_ptr);
	return reinterpret_cast<void*>(g_saved_params.top()->capsule->_jit_func_ptr);
}

KHOOK_API void* GetOriginalFunction() {
	return reinterpret_cast<void*>(g_saved_params.top()->fn_original_function_ptr);
}

KHOOK_API void* GetOriginalValuePtr(bool pop) {
	if (pop) {
		if (g_recall_count != 0) {
			g_saved_params.top()->recall_count--;
		} else {
			g_saved_params.pop();
		}
		RecursiveLockUnlockShared(g_hook_mutex, false);
		//printf("Origi: %p\n", g_original_return);
		return g_original_return;
	} else {
		return reinterpret_cast<void*>(g_saved_params.top()->original_return_ptr);
	}
}

KHOOK_API void* GetOverrideValuePtr(bool pop) {
	if (pop) {
		if (g_recall_count != 0) {
			g_saved_params.top()->recall_count--;
		} else {
			g_saved_params.pop();
		}
		RecursiveLockUnlockShared(g_hook_mutex, false);
		return g_override_return;
	} else {
		return reinterpret_cast<void*>(g_saved_params.top()->override_return_ptr);
	}
}

/*void memcpy_detour(std::uintptr_t dst, std::uintptr_t src, std::uintptr_t size) {
	std::cout << std::hex << "dst 0x" << dst << " src 0x" << src << " size 0x" << size << std::endl;
}*/

void memcpy_debug(void* dest, const void* src, std::size_t count) {
	//printf("dst: %p src: %p\n", dest, src);
	memcpy(dest, src, count);
}

void copy_stack(DetourCapsule::AsmJit& jit, std::int32_t offset, std::int32_t stack_size) {
	using namespace Asm;

#ifdef KHOOK_X64
	jit.push(rax);
	LINUX_ONLY(jit.push(rdi)); WIN_ONLY(jit.push(rcx));
	LINUX_ONLY(jit.push(rsi)); WIN_ONLY(jit.push(rdx));
	LINUX_ONLY(jit.push(rdx)); WIN_ONLY(jit.push(r8));

	// 1st param - Dst
	LINUX_ONLY(jit.lea(rdi, rsp(4 * sizeof(void*) + offset)));
	WIN_ONLY(jit.lea(rcx, rsp(4 * sizeof(void*) + offset)));
	// 2nd param - Src
	LINUX_ONLY(jit.lea(rsi, rbp(offsetof(AsmLoopDetails, sp_saved_stack))));
	WIN_ONLY(jit.lea(rdx, rbp(offsetof(AsmLoopDetails, sp_saved_stack))));
	// 3rd param - Size
	LINUX_ONLY(jit.mov(rdx, stack_size));
	WIN_ONLY(jit.mov(r8, stack_size));

	WIN_ONLY(jit.sub(rsp, 32));
	jit.mov(rax, reinterpret_cast<std::uintptr_t>(memcpy));
	jit.call(rax);
	WIN_ONLY(jit.add(rsp, 32));

	LINUX_ONLY(jit.pop(rdx)); WIN_ONLY(jit.pop(r8));
	LINUX_ONLY(jit.pop(rsi)); WIN_ONLY(jit.pop(rdx));
	LINUX_ONLY(jit.pop(rdi)); WIN_ONLY(jit.pop(rcx));
	jit.pop(rax);
#else
	jit.push(stack_size); // Size
	jit.lea(eax, esp(1 * sizeof(void*) + offset + stack_size + stack_start + sizeof(void*))); // Src
	jit.push(eax);
	jit.lea(eax, esp(2 * sizeof(void*) + offset)); // Dst
	jit.push(eax);
	jit.mov(eax, reinterpret_cast<std::uintptr_t>(memcpy));
	jit.call(eax);
	jit.add(esp, sizeof(void*) * 3);
#endif
}

DetourCapsule::DetourCapsule(void* detour_address) :
	_in_deletion(false),
	_start_callbacks(nullptr),
	_end_callbacks(nullptr),
	_jit_func_ptr(0),
	_original_function(0),
	_stack_size(STACK_SAFETY_BUFFER) {
	// Because we want to be call agnostic we must get clever
	// No register can be used to call a function, so here's the plan
	// mov rax, 0xStart Address of JIT function
	// add rax, <offset calculated later>
	// push rax
	// mov rax, 0xAddress Of function to call
	// push rax
	// retn
	// next instructions
	// !! Rewrite <offset calculated later>
#ifdef KHOOK_X64
	using namespace Asm;

	static auto print_register = [](DetourCapsule::AsmJit& jit, x86_64_Reg reg, const char* name) {
		WIN_ONLY(jit.sub(rsp, 32));
		
		LINUX_ONLY(jit.mov(rdi, reg));
		WIN_ONLY(jit.mov(rcx, reg));

		LINUX_ONLY(jit.mov(rsi, reinterpret_cast<std::uintptr_t>(name)));
		WIN_ONLY(jit.mov(rdx, reinterpret_cast<std::uintptr_t>(name)));

		jit.mov(rax, reinterpret_cast<std::uintptr_t>(PrintRegister));
		jit.call(rax);

		WIN_ONLY(jit.add(rsp, 32));
	};

	static auto print_rsp = [](DetourCapsule::AsmJit& jit, std::uint32_t offset = 0) {
		WIN_ONLY(jit.sub(rsp, 32));

		jit.push(rdi);
		jit.push(rcx);
		jit.push(rdx);
		jit.push(rax);
		jit.push(r8);
		jit.push(r9);
		
		LINUX_ONLY(jit.lea(rdi, rsp(6 * 8 + offset)));
		WIN_ONLY(jit.lea(rcx, rsp(32 + 6 * 8 + offset)));

		jit.mov(rax, reinterpret_cast<std::uintptr_t>(PrintRSP));
		jit.call(rax);

		jit.pop(r9);
		jit.pop(r8);
		jit.pop(rax);
		jit.pop(rdx);
		jit.pop(rcx);
		jit.pop(rdi);

		WIN_ONLY(jit.add(rsp, 32));
	};

	static auto begin_detour = [](DetourCapsule::AsmJit& jit, std::uint32_t offset_to_loop_params, std::uint32_t offset_to_regs, std::uint32_t offset_to_stack, std::int32_t stack_size, DetourCapsule* capsule) {
		WIN_ONLY(jit.sub(rsp, 48));
		// 1st param - Loop variable
		LINUX_ONLY(jit.lea(rdi, rsp(offset_to_loop_params)));
		WIN_ONLY(jit.lea(rcx, rsp(offset_to_loop_params)));
		// 2nd param - RSP Stack
		LINUX_ONLY(jit.mov(rsi, rsp(offset_to_stack)));
		WIN_ONLY(jit.mov(rdx, rsp(offset_to_stack)));
		// 3rd param - RSP Reg
		LINUX_ONLY(jit.lea(rdx, rsp(offset_to_regs)));
		WIN_ONLY(jit.lea(r8, rsp(offset_to_regs)));
		// 4th param - RSP Fake stack
		LINUX_ONLY(jit.mov(rcx, rsp));
		WIN_ONLY(jit.mov(r9, rsp));
		// 5th param - Stack size
		LINUX_ONLY(jit.mov(r8, stack_size));
		WIN_ONLY(jit.mov(rsp(0x20), stack_size));
		// 6th param - Detour Capsule
		LINUX_ONLY(jit.mov(r9, reinterpret_cast<std::uintptr_t>(capsule)));
		WIN_ONLY(jit.mov(rax, reinterpret_cast<std::uintptr_t>(capsule)));
		WIN_ONLY(jit.mov(rsp(0x28), rax));

		jit.mov(rax, reinterpret_cast<std::uintptr_t>(BeginDetour));
		jit.call(rax);
		WIN_ONLY(jit.add(rsp, 48));
	};

	static auto end_detour = [](DetourCapsule::AsmJit& jit, x86_64_Reg loop, bool no_callbacks) {
		WIN_ONLY(jit.sub(rsp, 32));
		// 1st param - Loop variable
		LINUX_ONLY(jit.mov(rdi, loop));
		WIN_ONLY(jit.mov(rcx, loop));
		// 2nd param - No callbacks
		LINUX_ONLY(jit.mov(rsi, no_callbacks));
		WIN_ONLY(jit.mov(rdx, no_callbacks));

		jit.mov(rax, reinterpret_cast<std::uintptr_t>(EndDetour));
		jit.call(rax);
		WIN_ONLY(jit.add(rsp, 32));
	};

	static auto push_current_hook = [](DetourCapsule::AsmJit& jit, x86_64_RegRm reg) {
		WIN_ONLY(jit.sub(rsp, 32));
		// 1st param - Original return ptr
		LINUX_ONLY(jit.mov(rdi, reg));
		WIN_ONLY(jit.mov(rcx, reg));
		// 2nd param - Store
		LINUX_ONLY(jit.mov(rsi, true));
		WIN_ONLY(jit.mov(rdx, true));

		jit.mov(rax, reinterpret_cast<std::uintptr_t>(PushPopCurrentHook));
		jit.call(rax);
		WIN_ONLY(jit.add(rsp, 32));
	};

	static auto pop_current_hook = [](DetourCapsule::AsmJit& jit) {
		WIN_ONLY(jit.sub(rsp, 32));
		// 2nd param - Store
		LINUX_ONLY(jit.mov(rsi, false));
		WIN_ONLY(jit.mov(rdx, false));

		jit.mov(rax, reinterpret_cast<std::uintptr_t>(PushPopCurrentHook));
		jit.call(rax);
		WIN_ONLY(jit.add(rsp, 32));
	};

	static auto push_rsp = [](DetourCapsule::AsmJit& jit) {
		// We should allocate shadow space, but our stack size should be big enough for it already...
		// 1st param - Rsp
		LINUX_ONLY(jit.mov(rdi, rsp));
		WIN_ONLY(jit.mov(rcx, rsp));
		jit.mov(rax, reinterpret_cast<std::uintptr_t>(PushRsp));
		jit.call(rax);
	};

	static auto peek_rsp = [](DetourCapsule::AsmJit& jit) {
		// Force align rsp
		jit.mov(rax, 0xFFFFFFFFFFFFFFF0);
		jit.l_and(rsp, rax);
		
		// just in case of stack corruption
		static constexpr std::uint32_t stackSpace = 96 + WIN_ONLY(32) LINUX_ONLY(0);
		jit.sub(rsp, stackSpace);

		// 1st param - Rsp
		LINUX_ONLY(jit.lea(rdi, rsp(stackSpace)));
		WIN_ONLY(jit.lea(rcx, rsp(stackSpace)));
		jit.mov(rax, reinterpret_cast<std::uintptr_t>(PeekRsp));
		jit.call(rax);

		jit.mov(rsp, rax);
	};

	static auto peek_rbp = [](DetourCapsule::AsmJit& jit) {
		WIN_ONLY(jit.sub(rsp, 32));
		jit.mov(rax, reinterpret_cast<std::uintptr_t>(PeekRbp));
		jit.call(rax);
		WIN_ONLY(jit.add(rsp, 32));

		jit.mov(rbp, rax);
	};

	static auto pop_rsp = [](DetourCapsule::AsmJit& jit) {
		WIN_ONLY(jit.sub(rsp, 32));
		jit.mov(rax, reinterpret_cast<std::uintptr_t>(PopRsp));
		jit.call(rax);
		WIN_ONLY(jit.add(rsp, 32));
	};

	// Push rbp we're going to be using it and align the stack at the same time
	_jit.push(rbp);
	//print_rsp(_jit);

	// Variable to store various data, should be 16 bytes aligned
	_jit.sub(rsp, local_params_size);

	// Save general purpose registers
	_jit.sub(rsp, sizeof(void*) * reg_count);
	for (int i = 0; i < reg_count; i++) {
		_jit.mov(rsp(sizeof(void*) * i), reg[i]);
	}
	static_assert((sizeof(void*) * reg_count) % 16 == 0);
	// Save floating point registers
	_jit.sub(rsp, 16 * float_reg_count);
	for (int i = 0; i < float_reg_count; i++) {
		_jit.movsd(rsp(16 * i), float_reg[i]);
	}

	//print_rsp(_jit, 16 * float_reg_count + local_params_size + (sizeof(void*) * reg_count) + 8);
	
	// Bytes offset to get back at where we saved our data
	static constexpr auto reg_start = 0;

	// Restore registers
	static auto restore_regs = [](DetourCapsule::AsmJit& jit) {
		for (int i = 0; i < float_reg_count; i++) {
			jit.movsd(float_reg[i], rbp(16 * i));
		}

		for (int i = 0; i < reg_count; i++) {
			jit.mov(reg[i], rbp((16 * float_reg_count) + 8 * i));
		}
	};

	static constexpr auto stack_local_data_start = 16 * float_reg_count + 8 * reg_count + reg_start;
	static constexpr auto func_param_stack_start = stack_local_data_start + local_params_size + 8 /* push rbp */;

	static auto perform_loop = [](DetourCapsule::AsmJit& jit, std::uintptr_t jit_func_ptr, std::int32_t func_param_stack_size, std::int32_t offset_fn_callback, std::int32_t offset_next_it, std::int32_t offset_loop_condition) {
		auto entry_loop = (std::int32_t)jit.get_outputpos();
		jit.mov(r8, rax(offset_fn_callback)); // offsetof(LinkedList, fn_callback)
		jit.test(r8, r8);
		std::int32_t exit_loop_recall = 0;
		jit.jz(INT32_MAX); auto exit_loop = jit.get_outputpos(); {
			// MAKE PRE/POST CALL
			jit.push(r8);
			jit.push(r8);
			// Reset hook action value to ignore
			jit.mov(r8, rax(offsetof(LinkedList, hook_action)));
			jit.mov(r8(), (std::int32_t)KHook::Action::Ignore);
			push_current_hook(jit, rax(offsetof(LinkedList, hook_ptr)));
			jit.pop(r8);
			jit.pop(r8);
			jit.mov(rax, jit_func_ptr);
			jit.mov(rax, rax());
			jit.add(rax, INT32_MAX);
			auto make_pre_call_return = jit.get_outputpos();
			jit.push(rax); // Setup return address, basically later in this function
			jit.push(r8); // PRE/POST Callback address
			copy_stack(jit, sizeof(void*) * 2, func_param_stack_size);
			jit.mov(rbp, rbp(offsetof(AsmLoopDetails, sp_saved_registers)));
			restore_regs(jit);
			jit.retn();
			jit.rewrite(make_pre_call_return - sizeof(std::uint32_t), jit.get_outputpos());
			peek_rsp(jit);
			pop_current_hook(jit);
			peek_rbp(jit);
			//print_register(jit, rbp, "PEEK-RBP");
			// Test loop condition
			jit.mov(rax, rbp(offset_loop_condition));
			jit.test(rax, rax);
			// Exit loop if a recall occurred, and that list was already iterated
			jit.jnz(INT32_MAX); exit_loop_recall = jit.get_outputpos();

			jit.mov(rax, rbp(offsetof(AsmLoopDetails, linked_list_it)));
			jit.mov(r8, rax(offsetof(LinkedList, hook_action)));
			jit.mov(r8, r8());
			jit.l_and(r8, 0xF);
			// If (current_hook->action > highestaction)
			jit.cmp(r8, rbp(offsetof(AsmLoopDetails, action)));
			jit.jle(INT32_MAX);
			auto if_pre_action = jit.get_outputpos(); {
				jit.mov(rbp(offsetof(AsmLoopDetails, action)), r8);
				jit.mov(r8, rax(offsetof(LinkedList, fn_make_override_return)));
				jit.mov(rbp(offsetof(AsmLoopDetails, fn_make_return)), r8);
				jit.mov(r8, rax(offsetof(LinkedList, override_return_ptr)));
				jit.mov(rbp(offsetof(AsmLoopDetails, override_return_ptr)), r8);
			}
			jit.rewrite<std::int32_t>(if_pre_action - sizeof(std::int32_t), jit.get_outputpos() - if_pre_action);
			// Next item in the list
			jit.mov(rax, rax(offset_next_it)); //  offsetof(LinkedList, next)
			jit.mov(rbp(offsetof(AsmLoopDetails, linked_list_it)), rax);
			jit.test(rax, rax);
	
			// Loop
			jit.jnz(INT32_MAX);
			jit.rewrite<std::int32_t>(jit.get_outputpos() - sizeof(std::int32_t), entry_loop - (std::int32_t)jit.get_outputpos());
		}
		jit.rewrite<std::int32_t>(exit_loop - sizeof(std::int32_t), jit.get_outputpos() - exit_loop);
		jit.rewrite<std::int32_t>(exit_loop_recall - sizeof(std::int32_t), jit.get_outputpos() - exit_loop_recall);
		jit.mov(rbp(offset_loop_condition), true);
	};

	// Allocate our fake stack	
	std::int32_t func_param_stack_size = (_stack_size != 0) ? _stack_size : STACK_SAFETY_BUFFER;
	_jit.sub(rsp, func_param_stack_size);
	// Registers have been saved, let's get the loop details
	begin_detour(_jit, 
		func_param_stack_size + stack_local_data_start,
		func_param_stack_size + reg_start,
		func_param_stack_size + func_param_stack_start,
		func_param_stack_size,
		this
	);
	_jit.mov(rbp, rax);
	_jit.mov(rax, rsp(func_param_stack_size + stack_local_data_start + local_params_size + sizeof(void*)));
	//print_register(_jit, rax, "RETURN ADDR");
	//print_register(_jit, rbp, "RBP");

	// Early retrieve callbacks
	_jit.mov(rax, reinterpret_cast<std::uintptr_t>(&_start_callbacks));
	_jit.mov(rax, rax());
	
	// If no callbacks, early return
	_jit.test(rax, rax);
	_jit.jnz(INT32_MAX);{auto jnz_pos = _jit.get_outputpos(); {
		// End the detour
		end_detour(_jit, rbp, true);
		_jit.add(rsp, func_param_stack_size);

		// Retrieve the call address
		_jit.mov(rax, reinterpret_cast<std::uintptr_t>(&_original_function));
		_jit.mov(rax, rax());

		// Restore rbp now, and setup call address
		_jit.mov(rbp, rsp(stack_local_data_start + local_params_size));
		_jit.mov(rsp(stack_local_data_start + local_params_size), rax);

		// Restore every other registers
		_jit.push(rbp);
		_jit.lea(rbp, rsp(reg_start));
		restore_regs(_jit);
		_jit.pop(rbp);

		_jit.add(rsp, stack_local_data_start + local_params_size);
		//print_rsp(_jit);
		_jit.retn();
	}
	// Write our jump offset
	_jit.rewrite<std::int32_t>(jnz_pos - sizeof(std::int32_t), _jit.get_outputpos() - jnz_pos);}

	// Check if this is a recall
	//print_register(_jit, rbp, "INIT-RBP");
	_jit.mov(rax, rbp(offsetof(AsmLoopDetails, recall_count)));
	_jit.test(rax, rax);
	std::int32_t recall_jump = 0;
	_jit.jz(INT32_MAX);{auto jz_pos = _jit.get_outputpos(); {
		// This is a recall, so free our local variables and reg saves we don't need them
		_jit.add(rsp, stack_local_data_start + local_params_size);
		_jit.jump(INT32_MAX); recall_jump = _jit.get_outputpos();
	}
	// Write our jump offset
	_jit.rewrite<std::int32_t>(jz_pos - sizeof(std::int32_t), _jit.get_outputpos() - jz_pos);}
	// Inital loop
	_jit.mov(rax, reinterpret_cast<std::uintptr_t>(&_start_callbacks));
	_jit.mov(rax, rax());
	// Default hook action is to ignore
	_jit.mov(rbp(offsetof(AsmLoopDetails, action)), (std::uint32_t)KHook::Action::Ignore);
	// Setup original function address
	_jit.mov(r8, reinterpret_cast<std::uintptr_t>(&_original_function));
	_jit.mov(r8, r8());
	_jit.mov(rbp(offsetof(AsmLoopDetails, fn_original_function_ptr)), r8);
	// Set default return to original value
	_jit.mov(r8, rax(offsetof(LinkedList, fn_make_original_return)));
	_jit.mov(rbp(offsetof(AsmLoopDetails, fn_make_return)), r8);
	// First hook will be made to call original
	_jit.mov(r8, rax(offsetof(LinkedList, fn_make_call_original)));
	_jit.mov(rbp(offsetof(AsmLoopDetails, fn_make_call_original)), r8);
	_jit.mov(r8, rax(offsetof(LinkedList, original_return_ptr)));
	_jit.mov(rbp(offsetof(AsmLoopDetails, original_return_ptr)), r8);
	// Default init override ptr but it won't be used
	_jit.mov(r8, rax(offsetof(LinkedList, override_return_ptr)));
	_jit.mov(rbp(offsetof(AsmLoopDetails, override_return_ptr)), r8);
	//print_register(_jit, rbp, "END-INIT-RBP");
	_jit.rewrite<std::int32_t>(recall_jump - sizeof(std::int32_t), _jit.get_outputpos() - recall_jump);

	// Remember our whole stack
	// We will restore it after each function call
	push_rsp(_jit);

	//print_register(_jit, rbp, "PRE-RBP");
	// Prelude to PRE LOOP
	// Hooks with a pre callback are enqueued at the start of linked list
	// If this a recall, don't init anything just pickup where we left off
	_jit.mov(rax, rbp(offsetof(AsmLoopDetails, pre_loop_started)));
	_jit.test(rax, rax);
	_jit.jnz(INT32_MAX);{auto jnz = _jit.get_outputpos(); {
		_jit.mov(rax, reinterpret_cast<std::uintptr_t>(&_start_callbacks));
		_jit.mov(rax, rax());
		_jit.mov(rbp(offsetof(AsmLoopDetails, linked_list_it)), rax);
	}
	_jit.rewrite<std::int32_t>(jnz - sizeof(std::int32_t), _jit.get_outputpos() - jnz);}
	_jit.mov(rbp(offsetof(AsmLoopDetails, pre_loop_started)), true);

	// PRE LOOP
	_jit.mov(rax, rbp(offsetof(AsmLoopDetails, pre_loop_over)));
	_jit.test(rax, rax);
	_jit.jnz(INT32_MAX);{auto jnz = _jit.get_outputpos(); {
		_jit.mov(rax, rbp(offsetof(AsmLoopDetails, linked_list_it)));
		perform_loop(_jit, reinterpret_cast<std::uintptr_t>(&_jit_func_ptr), func_param_stack_size, offsetof(LinkedList, fn_make_pre), offsetof(LinkedList, next), offsetof(AsmLoopDetails, pre_loop_over));
	}
	_jit.rewrite<std::int32_t>(jnz - sizeof(std::int32_t), _jit.get_outputpos() - jnz);}
	_jit.mov(rbp(offsetof(AsmLoopDetails, pre_loop_over)), true);

	//print_register(_jit, rbp, "ORIGINAL-RBP");
	// Call original (maybe)
	// RBP which we have set much earlier still contains our local variables
	// it should have been saved across all calls as per linux & win callconvs
	_jit.mov(rax, rbp(offsetof(AsmLoopDetails, original_call_over)));
	_jit.test(rax, rax);
	_jit.jnz(INT32_MAX);{auto jnz = _jit.get_outputpos(); {
		_jit.mov(rax, reinterpret_cast<std::uintptr_t>(&_original_function));
		_jit.mov(rax, rax());

		_jit.mov(rax, rbp(offsetof(AsmLoopDetails, action)));
		_jit.cmp(rax, (std::int32_t)Action::Supersede);
		_jit.je(INT32_MAX);
		auto if_not_supersede = _jit.get_outputpos(); {
			// MAKE ORIGINAL CALL
			_jit.mov(rax, reinterpret_cast<std::uintptr_t>(&_jit_func_ptr));
			_jit.mov(rax, rax());
			_jit.add(rax, INT32_MAX);
			auto make_pre_call_return = _jit.get_outputpos();
			_jit.push(rax); // Setup return address, basically later in this function
			_jit.mov(rax, rbp(offsetof(AsmLoopDetails, fn_make_call_original)));
			_jit.push(rax); // Call original
			//print_register(_jit, rax, "RAX");
			// RBP must be valid when copy stack is called
			copy_stack(_jit, sizeof(void*) * 2, func_param_stack_size);
			_jit.mov(rbp, rbp(offsetof(AsmLoopDetails, sp_saved_registers)));
			restore_regs(_jit);
			_jit.retn();
			_jit.rewrite(make_pre_call_return - sizeof(std::uint32_t), _jit.get_outputpos());
			peek_rsp(_jit);
			peek_rbp(_jit);
		}
		_jit.rewrite<std::int32_t>(if_not_supersede - sizeof(std::int32_t), _jit.get_outputpos() - if_not_supersede);
	}
	_jit.rewrite<std::int32_t>(jnz - sizeof(std::int32_t), _jit.get_outputpos() - jnz);}
	// Call original is over
	_jit.mov(rbp(offsetof(AsmLoopDetails, original_call_over)), true);

	//print_register(_jit, rbp, "POST-RBP");
	// Prelude to POST LOOP
	// Hooks with a post callback are enqueued at the end of linked list
	_jit.mov(rax, rbp(offsetof(AsmLoopDetails, post_loop_started)));
	_jit.test(rax, rax);
	_jit.jnz(INT32_MAX);{auto jnz = _jit.get_outputpos(); {
		_jit.mov(rax, reinterpret_cast<std::uintptr_t>(&_end_callbacks));
		_jit.mov(rax, rax());
		_jit.mov(rbp(offsetof(AsmLoopDetails, linked_list_it)), rax);
	}
	_jit.rewrite<std::int32_t>(jnz - sizeof(std::int32_t), _jit.get_outputpos() - jnz);}
	_jit.mov(rbp(offsetof(AsmLoopDetails, post_loop_started)), true);

	// POST LOOP
	_jit.mov(rax, rbp(offsetof(AsmLoopDetails, post_loop_over)));
	_jit.test(rax, rax);
	_jit.jnz(INT32_MAX);{auto jnz = _jit.get_outputpos(); {
		_jit.mov(rax, rbp(offsetof(AsmLoopDetails, linked_list_it)));
		perform_loop(_jit, reinterpret_cast<std::uintptr_t>(&_jit_func_ptr), func_param_stack_size, offsetof(LinkedList, fn_make_post), offsetof(LinkedList, prev), offsetof(AsmLoopDetails, post_loop_over));
	}
	_jit.rewrite<std::int32_t>(jnz - sizeof(std::int32_t), _jit.get_outputpos() - jnz);}
	//print_register(_jit, rbp, "END-POST-RBP");
	_jit.mov(rbp(offsetof(AsmLoopDetails, post_loop_over)), true);

	// EXIT HOOK
	pop_rsp(_jit);
	end_detour(_jit, rbp, false);

	// Restore every other registers
	_jit.push(rbp);
	_jit.mov(rbp, rbp(offsetof(AsmLoopDetails, sp_saved_registers)));
	restore_regs(_jit);
	_jit.pop(rbp);
	_jit.push(rax);

	_jit.mov(rax, rbp(offsetof(AsmLoopDetails, recall_count)));
	_jit.test(rax, rax);
	_jit.jnz(INT32_MAX);{auto jnz = _jit.get_outputpos(); {
		// We've climbed back all the recall, free the copy stack and asm loop
		// Move our saved rax value up
		_jit.pop(rax);
		_jit.add(rsp, func_param_stack_size + stack_local_data_start + local_params_size);
		_jit.push(rax);

		// Retrieve the call address
		_jit.mov(rax, rbp(offsetof(AsmLoopDetails, fn_make_return)));

		// Restore rbp now, setup call address and
		_jit.mov(rbp, rsp(sizeof(void*)));
		_jit.mov(rsp(sizeof(void*)), rax);
		// Restore rax
		_jit.pop(rax);

		//print_rsp(_jit);
		// fn_make_return will pop our override & original ptr
		_jit.retn();
	}
	_jit.rewrite<std::int32_t>(jnz - sizeof(std::int32_t), _jit.get_outputpos() - jnz);}
	_jit.sub(rax, 0x1);
	_jit.mov(rbp(offsetof(AsmLoopDetails, recall_count)), rax);
	_jit.pop(rax);
	
	// Free the fake stack
	_jit.add(rsp, func_param_stack_size);

	// Restore rbp, go back up the recall chain
	//print_rsp(_jit);
	_jit.pop(rbp);
	_jit.mov(rax, rsp());
	//print_register(_jit, rax, "RETURN ADDR");
	//_jit.breakpoint();
	_jit.retn();
#else
using namespace Asm;

	static auto print_rsp = [](DetourCapsule::AsmJit& jit, int static_offset = 0) {
		jit.push(eax); // -4
		jit.push(0x0); // -4
		
		jit.lea(eax, esp(8 + static_offset));
		jit.push(eax); // -4
		jit.mov(eax, reinterpret_cast<std::uintptr_t>(PrintRSP));
		jit.call(eax); // -4
		// +4
		jit.add(esp, sizeof(void*) * 2); // +8

		jit.pop(eax); // +4
	};

	static auto print_entry_rsp = [](DetourCapsule::AsmJit& jit, bool b) {
		jit.push(eax); // -4

		jit.lea(eax, esp(4));
		jit.push(b); // -4
		jit.push(eax); // -4
		jit.mov(eax, reinterpret_cast<std::uintptr_t>(PrintEntryExitRSP));
		jit.call(eax); // -4
		// +4
		jit.add(esp, sizeof(void*) * 2); // +8

		jit.pop(eax); // +4
	};
	static auto push_current_hook = [](DetourCapsule::AsmJit& jit, x86_RegRm reg) {
		jit.push(eax);

		jit.push(true);
		jit.push(reg);
		jit.mov(eax, reinterpret_cast<std::uintptr_t>(PushPopCurrentHook));
		jit.call(eax);
		jit.add(esp, sizeof(void*) * 3);
	};

	static auto pop_current_hook = [](DetourCapsule::AsmJit& jit) {
		jit.push(eax);
		jit.push(eax);

		jit.push(false);
		jit.push(0x0);
		jit.mov(eax, reinterpret_cast<std::uintptr_t>(PushPopCurrentHook));
		jit.call(eax);
		jit.add(esp, sizeof(void*) * 2);

		jit.pop(eax);
		jit.pop(eax);
	};

	static auto push_rsp = [](DetourCapsule::AsmJit& jit) {
		jit.push(eax);

		jit.lea(eax, esp(4));
		jit.push(eax);
		jit.mov(eax, reinterpret_cast<std::uintptr_t>(PushRsp));
		jit.call(eax);
		jit.add(esp, sizeof(void*) * 1);

		jit.pop(eax);
	};

	static auto peek_rsp = [](DetourCapsule::AsmJit& jit) {
		// Force align rsp
		jit.mov(eax, 0xFFFFFFF0);
		jit.l_and(esp, eax);
		
		// just in case of stack corruption
		static constexpr std::uint32_t stackSpace = 96;
		jit.sub(esp, stackSpace);

		// 1st param - Rsp
		jit.lea(eax, esp(stackSpace));
		jit.push(eax);
		jit.push(eax); // Keep stack aligned
		jit.mov(eax, reinterpret_cast<std::uintptr_t>(PeekRsp));
		jit.call(eax);

		jit.mov(esp, eax);
	};

	static auto pop_rsp = [](DetourCapsule::AsmJit& jit) {
		// Shadow space is unrequired it was allocated already
		jit.mov(eax, reinterpret_cast<std::uintptr_t>(PopRsp));
		jit.call(eax);
	};

	// Push rbp we're going to be using it and align the stack at the same time
	//_jit.breakpoint();
	//_jit.lea(eax, esp(4));
	//print_rsp(_jit);

	// Variable to store various data, should be 16 bytes aligned
	_jit.sub(esp, local_params_size);

	// Save general purpose registers
	_jit.sub(esp, sizeof(void*) * reg_count);
	for (int i = 0; i < reg_count; i++) {
		_jit.mov(esp(sizeof(void*) * i), reg[i]);
	}
	static_assert((reg_count * sizeof(void*)) % 16 == 0);

	// Bytes offset to get back at where we saved our data
	static constexpr auto reg_start = 0;

	// Restore regular registers
	static auto restore_reg = [](DetourCapsule::AsmJit& jit, std::uint32_t func_param_stack_size) {
		for (int i = 0; i < reg_count; i++) {
			jit.mov(reg[i], esp(reg_start + func_param_stack_size + sizeof(void*) * i));
		}
	};

	static constexpr auto stack_local_data_start = sizeof(void*) * reg_count + reg_start;
	static constexpr auto func_param_stack_start = stack_local_data_start + local_params_size;
	//print_rsp(_jit, func_param_stack_start);

	static auto perform_loop = [](DetourCapsule::AsmJit& jit, std::uintptr_t jit_func_ptr, std::int32_t func_param_stack_size, std::int32_t offset_fn_callback, std::int32_t offset_next_it) {
		auto entry_loop = (std::int32_t)jit.get_outputpos();
		jit.mov(ecx, eax(offset_fn_callback));
		jit.test(ecx, ecx);
		jit.jz(INT32_MAX); auto exit_loop = jit.get_outputpos(); {
			// MAKE PRE/POST CALL
			jit.push(ecx);
			jit.sub(esp, sizeof(void*) * 3);
			push_current_hook(jit, eax(offsetof(LinkedList, hook_ptr)));
			jit.add(esp, sizeof(void*) * 3);
			jit.pop(ecx);
			jit.mov(eax, jit_func_ptr);
			jit.mov(eax, eax());
			jit.add(eax, INT32_MAX);
			auto make_post_call_return = jit.get_outputpos();
			jit.sub(esp, sizeof(void*) * 3);
			jit.push(eax); // Setup return address, basically later in this function
			jit.push(ecx); // PRE/POST Callback address
			//print_rsp(jit, sizeof(void*) * 5 + func_param_stack_size + func_param_stack_start);
			copy_stack(jit, sizeof(void*) * 2, func_param_stack_size, func_param_stack_start + sizeof(void*) * 3);
			restore_reg(jit, func_param_stack_size + sizeof(void*) * 5);
			jit.retn();
			jit.rewrite(make_post_call_return - sizeof(std::uint32_t), jit.get_outputpos());
			peek_rsp(jit);
			//print_rsp(jit, func_param_stack_size + func_param_stack_start);
			pop_current_hook(jit);
			jit.lea(ebp, esp(stack_local_data_start + func_param_stack_size));
			jit.mov(eax, ebp(offsetof(AsmLoopDetails, linked_list_it)));
			jit.mov(ecx, eax(offsetof(LinkedList, hook_action)));
			jit.mov(ecx, ecx());
			jit.l_and(ecx, 0xF);
			// If current_hook-> action > highestaction
			jit.cmp(ecx, ebp(offsetof(AsmLoopDetails, action)));
			jit.jle(INT32_MAX);
			auto if_post_action = jit.get_outputpos(); {
				jit.mov(ebp(offsetof(AsmLoopDetails, action)), ecx);
				jit.mov(ecx, eax(offsetof(LinkedList, fn_make_override_return)));
				jit.mov(ebp(offsetof(AsmLoopDetails, fn_make_return)), ecx);
				jit.mov(ecx, eax(offsetof(LinkedList, override_return_ptr)));
				jit.mov(ebp(offsetof(AsmLoopDetails, override_return_ptr)), ecx);
			}
			jit.rewrite<std::int32_t>(if_post_action - sizeof(std::int32_t), jit.get_outputpos() - if_post_action);
			// Move forward towards the end of linked list
			jit.mov(eax, eax(offset_next_it));
			jit.mov(ebp(offsetof(AsmLoopDetails, linked_list_it)), eax);
			jit.test(eax, eax);
			// Loop
			jit.jnz(INT32_MAX);
			jit.rewrite<std::int32_t>(jit.get_outputpos() - sizeof(std::int32_t), entry_loop - (std::int32_t)jit.get_outputpos());
		}
		jit.rewrite<std::int32_t>(exit_loop - sizeof(std::int32_t), jit.get_outputpos() - exit_loop);
	};

	// Early retrieve callbacks
	_jit.mov(eax, reinterpret_cast<std::uintptr_t>(&_start_callbacks));
	_jit.mov(eax, eax());
	
	// If no callbacks, early return
	_jit.test(eax, eax);
	_jit.jnz(INT32_MAX); auto jnz_pos = _jit.get_outputpos(); {

		// Retrieve the call address
		_jit.mov(eax, reinterpret_cast<std::uintptr_t>(&_original_function));
		_jit.mov(eax, eax());

		// Restore rbp now, and setup call address
		_jit.mov(ebp, esp(stack_local_data_start + local_params_size));
		_jit.mov(esp(stack_local_data_start + local_params_size - sizeof(void*)), eax);

		// Restore every other registers
		restore_reg(_jit, 0);
		_jit.add(esp, stack_local_data_start + local_params_size - sizeof(void*));
		_jit.retn();
	}
	// Write our jump offset
	_jit.rewrite<std::int32_t>(jnz_pos - sizeof(std::int32_t), _jit.get_outputpos() - jnz_pos);

	// Copy the stack over
	std::int32_t func_param_stack_size = (_stack_size > 0) ? _stack_size : STACK_SAFETY_BUFFER;
	_jit.sub(esp, func_param_stack_size);

	// rax still contains the value of this->_start_callbacks
	// rbp is used because it's preserved between calls on x86_64
	_jit.lea(ebp, esp(stack_local_data_start + func_param_stack_size));
	// Default hook action is to ignore
	_jit.mov(ebp(offsetof(AsmLoopDetails, action)), (std::uint32_t)KHook::Action::Ignore);
	// We can set the first hook as overriding, its only gonna be used by actually overriding
	_jit.mov(ecx, eax(offsetof(LinkedList, hook_ptr)));
	// We can also set the override function as the original return because again it will be replaced if actually overriden
	_jit.mov(ecx, eax(offsetof(LinkedList, fn_make_original_return)));
	_jit.mov(ebp(offsetof(AsmLoopDetails, fn_make_return)), ecx);
	// First hook will be made to call original
	_jit.mov(ecx, eax(offsetof(LinkedList, fn_make_call_original)));
	_jit.mov(ebp(offsetof(AsmLoopDetails, fn_make_call_original)), ecx);
	_jit.mov(ecx, eax(offsetof(LinkedList, original_return_ptr)));
	_jit.mov(ebp(offsetof(AsmLoopDetails, original_return_ptr)), ecx);
	// Default init override ptr but it won't be used
	_jit.mov(ecx, eax(offsetof(LinkedList, override_return_ptr)));
	_jit.mov(ebp(offsetof(AsmLoopDetails, override_return_ptr)), ecx);

	// Remember our whole stack
	// We will restore it after each function call
	push_rsp(_jit);

	// Prelude to PRE LOOP
	// Hooks with a pre callback are enqueued at the start of linked list
	_jit.mov(eax, reinterpret_cast<std::uintptr_t>(&_start_callbacks));
	_jit.mov(eax, eax());
	_jit.mov(ebp(offsetof(AsmLoopDetails, linked_list_it)), eax);

	// PRE LOOP
	perform_loop(_jit, reinterpret_cast<std::uintptr_t>(&_jit_func_ptr), func_param_stack_size, offsetof(LinkedList, fn_make_pre), offsetof(LinkedList, next));

	// Call original (maybe)
	// RBP which we have set much earlier still contains our local variables
	// it should have been saved across all calls as per linux & win callconvs

	_jit.mov(eax, reinterpret_cast<std::uintptr_t>(&_original_function));
	_jit.mov(eax, eax());

	_jit.mov(eax, ebp(offsetof(AsmLoopDetails, action)));
	_jit.cmp(eax, (std::int32_t)Action::Supersede);
	_jit.je(INT32_MAX);
	auto if_not_supersede = _jit.get_outputpos(); {
		// MAKE ORIGINAL CALL
		_jit.mov(eax, reinterpret_cast<std::uintptr_t>(&_jit_func_ptr));
		_jit.mov(eax, eax());
		_jit.add(eax, INT32_MAX);
		auto make_pre_call_return = _jit.get_outputpos();
		_jit.sub(esp, sizeof(void*) * 3);
		_jit.push(eax); // Setup return address, basically later in this function
		_jit.mov(eax, ebp(offsetof(AsmLoopDetails, fn_make_call_original)));
		_jit.push(eax); // Call original
		//print_rsp(_jit, sizeof(void*) * 5 + func_param_stack_size + func_param_stack_start);
		copy_stack(_jit, sizeof(void*) * 2, func_param_stack_size, func_param_stack_start + sizeof(void*) * 3);
		restore_reg(_jit, func_param_stack_size + sizeof(void*) * 5);
		//print_rsp(_jit);
		//_jit.breakpoint();
		_jit.retn(); // call
		_jit.rewrite(make_pre_call_return - sizeof(std::uint32_t), _jit.get_outputpos());
		peek_rsp(_jit);
		_jit.lea(ebp, esp(stack_local_data_start + func_param_stack_size));
	}
	_jit.rewrite<std::int32_t>(if_not_supersede - sizeof(std::int32_t), _jit.get_outputpos() - if_not_supersede);

	// Prelude to POST LOOP
	// Hooks with a pre callback are enqueued at the start of linked list
	_jit.mov(eax, reinterpret_cast<std::uintptr_t>(&_end_callbacks));
	_jit.mov(eax, eax());
	_jit.mov(ebp(offsetof(AsmLoopDetails, linked_list_it)), eax);

	// POST LOOP
	perform_loop(_jit, reinterpret_cast<std::uintptr_t>(&_jit_func_ptr), func_param_stack_size, offsetof(LinkedList, fn_make_post), offsetof(LinkedList, prev));

	// EXIT HOOK
	// Free our fake param stack
	_jit.add(esp, func_param_stack_size);

	pop_rsp(_jit);

	// TODO TODO TODO TODO TODO
	// SETUP RETURN PTRS HERE AND SHARED MUTEX

	// Retrieve the call address
	_jit.mov(eax, ebp(offsetof(AsmLoopDetails, fn_make_return)));

	// Restore rbp now, setup call address
	_jit.mov(ebp, esp(stack_local_data_start + local_params_size));
	_jit.mov(esp(stack_local_data_start + local_params_size - sizeof(void*)), eax);

	// Restore every other registers
	restore_reg(_jit, 0);
	_jit.add(esp, stack_local_data_start + local_params_size - sizeof(void*));

	print_entry_rsp(_jit, false);

	// fn_make_return will pop our override & original ptr
	// this also re-aligns the stack on 16 bytes
	_jit.retn();
#endif
	_jit.SetRE();
	void* bridge = _jit;
	_jit_func_ptr = reinterpret_cast<std::uintptr_t>(bridge);

	auto result = safetyhook::InlineHook::create(detour_address, bridge);
	if (result) {
		_safetyhook = std::move(result.value());
		_original_function = reinterpret_cast<std::uintptr_t>(_safetyhook.original<void*>());
	}
}

class EmptyClass {};
DetourCapsule::~DetourCapsule() {
	_in_deletion = true;
	// Lock and unlock mutex, ensuring any other thread is done with this object
	// Setting _in_deletion to true previously, will prevent more logic from being ran
	_detour_mutex.lock();

	// Iterate through all existing hooks and kill them
	for (auto& callback : _callbacks) {
		auto& hook = callback.second;
		auto mfp = BuildMFP<EmptyClass, void, HookID_t>(reinterpret_cast<void*>(hook->hook_fn_remove));
		(((EmptyClass*)(hook->hook_ptr))->*mfp)(callback.first);
	}
	_callbacks.clear();
	_start_callbacks = nullptr;
	_end_callbacks = nullptr;

	_detour_mutex.unlock();
}

bool DetourCapsule::InsertHook(HookID_t id, const DetourCapsule::InsertHookDetails& details) {
	if (_in_deletion) {
		// We're being deleted it doesn't matter, abort
		return true;
	}

	//printf("_detour_mutex -- %d - try lock\n", gettid());
	if (!_detour_mutex.try_lock()) {
		// Don't deadlock the other threads because we can't insert
		return false;
	}
	//printf("_detour_mutex -- %d - lock\n", gettid());
	if (details.fn_make_post == 0) {
		// Insert at start, it doesn't matter
		_callbacks[id] = std::make_unique<LinkedList>(nullptr, _start_callbacks);
		if (_start_callbacks == nullptr) {
			_end_callbacks = _start_callbacks = _callbacks[id].get();
		} else {
			auto inserted = _callbacks[id].get();
			_start_callbacks = inserted;
		}
	} else if (details.fn_make_pre == 0) {
		// Insert at the end, it doesn't matter
		_callbacks[id] = std::make_unique<LinkedList>(_end_callbacks, nullptr);
		if (_start_callbacks == nullptr) {
			_end_callbacks = _start_callbacks = _callbacks[id].get();
		} else {
			auto inserted = _callbacks[id].get();
			_end_callbacks = inserted;
		}
	} else {
		// Okay iterate through the list and add it in the middle
		LinkedList* prev = nullptr;
		LinkedList* next = nullptr;

		LinkedList* curr = _start_callbacks;
		while (curr && curr->fn_make_post == 0 && curr->next) {
			curr = curr->next;
		}
		_callbacks[id] = std::make_unique<LinkedList>((curr) ? curr->prev : nullptr, curr);
		auto inserted = _callbacks[id].get();
		if (curr == _start_callbacks) {
			if (_end_callbacks == nullptr) {
				_end_callbacks = inserted;
			}
			_start_callbacks = inserted;
		}
	}
	auto inserted = _callbacks[id].get();
	inserted->CopyDetails(details);
	_detour_mutex.unlock();
	return true;
}

void DetourCapsule::RemoveHook(HookID_t id) {
	if (_in_deletion) {
		// We're being deleted it doesn't matter, abort
		return;
	}

	std::lock_guard guard(_detour_mutex);

	auto it = _callbacks.find(id);
	if (it != _callbacks.end()) {
		auto hook = it->second.get();
		if (hook == _start_callbacks) {
			_start_callbacks = _start_callbacks->next;
		}
		if (hook == _end_callbacks) {
			_end_callbacks = _end_callbacks->prev;
		}

		auto mfp = BuildMFP<EmptyClass, void, HookID_t>(reinterpret_cast<void*>(hook->hook_fn_remove));
		(((EmptyClass*)(hook->hook_ptr))->*mfp)(id);
	}
}

std::mutex g_hook_id_mutex;
HookID_t g_lastest_hook_id = 0;

std::shared_mutex g_hooks_detour_mutex;
std::unordered_map<void*, std::unique_ptr<DetourCapsule>> g_hooks_detour;
std::shared_mutex g_associated_hooks_mutex;
std::unordered_map<HookID_t, DetourCapsule*> g_associated_hooks;
std::mutex g_insert_hooks_mutex;
std::list<std::pair<HookID_t, DetourCapsule::InsertHookDetails>> g_insert_hooks;
std::mutex g_delete_hooks_mutex;
std::unordered_set<HookID_t> g_delete_hooks;

bool __InsertHook_Sync(HookID_t id, const DetourCapsule::InsertHookDetails& details) {
	//printf("__InsertHook_Sync -- %d\n", gettid());
	g_associated_hooks_mutex.lock_shared();
	auto it = g_associated_hooks.find(id);
	if (it == g_associated_hooks.end()) {
		g_associated_hooks_mutex.unlock_shared();
		return true;
	}
	//printf("__InsertHook_Sync -- %d -- InsertHook\n", gettid());
	bool ret = it->second->InsertHook(id, details);
	//printf("__InsertHook_Sync -- %d -- InsertHook -- over\n", gettid());
	g_associated_hooks_mutex.unlock_shared();
	return ret;
}

void __RemoveHook_Sync(HookID_t id) {
	std::lock_guard associated_guard(g_associated_hooks_mutex);
	auto it = g_associated_hooks.find(id);
	if (it == g_associated_hooks.end()) {
		return;
	}

	it->second->RemoveHook(id);

	g_associated_hooks.erase(id);
}

// Worker thread that insert/deletes hook
bool g_TerminateWorker = false;

std::thread g_InsertThread([]{
	while (!g_TerminateWorker) {
		g_insert_hooks_mutex.lock();
		if (g_insert_hooks.begin() != g_insert_hooks.end()) {
			auto it = g_insert_hooks.begin();
			auto id = it->first;
			auto details = it->second;
			g_insert_hooks.erase(it);
	
			// Let other threads add more hooks to insert
			g_insert_hooks_mutex.unlock();
	
			bool ret = __InsertHook_Sync(id, details);
	
			// Relock thread for loop condition
			g_insert_hooks_mutex.lock();

			// Insert failed, try again a little later
			if (!ret) {
				g_insert_hooks.push_back(std::make_pair(id, details));
			}
		}
		g_insert_hooks_mutex.unlock();
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
});

std::thread g_DeleteThread([]{
	while (!g_TerminateWorker) {
		g_delete_hooks_mutex.lock();
		while (g_delete_hooks.begin() != g_delete_hooks.end()) {
			auto it = g_delete_hooks.begin();
			HookID_t id = *it;
			g_delete_hooks.erase(it);

			// Let other threads add more hooks to delete
			g_delete_hooks_mutex.unlock();

			__RemoveHook_Sync(id);

			// Relock thread for loop condition
			g_delete_hooks_mutex.lock();
		}
		g_delete_hooks_mutex.unlock();
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
});

KHOOK_API HookID_t SetupHook(
	void* function,
	void* hookPtr,
	void* removedFunctionMFP,
	::KHook::Action* hookAction,
	void* overrideReturnPtr,
	void* originalReturnPtr,
	void* preMFP,
	void* postMFP,
	void* returnOverrideMFP,
	void* returnOriginalMFP,
	void* callOriginalMFP,
	bool async
) {
	DetourCapsule::InsertHookDetails details;
	details.hook_ptr = reinterpret_cast<std::uintptr_t>(hookPtr);
	details.hook_action = hookAction;
	details.hook_fn_remove = reinterpret_cast<std::uintptr_t>(removedFunctionMFP);

	details.fn_make_pre = reinterpret_cast<std::uintptr_t>(preMFP);
	details.fn_make_post = reinterpret_cast<std::uintptr_t>(postMFP);

	details.fn_make_override_return = reinterpret_cast<std::uintptr_t>(returnOverrideMFP);
	details.fn_make_original_return = reinterpret_cast<std::uintptr_t>(returnOriginalMFP);
	details.fn_make_call_original = reinterpret_cast<std::uintptr_t>(callOriginalMFP);

	details.override_return_ptr = reinterpret_cast<std::uintptr_t>(overrideReturnPtr);
	details.original_return_ptr = reinterpret_cast<std::uintptr_t>(originalReturnPtr);
	//printf("Origi: %p\n", details.original_return_ptr);

	g_hooks_detour_mutex.lock_shared();
	auto it = g_hooks_detour.find(function);
	if (it == g_hooks_detour.end()) {
		g_hooks_detour_mutex.unlock_shared();

		//printf("g_hooks_detour_mutex -- try lock\n");
		g_hooks_detour_mutex.lock();
		//printf("g_hooks_detour_mutex -- lock\n");
		auto insert = g_hooks_detour.insert_or_assign(function, std::make_unique<DetourCapsule>(function));
		g_hooks_detour_mutex.unlock();
		//printf("g_hooks_detour_mutex -- unlock\n");

		if (!insert.second) {
			//printf("setup failed\n");
			return INVALID_HOOK;
		}
		// If we've just inserted that new detour
		// Sync insert the hook as well
		async = false;
		//printf("new hook insert!\n");
	} else {
		g_hooks_detour_mutex.unlock_shared();
	}

	//printf("insert hook %d\n", async);
	g_hooks_detour_mutex.lock_shared();
	it = g_hooks_detour.find(function);
	if (it != g_hooks_detour.end()) {

		HookID_t id = 0;
		{
			std::lock_guard generator(g_hook_id_mutex);
			//printf("lock hook id\n");
			id = g_lastest_hook_id++;
		}

		// Associate hook with detour
		{
			//printf("trylock associated hook\n");
			std::lock_guard associated_guard(g_associated_hooks_mutex);
			//printf("lock associated hook\n");
			g_associated_hooks[id] = it->second.get();
		}

		if (!async) {
			if (__InsertHook_Sync(id, details) == false) {
				// Should be impossible to fail... but if it does, async add
				async = true;
			}
		}

		if (async) {
			std::lock_guard insert_guard(g_insert_hooks_mutex);
			g_insert_hooks.push_back(std::make_pair(id, details));
		}

		g_hooks_detour_mutex.unlock_shared();
		//printf("setup success\n");
		return id;
	}

	g_hooks_detour_mutex.unlock_shared();
	//printf("setup full failure\n");
	return INVALID_HOOK;
}

KHOOK_API void RemoveHook(
	HookID_t id,
	bool async
) {
	{
		std::lock_guard guard(g_insert_hooks_mutex);
		for (auto it = g_insert_hooks.begin(); it != g_insert_hooks.end(); it++) {
			if ((*it).first != id) {
				continue;
			}

			// Hook not yet been inserted, remove it right now
			g_insert_hooks.erase(it);

			// Disassociate from the detour
			{
				std::lock_guard guard_associated(g_associated_hooks_mutex);
				g_associated_hooks.erase(id);
			}

			// Invoke remove callback
			auto& hook = it->second;
			auto mfp = BuildMFP<EmptyClass, void, HookID_t>(reinterpret_cast<void*>(hook.hook_fn_remove));
			(((EmptyClass*)(hook.hook_ptr))->*mfp)(id);
			return;
		}
	}

	if (async) {
		g_associated_hooks_mutex.lock_shared();
		// If not associated still, early return
		auto it = g_associated_hooks.find(id);
		if (it == g_associated_hooks.end()) {
			g_associated_hooks_mutex.unlock_shared();
			return;
		}

		g_delete_hooks_mutex.lock();
		g_delete_hooks.insert(id);
		g_delete_hooks_mutex.unlock();

		g_associated_hooks_mutex.unlock_shared();
	} else {
		__RemoveHook_Sync(id);
	}
}

KHOOK_API void Shutdown(
) {
	g_hooks_detour_mutex.lock();
	g_associated_hooks_mutex.lock();
	g_associated_hooks.clear();
	g_hooks_detour.clear();
	g_hooks_detour_mutex.unlock();
	g_associated_hooks_mutex.unlock();

	g_TerminateWorker = true;
	g_InsertThread.join();
	g_DeleteThread.join();
}

KHOOK_API void* GetOriginal(void* function) {
	std::shared_lock guard(g_hooks_detour_mutex);
	auto it = g_hooks_detour.find(function);
	if (it != g_hooks_detour.end()) {
		return (*it).second->GetOriginal();
	}
	// No associated detours, so this is already original function
	return function;
}

}