#include "detour.hpp"

#include <stack>
#include <iostream>

#define KHOOK_X64

namespace KHook {

#define STACK_SAFETY_BUFFER 112

#ifdef WIN32
#define LINUX_ONLY(x)
#define WIN_ONLY(x) x
#else
#define LINUX_ONLY(x) x
#define WIN_ONLY(x)
#endif

template<typename T, typename Ret, typename... Args>
union MFP {
	MFP(Ret (T::*func)(Args...)) : mfp(func) {
#ifdef WIN32
#else
		this->details.adjustor = 0;
#endif
	}
	Ret (T::*mfp)(Args...);
	struct {
		void *addr;
#ifdef WIN32
#else
		intptr_t adjustor;
#endif
	} details;

	std::uintptr_t GetAddress() {
		return reinterpret_cast<std::uintptr_t>(this->details.addr);
	}
};

static thread_local std::stack<void*> g_current_hook;
static void PushPopCurrentHook(void* current_hook, bool push) {
	if (push) {
		g_current_hook.push(current_hook);
	} else {
		g_current_hook.pop();
	}
}

KHOOK_API void* GetCurrent() {
	return g_current_hook.top();
}

static thread_local std::stack<std::pair<void*, void*>> g_hook_fn_original_return;
static void PushHookOriginalReturn(void* original_return_ptr, void* fn_original_function_ptr) {
	g_hook_fn_original_return.push(std::make_pair(original_return_ptr, fn_original_function_ptr));
}

static thread_local std::stack<void*> g_hook_override_return;
static void PushHookOverrideReturn(void* override_return) {
	g_hook_override_return.push(override_return);
}

KHOOK_API void* GetOriginalFunction() {
	return g_hook_fn_original_return.top().second;
}

KHOOK_API void* GetOriginalValuePtr(bool pop) {
	auto ret = g_hook_fn_original_return.top().first;
	if (pop) {
		g_hook_fn_original_return.pop();
		g_hook_override_return.pop();
	}
	return ret;
}

KHOOK_API void* GetOverrideValuePtr(bool pop) {
	auto ret = g_hook_override_return.top();
	if (pop) {
		g_hook_fn_original_return.pop();
		g_hook_override_return.pop();
	}
	return ret;
}

static thread_local std::stack<std::uintptr_t> rsp_values;
static void PushRsp(std::uintptr_t rsp) {
	rsp_values.push(rsp);
}

static std::uintptr_t PeekRsp(std::uintptr_t rsp) {
	auto internal_rsp = rsp_values.top();
	assert((internal_rsp + STACK_SAFETY_BUFFER) > rsp);
	return internal_rsp;
}

static void PopRsp() {
	rsp_values.pop();
}

static void RecursiveLockUnlockShared(std::shared_mutex* mutex, bool lock) {
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
			assert(false);
		}

		it->second--;
		// No more locks, so unlock
		if (it->second == 0) {
			mutex->unlock_shared();
		}
	}
}

static void PrintRSP(std::uintptr_t rsp) {
	std::cout << "RSP : 0x" << std::hex << rsp << std::endl;
	for (int i = 0; i < 4; i++) {
		std::cout << "(RSP + 0x" << i * 8 << ") : 0x" << std::hex << *(std::uintptr_t*)(((std::uint8_t*)rsp) + i * 8) << std::endl;
	}
}

struct AsmLoopDetails {
	// Current iterated hook
	std::uintptr_t linked_list_it;
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
	static_assert(sizeof(std::uintptr_t) == sizeof(void*));
	static_assert(sizeof(std::uint32_t) >= sizeof(KHook::Action));
};

void copy_stack(DetourCapsule::AsmJit& jit, std::int32_t offset, std::int32_t stack_size, std::int32_t stack_start) {
	using namespace Asm;

	jit.push(rdi);
	jit.push(rsi);
	jit.push(rcx);

	jit.mov(rcx, stack_size);
	jit.lea(rdi, rsp(3 * 8 + offset));
	jit.lea(rsi, rsp(3 * 8 + stack_size + stack_start + offset));

	jit.rep_movs_bytes();

	jit.pop(rcx);
	jit.pop(rsi);
	jit.pop(rdi);
}

DetourCapsule::DetourCapsule(void* detour_address) :
	_terminate_edit_thread(false),
	_edit_thread([this]() { this->_EditThread(); }),
	_start_callbacks(nullptr),
	_end_callbacks(nullptr),
	_jit_func_ptr(0),
	_original_function(0),
	_stack_size(STACK_SAFETY_BUFFER) {
	static constexpr auto local_params_size = sizeof(AsmLoopDetails);
	static_assert(local_params_size % 16 == 0);
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

	static auto print_rsp = [](DetourCapsule::AsmJit& jit) {
		WIN_ONLY(jit.sub(rsp, 32));

		jit.push(rdi);
		jit.push(rcx);
		jit.push(rax);
		jit.push(rax);
		
		LINUX_ONLY(jit.lea(rdi, rsp(4 * 8)));
		WIN_ONLY(jit.lea(rcx, rsp(32 + 4 * 8)));

		jit.mov(rax, reinterpret_cast<std::uintptr_t>(PrintRSP));
		jit.call(rax);

		jit.pop(rax);
		jit.pop(rax);
		jit.pop(rcx);
		jit.pop(rdi);

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

	static auto push_original_return_ptr = [](DetourCapsule::AsmJit& jit, x86_64_RegRm original_return_ptr, x86_64_Reg fn_original_function_ptr) {
		WIN_ONLY(jit.sub(rsp, 32));
		// 1st param - Original return ptr
		LINUX_ONLY(jit.mov(rdi, original_return_ptr));
		WIN_ONLY(jit.mov(rcx, original_return_ptr));
		// 2nd param - Fn original return ptr
		LINUX_ONLY(jit.mov(rsi, fn_original_function_ptr));
		WIN_ONLY(jit.mov(rdx, fn_original_function_ptr));
		jit.mov(rax, reinterpret_cast<std::uintptr_t>(PushHookOriginalReturn));
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

	static auto push_override_return_ptr = [](DetourCapsule::AsmJit& jit, x86_64_RegRm override_return_ptr) {
		// Shadow space is unrequired it was allocated already
		// 1st param - Original return ptr
		LINUX_ONLY(jit.mov(rdi, override_return_ptr));
		WIN_ONLY(jit.mov(rcx, override_return_ptr));

		jit.mov(rax, reinterpret_cast<std::uintptr_t>(PushHookOverrideReturn));
		jit.call(rax);
	};

	static auto pop_rsp = [](DetourCapsule::AsmJit& jit) {
		// Shadow space is unrequired it was allocated already
		jit.mov(rax, reinterpret_cast<std::uintptr_t>(PopRsp));
		jit.call(rax);
	};

	static auto lock_shared_mutex = [](DetourCapsule::AsmJit& jit, std::shared_mutex* mutex) {
		// Shadow space is unrequired it was allocated already
		// 1st param - Mutex
		LINUX_ONLY(jit.mov(rdi, reinterpret_cast<std::uintptr_t>(mutex)));
		WIN_ONLY(jit.mov(rcx, reinterpret_cast<std::uintptr_t>(mutex)));
		// 2nd param - Lock
		LINUX_ONLY(jit.mov(rsi, true));
		WIN_ONLY(jit.mov(rdx, true));
		jit.mov(rax, reinterpret_cast<std::uintptr_t>(RecursiveLockUnlockShared));
		jit.call(rax);
	};

	static auto unlock_shared_mutex = [](DetourCapsule::AsmJit& jit, std::shared_mutex* mutex) {
		// Shadow space is unrequired it was allocated already
		// 1st param - Mutex
		LINUX_ONLY(jit.mov(rdi, reinterpret_cast<std::uintptr_t>(mutex)));
		WIN_ONLY(jit.mov(rcx, reinterpret_cast<std::uintptr_t>(mutex)));
		// 2nd param - Lock
		LINUX_ONLY(jit.mov(rsi, false));
		WIN_ONLY(jit.mov(rdx, false));
		jit.mov(rax, reinterpret_cast<std::uintptr_t>(RecursiveLockUnlockShared));
		jit.call(rax);
	};

#ifdef WIN32
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
	// Push rbp we're going to be using it and align the stack at the same time
	_jit.push(rbp);
	// RSP is aligned now AND MUST STAY ALIGNED

	// Variable to store various data, should be 16 bytes aligned
	_jit.sub(rsp, local_params_size);

	// Save general purpose registers
	for (int i = 0; i < reg_count; i++) {
		_jit.push(reg[i]);
	}
	// Save floating point registers
	_jit.sub(rsp, 16 * float_reg_count);
	for (int i = 0; i < float_reg_count; i++) {
		_jit.movsd(rsp(16 * i), float_reg[i]);
	}

	// Introduce shadow space
	WIN_ONLY(_jit.sub(rsp, 32));
	// Bytes offset to get back at where we saved our data
	static constexpr auto reg_start = WIN_ONLY(32) LINUX_ONLY(0);

	// Restore floating point registers
	static auto restore_float_regs = [](DetourCapsule::AsmJit& jit, std::uint32_t func_param_stack_size) {
		for (int i = 0; i < float_reg_count; i++) {
			jit.movsd(float_reg[i], rsp(reg_start + func_param_stack_size + (16 * (float_reg_count - 1)) - (16 * i)));
		}
	};

	// Restore regular registers
	static auto restore_reg = [](DetourCapsule::AsmJit& jit, std::uint32_t func_param_stack_size) {
		for (int i = 0; i < reg_count; i++) {
			jit.mov(reg[i], rsp(reg_start + func_param_stack_size + (16 * float_reg_count) + (8 * (reg_count - 1)) - (8 * i)));
		}
	};

	static constexpr auto stack_local_data_start = 16 * float_reg_count + 8 * reg_count + reg_start;
	static constexpr auto func_param_stack_start = stack_local_data_start + local_params_size + 8 /* push rbp */;

	// Begin thread safety
	lock_shared_mutex(_jit, &_detour_mutex);

	// Early retrieve callbacks
	_jit.mov(rax, reinterpret_cast<std::uintptr_t>(&_start_callbacks));
	_jit.mov(rax, rax());
	
	// If no callbacks, early return
	_jit.test(rax, rax);
	_jit.jnz(INT32_MAX); auto jnz_pos = _jit.get_outputpos(); {
		// Unlock mutex
		unlock_shared_mutex(_jit, &_detour_mutex);

		// Retrieve the call address
		_jit.mov(rax, reinterpret_cast<std::uintptr_t>(&_original_function));
		_jit.mov(rax, rax());

		// Restore rbp now, and setup call address
		_jit.mov(rbp, rsp(stack_local_data_start + local_params_size));
		_jit.mov(rsp(stack_local_data_start + local_params_size), rax);

		// Restore every other registers
		restore_float_regs(_jit, 0);
		restore_reg(_jit, 0);
		_jit.add(rsp, stack_local_data_start + local_params_size);
		_jit.retn();
	}
	// Write our jump offset
	_jit.rewrite<std::int32_t>(jnz_pos - sizeof(std::int32_t), _jit.get_outputpos() - jnz_pos);

	// Copy the stack over
	std::int32_t func_param_stack_size = (_stack_size != 0) ? _stack_size : STACK_SAFETY_BUFFER;
	_jit.sub(rsp, func_param_stack_size);

	// rax still contains the value of this->_start_callbacks
	// rbp is used because it's preserved between calls on x86_64
	_jit.lea(rbp, rsp(stack_local_data_start + func_param_stack_size));
	// Default hook action is to ignore
	_jit.mov(rbp(offsetof(AsmLoopDetails, action)), (std::uint32_t)KHook::Action::Ignore);
	// We can set the first hook as overriding, its only gonna be used by actually overriding
	_jit.mov(r8, rax(offsetof(LinkedList, hook_ptr)));
	// We can also set the override function as the original return because again it will be replaced if actually overriden
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

	// Remember our whole stack
	// We will restore it after each function call
	push_rsp(_jit);

	/*_jit.mov(rax, reinterpret_cast<std::uintptr_t>(&_start_callbacks));
	_jit.mov(rax, rax());

	_jit.push(rax(offsetof(LinkedList, fn_make_call_original)));
	_jit.push(rax(offsetof(LinkedList, fn_make_pre)));
	print_rsp(_jit);
	_jit.pop(rax);
	_jit.pop(rax);*/

	// Prelude to PRE LOOP
	// Hooks with a pre callback are enqueued at the start of linked list
	_jit.mov(rax, reinterpret_cast<std::uintptr_t>(&_start_callbacks));
	_jit.mov(rax, rax());
	_jit.mov(rbp(offsetof(AsmLoopDetails, linked_list_it)), rax);

	// PRE LOOP
	auto entry_pre_loop = (std::int32_t)_jit.get_outputpos();
	_jit.mov(r8, rax(offsetof(LinkedList, fn_make_pre)));
	_jit.test(r8, r8);
	_jit.jz(INT32_MAX); auto exit_pre_loop = _jit.get_outputpos(); {
		// MAKE PRE CALL
		_jit.push(r8);
		_jit.push(r8);
		push_current_hook(_jit, rax(offsetof(LinkedList, hook_ptr)));
		_jit.pop(r8);
		_jit.pop(r8);
		_jit.mov(rax, reinterpret_cast<std::uintptr_t>(&_jit_func_ptr));
		_jit.mov(rax, rax());
		_jit.add(rax, INT32_MAX);
		auto make_pre_call_return = _jit.get_outputpos();
		_jit.push(rax); // Setup return address, basically later in this function
		_jit.push(r8); // PRE Callback address
		copy_stack(_jit, 8 * 2, func_param_stack_size, func_param_stack_start);
		restore_float_regs(_jit, func_param_stack_size + 8 * 2);
		restore_reg(_jit, func_param_stack_size + 8 * 2);
		_jit.retn();
		_jit.rewrite(make_pre_call_return - sizeof(std::uint32_t), _jit.get_outputpos());
		peek_rsp(_jit);
		pop_current_hook(_jit);
		_jit.mov(rax, rbp(offsetof(AsmLoopDetails, linked_list_it)));
		_jit.mov(r8, rax(offsetof(LinkedList, hook_action)));
		_jit.mov(r8, r8());
		_jit.l_and(r8, 0xF);
		// If current_hook-> action > highestaction
		_jit.cmp(r8, rbp(offsetof(AsmLoopDetails, action)));
		_jit.jle(INT32_MAX);
		auto if_pre_action = _jit.get_outputpos(); {
			_jit.mov(rbp(offsetof(AsmLoopDetails, action)), r8);
			_jit.mov(r8, rax(offsetof(LinkedList, fn_make_override_return)));
			_jit.mov(rbp(offsetof(AsmLoopDetails, fn_make_return)), r8);
			_jit.mov(r8, rax(offsetof(LinkedList, override_return_ptr)));
			_jit.mov(rbp(offsetof(AsmLoopDetails, override_return_ptr)), r8);
		}
		_jit.rewrite<std::int32_t>(if_pre_action - sizeof(std::int32_t), _jit.get_outputpos() - if_pre_action);
		// Move forward towards the end of linked list
		_jit.mov(rax, rax(offsetof(LinkedList, next)));
		_jit.mov(rbp(offsetof(AsmLoopDetails, linked_list_it)), rax);
		_jit.test(rax, rax);

		// Loop
		_jit.jnz(INT32_MAX);
		_jit.rewrite<std::int32_t>(_jit.get_outputpos() - sizeof(std::int32_t), entry_pre_loop - (std::int32_t)_jit.get_outputpos());
	}
	_jit.rewrite<std::int32_t>(exit_pre_loop - sizeof(std::int32_t), _jit.get_outputpos() - exit_pre_loop);

	// Call original (maybe)
	// RBP which we have set much earlier still contains our local variables
	// it should have been saved across all calls as per linux & win callconvs

	_jit.mov(rax, reinterpret_cast<std::uintptr_t>(&_original_function));
	_jit.mov(rax, rax());

	push_original_return_ptr(_jit, rbp(offsetof(AsmLoopDetails, original_return_ptr)), rax);

	_jit.mov(rax, rbp(offsetof(AsmLoopDetails, action)));
	_jit.cmp(rax, (std::int32_t)Action::Supercede);
	_jit.je(INT32_MAX);
	auto if_not_supercede = _jit.get_outputpos(); {
		// MAKE ORIGINAL CALL
		_jit.mov(rax, reinterpret_cast<std::uintptr_t>(&_jit_func_ptr));
		_jit.mov(rax, rax());
		_jit.add(rax, INT32_MAX);
		auto make_pre_call_return = _jit.get_outputpos();
		_jit.push(rax); // Setup return address, basically later in this function
		_jit.mov(rax, rbp(offsetof(AsmLoopDetails, fn_make_call_original)));
		_jit.push(rax); // Call original
		copy_stack(_jit, 8 * 2, func_param_stack_size, func_param_stack_start);
		restore_float_regs(_jit, func_param_stack_size + 8 * 2);
		restore_reg(_jit, func_param_stack_size + 8 * 2);
		//print_rsp(_jit);
		//_jit.breakpoint();
		_jit.retn();
		_jit.rewrite(make_pre_call_return - sizeof(std::uint32_t), _jit.get_outputpos());
		peek_rsp(_jit);
	}
	_jit.rewrite<std::int32_t>(if_not_supercede - sizeof(std::int32_t), _jit.get_outputpos() - if_not_supercede);

	// Prelude to POST LOOP
	// Hooks with a pre callback are enqueued at the start of linked list
	_jit.mov(rax, reinterpret_cast<std::uintptr_t>(&_end_callbacks));
	_jit.mov(rax, rax());
	_jit.mov(rbp(offsetof(AsmLoopDetails, linked_list_it)), rax);

	// POST LOOP
	auto entry_post_loop = (std::int32_t)_jit.get_outputpos();
	_jit.mov(r8, rax(offsetof(LinkedList, fn_make_post)));
	_jit.test(r8, r8);
	_jit.jz(INT32_MAX); auto exit_post_loop = _jit.get_outputpos(); {
		// MAKE POST CALL
		_jit.push(r8);
		_jit.push(r8);
		push_current_hook(_jit, rax(offsetof(LinkedList, hook_ptr)));
		_jit.pop(r8);
		_jit.pop(r8);
		_jit.mov(rax, reinterpret_cast<std::uintptr_t>(&_jit_func_ptr));
		_jit.mov(rax, rax());
		_jit.add(rax, INT32_MAX);
		auto make_post_call_return = _jit.get_outputpos();
		_jit.push(rax); // Setup return address, basically later in this function
		_jit.push(r8); // POST Callback address
		copy_stack(_jit, 8 * 2, func_param_stack_size, func_param_stack_start);
		restore_float_regs(_jit, func_param_stack_size + 8 * 2);
		restore_reg(_jit, func_param_stack_size + 8 * 2);
		_jit.retn();
		_jit.rewrite(make_post_call_return - sizeof(std::uint32_t), _jit.get_outputpos());
		peek_rsp(_jit);
		pop_current_hook(_jit);
		_jit.mov(rax, rbp(offsetof(AsmLoopDetails, linked_list_it)));
		_jit.mov(r8, rax(offsetof(LinkedList, hook_action)));
		_jit.mov(r8, r8());
		_jit.l_and(r8, 0xF);
		// If current_hook-> action > highestaction
		_jit.cmp(r8, rbp(offsetof(AsmLoopDetails, action)));
		_jit.jle(INT32_MAX);
		auto if_post_action = _jit.get_outputpos(); {
			_jit.mov(rbp(offsetof(AsmLoopDetails, action)), r8);
			_jit.mov(r8, rax(offsetof(LinkedList, fn_make_override_return)));
			_jit.mov(rbp(offsetof(AsmLoopDetails, fn_make_return)), r8);
			_jit.mov(r8, rax(offsetof(LinkedList, override_return_ptr)));
			_jit.mov(rbp(offsetof(AsmLoopDetails, override_return_ptr)), r8);
		}
		_jit.rewrite<std::int32_t>(if_post_action - sizeof(std::int32_t), _jit.get_outputpos() - if_post_action);
		// Move forward towards the end of linked list
		_jit.mov(rax, rax(offsetof(LinkedList, prev)));
		_jit.mov(rbp(offsetof(AsmLoopDetails, linked_list_it)), rax);
		_jit.test(rax, rax);
		// Loop
		_jit.jnz(entry_post_loop - (std::int32_t)_jit.get_outputpos());
	}
	_jit.rewrite<std::int32_t>(exit_post_loop - sizeof(std::int32_t), _jit.get_outputpos() - exit_post_loop);

	// EXIT HOOK
	// Free our fake param stack
	_jit.add(rsp, func_param_stack_size);

	push_override_return_ptr(_jit, rbp(offsetof(AsmLoopDetails, override_return_ptr)));
	pop_rsp(_jit);

	// Unlock mutex
	unlock_shared_mutex(_jit, &_detour_mutex);

	// Retrieve the call address
	_jit.mov(rax, rbp(offsetof(AsmLoopDetails, fn_make_return)));

	// Restore rbp now, setup call address
	_jit.mov(rbp, rsp(stack_local_data_start + local_params_size));
	_jit.mov(rsp(stack_local_data_start + local_params_size), rax);

	// Restore every other registers
	restore_float_regs(_jit, 0);
	restore_reg(_jit, 0);
	_jit.add(rsp, stack_local_data_start + local_params_size);

	// fn_make_return will pop our override & original ptr
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

DetourCapsule::~DetourCapsule() {
}

std::mutex g_hooks_mutex;
std::unordered_map<void*, std::unique_ptr<DetourCapsule>> g_hooks_detour;
std::unordered_map<HookID_t, DetourCapsule*> g_associated_hooks;

void DetourCapsule::InsertHook(HookID_t id, DetourCapsule::InsertHookDetails details, bool async) {
	g_associated_hooks[id] = this;

	if (!async) {
		_detour_mutex.lock();

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
				if (curr == _end_callbacks) {
					_end_callbacks = inserted;
				}
				_start_callbacks = inserted;
			}
		}
	
		auto inserted = _callbacks[id].get();
		inserted->CopyDetails(details);
	
		_detour_mutex.unlock();
	} else {
		_async_mutex.lock();
		_insert_hooks.insert_or_assign(id, details);
		_async_mutex.unlock();
	}
}

void DetourCapsule::RemoveHook(HookID_t id, bool async) {
	if (!async) {
		_detour_mutex.lock();
		g_associated_hooks.erase(id);
		_delete_hooks.erase(id);
		_insert_hooks.erase(id);

		auto it = _callbacks.find(id);
		if (it != _callbacks.end()) {
			auto hook = it->second.get();
			if (hook == _start_callbacks) {
				_start_callbacks = _start_callbacks->next;
			}
			if (hook == _end_callbacks) {
				_end_callbacks = _end_callbacks->prev;
			}
			// TO-DO call remove callback here
			_callbacks.erase(it);
		}
	
		_detour_mutex.unlock();
	} else {
		_async_mutex.lock();
		// Are we still currently inserting that hook ?
		// If so early release and call it a day
		if (_insert_hooks.find(id) != _insert_hooks.end()) {
			g_associated_hooks.erase(id);
			// TO-DO call remove callback here
			_insert_hooks.erase(id);
		} else {
			_delete_hooks.insert(id);
		}
		_async_mutex.unlock();
	}
}

void DetourCapsule::_EditThread() {
	while (!_terminate_edit_thread) {
		std::unique_lock lock(_async_mutex);
		_cv_edit.wait(lock);

		std::unique_lock lock2(g_hooks_mutex);
		// Now for each hook add or remove them synchronously
		for (auto insert_hook : _insert_hooks) {
			InsertHook(insert_hook.first, insert_hook.second, false);
		}
		for (auto delete_hook : _delete_hooks) {
			RemoveHook(delete_hook, false);
		}

		_insert_hooks.clear();
		_delete_hooks.clear();
	}
}

HookID_t g_lastest_hook_id = 0;

KHOOK_API HookID_t SetupHook(void* function,
	void* hookPtr,
	void* removedFunctionMFP,
	Action* hookAction,
	void* overrideReturnPtr,
	void* originalReturnPtr,
	void* preMFP,
	void* postMFP,
	void* returnOverrideMFP,
	void* returnOriginalMFP,
	void* callOriginalMFP,
	bool async) {
	std::lock_guard guard(g_hooks_mutex);

	DetourCapsule::InsertHookDetails details;
	details.hook_ptr = reinterpret_cast<std::uintptr_t>(hookPtr);
	details.hook_action = hookAction;

	details.fn_make_pre = reinterpret_cast<std::uintptr_t>(preMFP);
	details.fn_make_post = reinterpret_cast<std::uintptr_t>(postMFP);

	details.fn_make_override_return = reinterpret_cast<std::uintptr_t>(returnOverrideMFP);
	details.fn_make_original_return = reinterpret_cast<std::uintptr_t>(returnOriginalMFP);
	details.fn_make_call_original = reinterpret_cast<std::uintptr_t>(callOriginalMFP);

	details.override_return_ptr = reinterpret_cast<std::uintptr_t>(overrideReturnPtr);
	details.original_return_ptr = reinterpret_cast<std::uintptr_t>(originalReturnPtr);

	auto id = g_lastest_hook_id++;
	auto it = g_hooks_detour.find(function);
	if (it == g_hooks_detour.end()) {
		auto insert = g_hooks_detour.insert_or_assign(function, std::make_unique<DetourCapsule>(function));

		if (insert.second) {
			// Detour is just created so insert the new hook immediately
			insert.first->second->InsertHook(id, details, false);
			return id;
		}
		return INVALID_HOOK;
	}

	it->second->InsertHook(id, details, async);
	return id;
}

KHOOK_API void RemoveHook(HookID_t id, bool async) {
	std::lock_guard guard(g_hooks_mutex);

	auto it = g_associated_hooks.find(id);
	if (it != g_associated_hooks.end()) {
		it->second->RemoveHook(id, async);
	}
}


}