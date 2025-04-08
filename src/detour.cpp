#include "detour.hpp"

#include <stack>

#define KHOOK_X64

namespace KHook {

std::mutex gDetoursUpdate;
std::unordered_set<DetourCapsule*>  gDetoursToUpdate;

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

static thread_local std::stack<std::pair<void*, void*>> g_hook_fn_original_return;
static void PushPopHookOriginalReturn(void* original_return_ptr, void* fn_original_function_ptr, bool push) {
	if (push) {
		g_hook_fn_original_return.push(std::make_pair(original_return_ptr, fn_original_function_ptr));
	} else {
		g_hook_fn_original_return.pop();
	}
}

KHOOK_API void* GetOriginalFunction() {
	return g_hook_fn_original_return.top().second;
}

KHOOK_API void* GetOriginalValuePtr() {
	return g_hook_fn_original_return.top().first;
}

static std::uintptr_t SaveRestoreRsp(void* jit, std::uintptr_t rsp, bool store) {
	static thread_local std::unordered_map<void*, std::uintptr_t> rsp_values;

	auto it = rsp_values.find(jit);
	if (it == rsp_values.end()) {
		it = rsp_values.insert_or_assign(jit, 0).first;
	}

	if (store) {
		it->second = rsp;
	} else {
		// If stack restoration is bigger than this, something went horribly wrong
		assert((it->second + STACK_SAFETY_BUFFER) <= rsp);
	}

	return it->second;
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

struct AsmLoopDetails {
	// Highest hook action so far
	std::uintptr_t action;
	// If Action::Override or higher
	// These will be used to perform the return
	std::uintptr_t overriding_hook_ptr;
	std::uintptr_t fn_make_override_return;
	// The hook that performed the original call
	std::uintptr_t fn_make_call_original;
	std::uintptr_t original_return_ptr;
	static_assert(sizeof(std::uintptr_t) == sizeof(void*));
	static_assert(sizeof(std::uint32_t) >= sizeof(KHook::Action));
};

/*
 * @param hookAction Pointer to the hook action value.
 * @param preMFP (Member) function to call with the original this ptr (if any), before the hooked function is called.
 * @param postMFP (Member) function to call with the original this ptr (if any), after the hooked function is called.
 * @param returnMFP (Member) function to call with the original this ptr (if any), to return the overridden return value.
 * @param returnOriginalMFP (Member) function to call with the original this ptr (if any), to return the original return value.
 * @param callOriginalMFP 
*/

DetourCapsule::DetourCapsule() : _start_callbacks(nullptr) {
	static constexpr auto local_params_size = sizeof(AsmLoopDetails);
	static_assert(local_params_size % 16 == 0);
#ifdef KHOOK_X64
	using namespace Asm;

	static auto push_original_return_ptr = [](DetourCapsule::AsmJit& jit, x86_64_RegRm original_return_ptr, x8664Reg fn_original_function_ptr) {
		jit.mov(rax, reinterpret_cast<std::uintptr_t>(PushPopHookOriginalReturn));
		// 1st param - Original return ptr
		LINUX_ONLY(jit.mov(rdi, original_return_ptr));
		WIN_ONLY(jit.mov(rcx, original_return_ptr));
		// 2nd param - Fn original return ptr
		LINUX_ONLY(jit.mov(rsi, fn_original_function_ptr));
		WIN_ONLY(jit.mov(rdx, fn_original_function_ptr));
		// 3rd param - Store
		LINUX_ONLY(jit.mov(rdx, false));
		WIN_ONLY(jit.mov(r8, false));
		jit.call(rax);
	};

	static auto pop_original_return_ptr = [](DetourCapsule::AsmJit& jit) {
		jit.mov(rax, reinterpret_cast<std::uintptr_t>(PushPopHookOriginalReturn));
		// 1st param - Hook
		LINUX_ONLY(jit.mov(rdi, 0));
		WIN_ONLY(jit.mov(rcx, 0));
		// 2nd param - Fn original return ptr
		LINUX_ONLY(jit.mov(rsi, 0));
		WIN_ONLY(jit.mov(rdx, 0));
		// 3rd param - Store
		LINUX_ONLY(jit.mov(rdx, false));
		WIN_ONLY(jit.mov(r8, false));
		jit.call(rax);
	};

	static auto save_rsp = [](DetourCapsule::AsmJit& jit) {
		jit.mov(rax, reinterpret_cast<std::uintptr_t>(SaveRestoreRsp));
		// 1st param - Jit
		LINUX_ONLY(jit.mov(rdi, reinterpret_cast<std::uintptr_t>(&jit)));
		WIN_ONLY(jit.mov(rcx, reinterpret_cast<std::uintptr_t>(&jit)));
		// 2nd param - Rsp
		LINUX_ONLY(jit.mov(rsi, rsp));
		WIN_ONLY(jit.mov(rdx, rsp));
		// 3rd param - Store
		LINUX_ONLY(jit.mov(rdx, true));
		WIN_ONLY(jit.mov(r8, true));
		jit.call(rax);
	};

	static auto restore_rsp = [](DetourCapsule::AsmJit& jit) {
		// Force align rsp
		jit.mov(rax, 0xFFFFFFFFFFFFFFF0);
		jit.l_and(rsp, rax);
		
		// just in case of stack corruption
		static constexpr std::uint32_t stackSpace = 96 + WIN_ONLY(32) LINUX_ONLY(0);
		jit.sub(rsp, stackSpace);

		jit.mov(rax, reinterpret_cast<std::uintptr_t>(SaveRestoreRsp));
		// 1st param - Jit
		LINUX_ONLY(jit.mov(rdi, reinterpret_cast<std::uintptr_t>(&jit)));
		WIN_ONLY(jit.mov(rcx, reinterpret_cast<std::uintptr_t>(&jit)));
		// 2nd param - Rsp
		LINUX_ONLY(jit.lea(rsi, rsp(stackSpace)));
		WIN_ONLY(jit.lea(rdx, rsp(stackSpace)));
		// 3rd param - Store
		LINUX_ONLY(jit.mov(rdx, true));
		WIN_ONLY(jit.mov(r8, true));
		jit.call(rax);

		jit.mov(rsp, rax);
	};

	static auto lock_shared_mutex = [](DetourCapsule::AsmJit& jit, std::shared_mutex* mutex) {
		jit.mov(rax, reinterpret_cast<std::uintptr_t>(RecursiveLockUnlockShared));
		// 1st param - Mutex
		LINUX_ONLY(jit.mov(rdi, reinterpret_cast<std::uintptr_t>(mutex)));
		WIN_ONLY(jit.mov(rcx, reinterpret_cast<std::uintptr_t>(mutex)));
		// 2nd param - Lock
		LINUX_ONLY(jit.mov(rsi, true));
		WIN_ONLY(jit.mov(rdx, true));
		jit.call(rax);
	};

	static auto unlock_shared_mutex = [](DetourCapsule::AsmJit& jit, std::shared_mutex* mutex) {
		jit.mov(rax, reinterpret_cast<std::uintptr_t>(RecursiveLockUnlockShared));
		// 1st param - Mutex
		LINUX_ONLY(jit.mov(rdi, reinterpret_cast<std::uintptr_t>(mutex)));
		WIN_ONLY(jit.mov(rcx, reinterpret_cast<std::uintptr_t>(mutex)));
		// 2nd param - Lock
		LINUX_ONLY(jit.mov(rsi, false));
		WIN_ONLY(jit.mov(rdx, false));
		jit.call(rax);
	};

#ifdef WIN32
	// Save everything pertaining to Windows x86_64 callconv
	static const x8664Reg reg[] = { rcx, rdx, r8, r9 }; // 32 bytes so 16 bytes aligned
	// Save XMM0-XMM5
	static const x8664FloatReg float_reg[] = { xmm0, xmm1, xmm2, xmm3 }; // Each register is 16 bytes
#else
	// Save everything pertaining to Linux x86_64 callconv
	static const x8664Reg reg[] = { rdi, rsi, rdx, rcx, r8, r9 }; // 48 bytes (so 16 bytes aligned)
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

	// Restore floating point registers
	static auto restore_float_regs = [](DetourCapsule::AsmJit& jit, std::uint32_t func_param_stack_size) {
		for (int i = 0; i < float_reg_count; i++) {
			jit.movsd(float_reg[i], rsp(func_param_stack_size + (16 * (float_reg_count - 1)) - (16 * i)));
		}
	};

	// Restore regular registers
	static auto restore_reg = [](DetourCapsule::AsmJit& jit, std::uint32_t func_param_stack_size) {
		for (int i = 0; i < reg_count; i++) {
			jit.mov(reg[i], rsp(func_param_stack_size + (16 * float_reg_count) + (8 * (reg_count - 1)) - (8 * i)));
		}
	};

	// Introduce shadow space
	WIN_ONLY(_jit.sub(rsp, 32));
	// Bytes offset to get back at where we saved our data
	static constexpr auto reg_start = WIN_ONLY(32) LINUX_ONLY(0);
	static constexpr auto stack_local_data_start = 16 * float_reg_count + 8 * reg_count + reg_start;
	static constexpr auto func_param_stack_start = stack_local_data_start + local_params_size;
	// Frees the entire stack and unaligns it
	static auto free_stack = [](DetourCapsule::AsmJit& jit, std::uint32_t func_param_stack_size) {
		jit.add(rsp, func_param_stack_start + func_param_stack_size);
		jit.pop(rbp);
	};

	// Begin thread safety
	lock_shared_mutex(_jit, &_detour_mutex);

	// Early retrieve callbacks
	_jit.mov(rax, reinterpret_cast<std::uintptr_t>(&_start_callbacks));
	_jit.mov(rax, rax());
	
	// If no callbacks, early return
	_jit.test(rax, rax);
	_jit.jnz(INT32_MAX);
	auto jnz_pos = _jit.get_outputpos();

	// Unlock mutex
	unlock_shared_mutex(_jit, &_detour_mutex);

	// Recopy the registers in case we blew them up
	restore_float_regs(_jit, 0);
	restore_reg(_jit, 0);
	// This unaligns the stack
	free_stack(_jit, 0);

	_jit.mov(rax, reinterpret_cast<std::uintptr_t>(&_original_function));
	_jit.mov(rax, rax());
	// Go back to original function with original stack
	_jit.jump(rax);

	// Write our jump offset
	_jit.rewrite<std::int32_t>(jnz_pos - sizeof(std::int32_t), _jit.get_outputpos() - jnz_pos);

	// Remember our stack

	// Copy the stack over
	std::int32_t func_param_stack_size = (_stack_size != 0) ? _stack_size : STACK_SAFETY_BUFFER;
	_jit.sub(rsp, func_param_stack_size);

	// Prelude to loop
	save_rsp(_jit);
	// rax still contains the value of this->_start_callbacks
	// rbp is used because it's preserved between calls on x86_64
	_jit.push(r8);

	_jit.lea(rbp, rsp(stack_local_data_start + func_param_stack_size));
	// Default hook action is to ignore
	_jit.mov(rbp(offsetof(AsmLoopDetails, action)), (std::uint32_t)KHook::Action::Ignore);
	// We can set the first hook as overriding, its only gonna be used by actually overriding
	_jit.mov(r8, rax(offsetof(LinkedList, hook_ptr)));
	_jit.mov(rbp(offsetof(AsmLoopDetails, overriding_hook_ptr)), r8);
	// We can also set the override function as the original return because again it will be replaced if actually overriden
	_jit.mov(r8, rax(offsetof(LinkedList, fn_make_override_return)));
	_jit.mov(rbp(offsetof(AsmLoopDetails, fn_make_override_return)), r8);
	// First hook will be made to call original
	_jit.mov(r8, rax(offsetof(LinkedList, fn_make_call_original)));
	_jit.mov(rbp(offsetof(AsmLoopDetails, fn_make_call_original)), r8);
	_jit.mov(r8, rax(offsetof(LinkedList, original_return_ptr)));
	_jit.mov(rbp(offsetof(AsmLoopDetails, original_return_ptr)), r8);

	_jit.pop(r8);

	// Copy the entire func param stack over
	_jit.push(rdi);
	_jit.push(rsi);
	_jit.push(rcx);

	_jit.mov(rcx, func_param_stack_size);
	_jit.lea(rdi, rsp(3 * 8));
	_jit.lea(rsi, rsp(3 * 8 + func_param_stack_size + func_param_stack_start));

	_jit.rep_movs_bytes();

	_jit.pop(rcx);
	_jit.pop(rsi);
	_jit.pop(rdi);

	// PRE LOOP

	// Call original (maybe)
	// RBP which we have set much earlier still contains our local variables
	// it should have been saved across all calls as per linux & win callconvs
	_jit.mov(rax, reinterpret_cast<std::uintptr_t>(&_original_function));
	_jit.mov(rax, rax());
	push_original_return_ptr(_jit, rbp(offsetof(AsmLoopDetails, original_return_ptr)), rax);
	_jit.mov(rax, rbp(offsetof(AsmLoopDetails, action)));

	_jit.cmp(rax, (std::int32_t)Action::Supercede);
	_jit.jne(INT32_MAX);
	auto jne_pos = _jit.get_outputpos();
	// Call original
	restore_float_regs(_jit, func_param_stack_size);
	restore_reg(_jit, func_param_stack_size);
	_jit.mov(rax, rbp(offsetof(AsmLoopDetails, fn_make_call_original)));
	_jit.call(rax);
	restore_rsp(_jit);

	// POST LOOP

	pop_original_return_ptr(_jit);
	restore_float_regs(_jit, func_param_stack_size);
	restore_reg(_jit, func_param_stack_size);
	free_stack(_jit, func_param_stack_size);
	// Jump to the original / Overwritten return value function
	_jit.jump(rax);
#endif
}

DetourCapsule::~DetourCapsule() {
	std::lock_guard guard(gDetoursUpdate);
	gDetoursToUpdate.erase(this);
}

void DetourCapsule::AddCallback(void* func) {
	std::lock_guard guard(gDetoursUpdate);
	_GetWriteCallback(func).push_back(CBAction::ADD);
	gDetoursToUpdate.insert(this);
}

void DetourCapsule::RemoveCallback(void* func) {
	std::lock_guard guard(gDetoursUpdate);
	_GetWriteCallback(func).push_back(CBAction::REMOVE);
	gDetoursToUpdate.insert(this);
}

std::vector<DetourCapsule::CBAction>& DetourCapsule::_GetWriteCallback(void* func) {
	auto it = _write_callbacks.find(func);
	if (it == _write_callbacks.end()) {
		it = _write_callbacks.emplace(func, std::vector<DetourCapsule::CBAction>()).first;
	}
	return it->second;
}


}