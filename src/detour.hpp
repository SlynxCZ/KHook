#pragma once
#include <cstdint>
#include <mutex>
#include <shared_mutex>	
#include <vector>
#include <unordered_map>
#include <unordered_set>

#include "khook/asm/x86_64.hpp"
#include "khook/khook.hpp"

namespace KHook {
	// A general purpose, thread-safe, detour, it functions in a very straight foward manner :
	//
	// [   DETOUR START]
	// [jit]
	//
	// [   Save All Registers]
	// [   Save 100 Bytes of stack]
	// [   Loop (forever) first thread-safe check]
	// [   Add +1 to second thread-safe varaible]
	// [   Unlock mutex ]
	// 
	// [jit]
	// [   DETOUR END]
	class DetourCapsule {
	public:
		using AsmJit = Asm::x86_64_Jit;

		DetourCapsule();
		~DetourCapsule();

		void AddCallback(void* func);
		void RemoveCallback(void* func);
	private:
		enum class CBAction : std::uint8_t {
			ADD = 1,
			REMOVE = 2
		};
		std::vector<CBAction>& _GetWriteCallback(void* func);
		
		// Detour pending modifications
		std::mutex _write_mutex;
		std::unordered_map<void*, std::vector<CBAction>> _write_callbacks;

		struct LinkedList {
			LinkedList(LinkedList* prev) : prev(prev), next(nullptr) {
				if (prev) {
					prev->next = this;
				}
			}
			~LinkedList() {
				if (prev) {
					prev->next = this->next;
				}
				if (next) {
					next->prev = this->prev;
				}
			}

			LinkedList* prev = nullptr;
			LinkedList* next = nullptr;
			std::uintptr_t hook_ptr;
			KHook::Action* hook_action;

			std::uintptr_t fn_make_pre;
			std::uintptr_t fn_make_post;

			std::uintptr_t fn_make_call_original;
			std::uintptr_t fn_make_original_return;
			std::uintptr_t fn_make_override_return;

			std::uintptr_t original_return_ptr;
			std::uintptr_t override_return_ptr;
		};
		// Detour callbacks
		std::shared_mutex _detour_mutex;
		std::unordered_set<void*> _callbacks;
		LinkedList* _start_callbacks;
		LinkedList* _end_callbacks;

		// Detour business logic
		AsmJit _jit;
		std::uintptr_t _jit_func_ptr;

		// Detour details
		std::uintptr_t _original_function;
		std::uint32_t _stack_size;
	};
}