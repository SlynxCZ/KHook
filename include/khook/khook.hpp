#pragma once

#include <cstdint>
#include <unordered_set>

namespace KHook {

enum class Action : std::uint8_t {
	// Hook has taken no specific action
	Ignore = 0,
	// Hook has overwritten the return value
	// But call original anyways if in PRE callback
	// Doesn't do anything in a POST callback
	Override,
	// Hook has overwritten thre return value
	// Don't call the original if in PRE callback
	// Doesn't do anything in a POST callback
	Supercede
};

template<typename RETURN>
struct HookAction {
	Action action;
	RETURN ret;
};

template<>
struct HookAction<void> {
	Action action;
};

class Hook {
protected:
	Action _action;
};

template<typename RETURN>
class HookT : Hook {
public:
	HookT();
	~HookT() {
		if (_ret) {
			delete _ret;
		}
		if (_original_return) {
			delete _original_return;
		}
	}
protected:
	RETURN* _ret = nullptr;
	RETURN* _original_return = nullptr;
};

template<typename RETURN>
inline HookT<RETURN>::HookT() : _ret(new RETURN), _original_return(new RETURN) {}

template<>
inline HookT<void>::HookT() {}

// Thread dependent function
// It retrieves the currently called Hook ptr
static void* GetCurrent();

// Thread dependent function
// It retrieves the currently hooked function ptr
static void* GetOriginalFunction();

template<typename CLASS, typename RETURN, typename... ARGS>
class MemberHook : HookT<RETURN> {
public:
	using fnCallback = HookAction<RETURN> (*)(CLASS*, ARGS...);
private:
	// Called by KHook
	void KHook_Callback_PRE(Args...) {
		// Retrieve the real VirtualHook
		MemberHook<CLASS, RETURN, ARGS...> real_this = GetCurrent();
		real_this->KHook_Callback_Fixed(_pre_callbacks, this, Args...);
	}

	// Called by KHook
	void KHook_Callback_POST(Args...) {
		// Retrieve the real VirtualHook
		MemberHook<CLASS, RETURN, ARGS...> real_this = GetCurrent();
		real_this->KHook_Callback_Fixed(_post_callbacks, this, Args...);
	}

	// Fixed KHook callback
	void KHook_Callback_Fixed(std::unordered_set<fnCallback>& callbacks, CLASS* hooked_this, Args... args) { 
		_action = Action::Ignore;
		// Not one of our this ptrs, byebye
		if (!_global_hook && _hooked_this.find(hooked_this) == _hooked_this.end()) {
			return;
		}
		for (auto callback : callbacks) {
			HookAction<RETURN> action = (*callback)(hooked_this, args...);
			if (action.action > _action) {
				// Alright action is higher than our current, so update values
				_action = action.action;
				constexpr if (!std::is_same<RETURN, void>::value) {
					*_ret = action.ret;
				}
			}
		}
	}
	
	// Various filters to make MemberHook class useful
	std::unordered_set<fnCallback> _pre_callbacks;
	std::unordered_set<fnCallback> _post_callbacks;
	std::unordered_set<CLASS*> _hooked_this;
	bool _global_hook;

	// Might be used by KHook
	RETURN MakeReturn(ARGS...) {
		constexpr if (std::is_same<RETURN, void>::value) {
			return;
		} constexpr else {
			HookT<RETURN> real_this = GetCurrent();
			return *real_this->_ret;
		}
	}

	RETURN MakeOriginalReturn(ARGS...) {
		constexpr if (std::is_same<RETURN, void>::value) {
			return;
		} constexpr else {
			HookT<RETURN> real_this = GetCurrent();
			return *real_this->_original_return;
		}
	}


	class EmptyClass {};
	union OriginalPtr {
		RETURN (EmptyClass::*mfp)(ARGS...);
		struct
		{
			void* addr;
#ifdef WIN32
#else
			intptr_t adjustor;
#endif
		} details;
		
		OriginalPtr(void* addr) {
			details.addr = addr;
#ifdef WIN32
#else
			details.adjustor = 0;
#endif
		}
	};

	void MakeOriginalCall(ARGS ...args) {
		HookT<RETURN> real_this = GetCurrent();
		OriginalPtr ptr(GetOriginalFunction());
		constexpr if (std::is_same<RETURN, void>::value) {
			(*(((EmptyClass*)this)->ptr.mfp))(args...);
		} constexpr else {
			*real_this->_original_return = (*(((EmptyClass*)this)->ptr.mfp))(args...);
		}
	}
};

}