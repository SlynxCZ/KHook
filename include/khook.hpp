#pragma once

#include <cstdint>
#include <unordered_set>

#ifdef WIN32
#define KHOOK_API __declspec(dllexport)
#else
#define KHOOK_API __attribute__((visibility("default")))
#endif 

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

class __Hook {
};

template<typename RETURN>
class Hook : __Hook {
public:
	Hook();
	~Hook() {
		if (_ret) {
			delete _ret;
		}
		if (_original_return) {
			delete _original_return;
		}
	}
protected:
	Action _action;
	RETURN* _ret = nullptr;
	RETURN* _original_return = nullptr;
};

template<typename RETURN>
inline Hook<RETURN>::Hook() : _ret(new RETURN), _original_return(new RETURN) {}

template<>
inline Hook<void>::Hook() {}

using HookID_t = std::uint32_t;
constexpr HookID_t INVALID_HOOK = -1;
/**
 * Creates a hook around the given function address.
 *
 * @param function Address of the function to hook.
 * @param hookPtr Pointer of the class with which to call the provided MFPs.
 * @param hookAction Pointer to the hook action value.
 * @param preMFP (Member) function to call with the original this ptr (if any), before the hooked function is called.
 * @param postMFP (Member) function to call with the original this ptr (if any), after the hooked function is called.
 * @param returnMFP (Member) function to call with the original this ptr (if any), to return the overridden return value.
 * @param returnOriginalMFP (Member) function to call with the original this ptr (if any), to return the original return value.
 * @param callOriginalMFP (Member) function to call with the original this ptr (if any), to call the original function and store the return value if needed.
 * @return The created hook id on success, INVALID_HOOK otherwise.
 */
KHOOK_API HookID_t SetupHook(void* function, void* hookPtr, Action* hookAction, void* preMFP, void* postMFP, void* returnMFP, void* returnOriginalMFP, void* callOriginalMFP);

/**
 * Thread local function, only to be called under KHook callbacks. It returns the pointer value hookPtr provided during SetupHook.
 *
 * @return The stored hookPtr. Behaviour is undefined if called outside hook callbacks.
 */
KHOOK_API void* GetCurrent();

/**
 * Thread local function, only to be called under KHook callbacks. It returns the pointer to the original hooked function.
 *
 * @return The original function pointer. Behaviour is undefined if called outside POST callbacks.
 */
KHOOK_API void* GetOriginalFunction();

/**
 * Thread local function, only to be called under KHook callbacks. It returns a pointer containing the original return value (if not superceded).
 *
 * @return The original value pointer. Behaviour is undefined if called outside POST callbacks.
 */
KHOOK_API void* GetOriginalValuePtr(bool pop = false);

/**
 * Thread local function, only to be called under KHook callbacks. It returns a pointer containing the override return value.
 *
 * @return The override value pointer. Behaviour is undefined if called outside POST callbacks.
 */
KHOOK_API void* GetOverrideValuePtr(bool pop = false);

template<typename CLASS, typename RETURN, typename... ARGS>
class MemberHook : protected Hook<RETURN> {
public:
	using fnCallback = HookAction<RETURN> (*)(CLASS*, ARGS...);
private:
	// Various filters to make MemberHook class useful
	fnCallback _pre_callback;
	fnCallback _post_callback;
	std::unordered_set<CLASS*> _hooked_this;
	bool _global_hook;

	// Called by KHook
	RETURN KHook_Callback_PRE(ARGS... args) {
		// Retrieve the real VirtualHook
		MemberHook<CLASS, RETURN, ARGS...> real_this = GetCurrent();
		real_this->KHook_Callback_Fixed(_pre_callback, this, args...);
		if constexpr(!std::is_same<RETURN, void>::value) {
			return *real_this->_ret;
		}
	}

	// Called by KHook
	RETURN KHook_Callback_POST(ARGS... args) {
		// Retrieve the real VirtualHook
		MemberHook<CLASS, RETURN, ARGS...> real_this = GetCurrent();
		real_this->KHook_Callback_Fixed(_post_callback, this, args...);
		if constexpr(!std::is_same<RETURN, void>::value) {
			return *real_this->_ret;
		}
	}

	// Fixed KHook callback
	void KHook_Callback_Fixed(fnCallback callback, CLASS* hooked_this, ARGS... args) { 
		this->_action = Action::Ignore;
		// Not one of our this ptrs, byebye
		if (!_global_hook && _hooked_this.find(hooked_this) == _hooked_this.end()) {
			return;
		}
		HookAction<RETURN> action = (*callback)(hooked_this, args...);
		if (action.action > this->_action) {
			this->_action = action.action;
			if constexpr(!std::is_same<RETURN, void>::value) {
				*(this->_ret) = action.ret;
			}
		}
	}

	// Might be used by KHook
	// Called if hook was selected as override hook
	// It returns the final value the hook will use
	RETURN MakeOverrideReturn(ARGS...) {
		if constexpr(std::is_same<RETURN, void>::value) {
			return;
		} else {
			return *(RETURN*)GetOverrideValuePtr(true);
		}
	}

	// Called if the hook has no return override
	RETURN MakeOriginalReturn(ARGS...) {
		if constexpr(std::is_same<RETURN, void>::value) {
			return;
		} else {
			return *(RETURN*)GetOriginalValuePtr(true);
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

	// Called if the hook wasn't superceded
	RETURN MakeOriginalCall(ARGS ...args) {
		OriginalPtr ptr(GetOriginalFunction());
		if constexpr(std::is_same<RETURN, void>::value) {
			(*(((EmptyClass*)this)->ptr.mfp))(args...);
		} else {
			RETURN* ret = (RETURN*)GetOriginalValuePtr();
			*ret = (*(((EmptyClass*)this)->ptr.mfp))(args...);
			return *ret;
		}
	}
};

}