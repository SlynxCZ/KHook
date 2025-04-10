#include <iostream>

#include "detour.hpp"

KHook::Action gAction = KHook::Action::Ignore;

std::uint32_t hello_test(std::uint32_t i) {
    std::cout << "green " << i << std::endl;
    return i;
}

std::uint32_t hello_pre(std::uint32_t i, std::uint32_t j) {
    std::cout << "\ngreen pre " << i << std::endl;
    return 66;
}

std::uint32_t hello_original(std::uint32_t i) {
    auto fn = (std::uint32_t (*)(std::uint32_t))KHook::GetOriginalFunction();
    fn(i);
    return 10;
}

std::uint32_t hello_return_original(std::uint32_t test) {
    return 77;
}

int main() {
    KHook::DetourCapsule detour(reinterpret_cast<void*>(hello_test));

    KHook::DetourCapsule::InsertHookDetails details {};
    details.hook_ptr = 0;
    details.hook_action = &gAction;

    details.fn_make_pre = reinterpret_cast<std::uintptr_t>(hello_pre);
    details.fn_make_post = 0;

    details.fn_make_call_original = reinterpret_cast<std::uintptr_t>(hello_original);
    details.fn_make_original_return = reinterpret_cast<std::uintptr_t>(hello_return_original);
    details.fn_make_override_return = reinterpret_cast<std::uintptr_t>(hello_return_original);

    details.original_return_ptr = 0;
    details.override_return_ptr = 0;
    detour.InsertHook(10, details, true);

    std::cout << "awaiting..." << std::endl;
    std::cout << "pre addr: 0x" << std::hex << details.fn_make_pre << std::endl;
    std::cout << "call original addr: 0x" << std::hex << details.fn_make_call_original << std::endl;
    std::cin.get();
    for (std::uint32_t i = 0; i < 1; i++) {
        auto ret = hello_test(55);
        std::cout << "return: " << std::dec << ret << std::endl;
    }
    return 0;
}