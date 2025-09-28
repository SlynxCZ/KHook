#include <iostream>
#include <thread>
#include "detour.hpp"
#include "khook.hpp"

// ------------------- Free function -------------------
int original_function(float p1, int p2, float p3, int p4, double p5) {
    std::cout << "original_function" << std::endl;
    return 34;
}

KHook::Return<int> original_function_pre(float p1, int p2, float p3, int p4, double p5) {
    std::cout << "[Function typed pre] " << p1 << "|" << p2 << "|" << p3 << std::endl;
    return { KHook::Action::Ignore };
}

KHook::Return<int> original_function_post(float p1, int p2, float p3, int p4, double p5) {
    std::cout << "[Function typed post]" << std::endl;
    return { KHook::Action::Supersede, 52 };
}

// Typed function hook
KHook::Function<int, float, int, float, int, double>
    testHook(original_function, original_function_pre, original_function_post);

// Dynamic function callbacks
KHook::Return<int> dyn_func_pre(KHook::DynamicHook* hook) {
    std::cout << "[Function dynamic pre]" << std::endl;
    float a = hook->GetParam<float>(0);
    int b   = hook->GetParam<int>(1);
    std::cout << "params: " << a << ", " << b << std::endl;
    hook->SetParam<int>(1, 999);
    return { KHook::Action::Ignore };
}

KHook::Return<int> dyn_func_post(KHook::DynamicHook* hook) {
    std::cout << "[Function dynamic post]" << std::endl;
    int ret = hook->GetReturn<int>();
    std::cout << "original return=" << ret << std::endl;
    hook->SetReturn(777);
    return { KHook::Action::Supersede };
}

// Dynamic function hook (now with ARGS...)
KHook::FunctionDynamic<int, float, int, float, int, double>
    testHookFuncDyn(original_function, dyn_func_pre, dyn_func_post);

// ------------------- Class with virtual -------------------
class TestClass {
public:
    virtual void Foo() {}
    virtual void Goo() {}
    virtual void Boo() {}
    virtual void Xoo() {}
    virtual void Too() {}
    virtual float Test(float x, float y, float z) {
        std::cout << "[Original Test] x=" << x << " y=" << y << " z=" << z << std::endl;
        return 52.0f;
    }
};

// Typed virtual callbacks
KHook::Return<float> test_pre(TestClass* ptr, float x, float y, float z) {
    std::cout << "[Virtual typed pre] " << x << "|" << y << "|" << z << std::endl;
    return { KHook::Action::Ignore };
}

KHook::Return<float> test_post(TestClass* ptr, float x, float y, float z) {
    std::cout << "[Virtual typed post]" << std::endl;
    return { KHook::Action::Supersede, 57.0f };
}

// Typed virtual hook
KHook::Virtual<TestClass, float, float, float, float>
    testHook3(&TestClass::Test, test_pre, test_post);

// Dynamic virtual callbacks
KHook::Return<float> dyn_virtual_pre(KHook::DynamicHook* hook) {
    std::cout << "[Virtual dynamic pre]" << std::endl;
    float x = hook->GetParam<float>(0);
    float y = hook->GetParam<float>(1);
    float z = hook->GetParam<float>(2);
    std::cout << "params: " << x << ", " << y << ", " << z << std::endl;
    hook->SetParam<float>(2, 123.45f);
    return { KHook::Action::Ignore };
}

KHook::Return<float> dyn_virtual_post(KHook::DynamicHook* hook) {
    std::cout << "[Virtual dynamic post]" << std::endl;
    float ret = hook->GetReturn<float>();
    std::cout << "original return=" << ret << std::endl;
    hook->SetReturn(999.0f);
    return { KHook::Action::Supersede };
}

// Dynamic virtual hook (now with ARGS...)
KHook::VirtualDynamic<TestClass, float, float, float, float>
    testHookDyn(&TestClass::Test, dyn_virtual_pre, dyn_virtual_post);

// ------------------- MAIN -------------------
int main() {
    std::cin.get();

    // ---------- Function (typed) ----------
    std::cout << "\n=== Function typed ===" << std::endl;
    int ret = original_function(4.0, 5, 6.0, 2, 7.0);
    std::cout << "return: " << ret << std::endl;

    // ---------- Function (dynamic) ----------
    std::cout << "\n=== Function dynamic ===" << std::endl;
    int retDyn = original_function(10.0, 20, 30.0, 40, 50.0);
    std::cout << "dynamic return: " << retDyn << std::endl;

    // ---------- Virtual (typed) ----------
    std::cout << "\n=== Virtual typed ===" << std::endl;
    TestClass cls;
    testHook3.Add(&cls);
    float vret = cls.Test(1.0f, 2.0f, 3.0f);
    std::cout << "virtual return: " << vret << std::endl;

    // ---------- Virtual (dynamic) ----------
    std::cout << "\n=== Virtual dynamic ===" << std::endl;
    TestClass clsDyn;
    testHookDyn.Add(&clsDyn);
    float vretDyn = clsDyn.Test(11.0f, 22.0f, 33.0f);
    std::cout << "virtual dynamic return: " << vretDyn << std::endl;

    // KHook::Shutdown();
    return 0;
}
