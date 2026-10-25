#pragma once

// Minimal, dependency-free test harness. No network, no third-party fetch, so
// it builds identically under native CMake, Podman and Yocto.

#include <cstdio>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace test {

struct Case {
  std::string name;
  std::function<void()> fn;
};

inline std::vector<Case>& cases() {
  static std::vector<Case> c;
  return c;
}

struct Registrar {
  Registrar(std::string n, std::function<void()> f) {
    cases().push_back({std::move(n), std::move(f)});
  }
};

inline int g_failures = 0;
inline int g_checks = 0;

template <class A, class B>
inline void checkEq(const A& a, const B& b, const char* ea, const char* eb,
                    const char* file, int line) {
  ++g_checks;
  if (a == b) return;
  ++g_failures;
  std::ostringstream os;
  os << "  FAIL " << file << ":" << line << ": " << ea << " == " << eb << "\n"
     << "    left:  " << a << "\n"
     << "    right: " << b << "\n";
  std::fputs(os.str().c_str(), stderr);
}

inline int runAll() {
  for (auto& c : cases()) {
    std::fprintf(stderr, "RUN  %s\n", c.name.c_str());
    int before = g_failures;
    c.fn();
    std::fprintf(stderr, "%s  %s\n", g_failures == before ? "PASS" : "FAIL",
                 c.name.c_str());
  }
  std::fprintf(stderr, "\n%d checks, %d failures\n", g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}

} // namespace test

#define TEST(name)                                            \
  static void test_##name();                                  \
  static ::test::Registrar reg_##name(#name, test_##name);    \
  static void test_##name()

#define CHECK(expr)                                                     \
  do {                                                                  \
    ++::test::g_checks;                                                 \
    if (!(expr)) {                                                      \
      ++::test::g_failures;                                             \
      std::fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
    }                                                                   \
  } while (0)

#define CHECK_EQ(a, b) ::test::checkEq((a), (b), #a, #b, __FILE__, __LINE__)
