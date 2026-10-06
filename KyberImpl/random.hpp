#pragma once

#include <cstdint>
#include <cstdlib>
#include <span>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <cerrno>
#ifdef __linux__
#include <unistd.h>
#include <sys/syscall.h>
#elif __NetBSD__
#include <sys/random.h>
#else
#include <unistd.h>
#endif
#endif

#ifdef _WIN32
inline void randombytes(std::span<uint8_t> out) {
  HCRYPTPROV ctx;
  size_t len;

  if(!CryptAcquireContext(&ctx, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    std::abort();

  while(!out.empty()) {
    len = (out.size() > 1048576) ? 1048576 : out.size();
    if(!CryptGenRandom(ctx, static_cast<DWORD>(len), reinterpret_cast<BYTE*>(out.data())))
      std::abort();

    out = out.subspan(len);
  }

  if(!CryptReleaseContext(ctx, 0))
    std::abort();
}
#elif defined(__linux__) && defined(SYS_getrandom)
inline void randombytes(std::span<uint8_t> out) {
  ssize_t ret;

  while(!out.empty()) {
    ret = syscall(SYS_getrandom, out.data(), out.size(), 0);
    if(ret == -1 && errno == EINTR)
      continue;
    else if(ret == -1)
      std::abort();

    out = out.subspan(ret);
  }
}
#elif defined(__NetBSD__)
inline void randombytes(std::span<uint8_t> out) {
  ssize_t ret;

  while(!out.empty()) {
    ret = getrandom(out.data(), out.size(), 0);
    if(ret == -1 && errno == EINTR)
      continue;
    else if(ret == -1)
      std::abort();

    out = out.subspan(ret);
  }
}
#else
inline void randombytes(std::span<uint8_t> out) {
  static int fd = -1;
  ssize_t ret;

  while(fd == -1) {
    fd = open("/dev/urandom", O_RDONLY);
    if(fd == -1 && errno == EINTR)
      continue;
    else if(fd == -1)
      std::abort();
  }

  while(!out.empty()) {
    ret = read(fd, out.data(), out.size());
    if(ret == -1 && errno == EINTR)
      continue;
    else if(ret == -1)
      std::abort();

    out = out.subspan(ret);
  }
}
#endif