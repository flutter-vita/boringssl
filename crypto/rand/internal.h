// Copyright 2024 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef OPENSSL_HEADER_CRYPTO_RAND_INTERNAL_H
#define OPENSSL_HEADER_CRYPTO_RAND_INTERNAL_H

#include <openssl/base.h>


#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
#define OPENSSL_RAND_DETERMINISTIC
#elif defined(OPENSSL_TRUSTY)
#define OPENSSL_RAND_TRUSTY
#elif defined(OPENSSL_WINDOWS)
#define OPENSSL_RAND_WINDOWS
#elif defined(__vita__)
// Before the OPENSSL_LINUX branch, which this target would otherwise take and
// which is fatal here: urandom.cc reaches entropy via syscall(__NR_getrandom)
// and abort()s unless that either works or reports ENOSYS with a readable
// /dev/urandom. A Vita has no syscall(2), no __NR_getrandom, and no /dev at
// all, so it takes the abort -- silently, since the perror alongside it goes
// to a stderr nothing is reading. That is a process death at first handshake
// with no diagnostic whatsoever.
#define OPENSSL_RAND_VITA
#elif defined(OPENSSL_LINUX)
#define OPENSSL_RAND_URANDOM
#elif defined(OPENSSL_APPLE) && !defined(OPENSSL_MACOS)
// Unlike macOS, iOS and similar hide away getentropy().
#define OPENSSL_RAND_IOS
#else
// By default if you are integrating BoringSSL we expect you to
// provide getentropy from the <unistd.h> header file.
#define OPENSSL_RAND_GETENTROPY
#endif

#if defined(OPENSSL_LINUX) || defined(OPENSSL_FREEBSD) || \
    defined(OPENSSL_OPENBSD)

// On linux we use MADVISE instead of pthread_atfork(), due
// to concerns about clone() being used for address space
// duplication.
#define OPENSSL_FORK_DETECTION
#define OPENSSL_FORK_DETECTION_WIPEONFORK

#elif defined(OPENSSL_MACOS) || defined(OPENSSL_IOS)

// These platforms may detect address space duplication with pthread_atfork.
// iOS doesn't normally allow fork in apps, but it's there.
#define OPENSSL_FORK_DETECTION
#define OPENSSL_FORK_DETECTION_PTHREAD_ATFORK

#elif defined(OPENSSL_WINDOWS) || defined(OPENSSL_TRUSTY) || \
    defined(__ZEPHYR__) || defined(CROS_EC)

// These platforms do not fork.
#define OPENSSL_DOES_NOT_FORK

#else

// Other platforms may fork, but BoringSSL cannot reliably detect it happening.
// So instead, new entropy will be drawn on every RNG call.

#endif

#endif  // OPENSSL_HEADER_CRYPTO_RAND_INTERNAL_H
