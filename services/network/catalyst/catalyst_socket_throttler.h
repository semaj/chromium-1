// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SERVICES_NETWORK_CATALYST_SOCKET_THROTTLER_H_
#define SERVICES_NETWORK_CATALYST_SOCKET_THROTTLER_H_

#include <stdint.h>
#include <map>
#include <memory>

#include "base/component_export.h"
#include "base/memory/weak_ptr.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "net/base/completion_callback.h"

namespace network {

  class COMPONENT_EXPORT(NETWORK_SERVICE) CatalystSocketPerOriginThrottler final {
    public:

      CatalystSocketPerOriginThrottler();
      ~CatalystSocketPerOriginThrottler();

      int TryCanSend(net::CompletionOnceCallback);

    private:
      void OnTimer();

      // I don't think this synchronization is necessary, since we're in an async, single-threaded event loop
      std::atomic_int64_t tokens_;
      //std::mutex mut_;
      std::queue<net::CompletionOnceCallback> cbs_;
      base::RepeatingTimer timer_;
      base::WeakPtrFactory<CatalystSocketPerOriginThrottler> weak_factory_;

      DISALLOW_COPY_AND_ASSIGN(CatalystSocketPerOriginThrottler);
  };

  class COMPONENT_EXPORT(NETWORK_SERVICE) CatalystSocketThrottler final {
    public:

      CatalystSocketThrottler();
      ~CatalystSocketThrottler();

      int TryCanSend(url::Origin origin, net::CompletionOnceCallback);

    private:

      std::map<url::Origin, std::unique_ptr<CatalystSocketPerOriginThrottler>> per_origin_throttlers_;

      DISALLOW_COPY_AND_ASSIGN(CatalystSocketThrottler);
  };

}  // namespace network

#endif  // SERVICES_NETWORK_CATALYST_SOCKET_THROTTLER_H_
