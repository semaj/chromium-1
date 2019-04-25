// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "catalyst_socket_throttler.h"

#include <algorithm>

#include "base/rand_util.h"

namespace network {

  CatalystSocketPerOriginThrottler::CatalystSocketPerOriginThrottler()
    : tokens_(10),
      weak_factory_(this) {
      timer_.Start(FROM_HERE, base::TimeDelta::FromMilliseconds(10),
          this, &CatalystSocketPerOriginThrottler::OnTimer);
    }
  CatalystSocketPerOriginThrottler::~CatalystSocketPerOriginThrottler() {}

  int CatalystSocketPerOriginThrottler::TryCanSend(net::CompletionOnceCallback cb) {
    if (tokens_ > 0 && cbs_.empty()) {
      tokens_--;
      return net::OK;
    } else {
      cbs_.push(std::move(cb));
      return net::ERR_IO_PENDING;
    }
  }

  void CatalystSocketPerOriginThrottler::OnTimer() {
    if (tokens_ < 10) {
      tokens_++;
    }
    //if (!mut_.try_lock()) {
      //return
    //}
    while (tokens_ > 0 && !cbs_.empty()) {
      int result = net::OK;
      base::PostTask(FROM_HERE, base::BindOnce(std::move(cbs_.front()), result));
      //std::move(cbs_.front()).Run(result);
      cbs_.pop();
      tokens_--;
    }
  }


  CatalystSocketThrottler::CatalystSocketThrottler() {}
  CatalystSocketThrottler::~CatalystSocketThrottler() {}

  int CatalystSocketThrottler::TryCanSend(url::Origin origin, net::CompletionOnceCallback callback) {
    if (per_origin_throttlers_.find(origin) == per_origin_throttlers_.end()) {
      per_origin_throttlers_[origin] = std::make_unique<CatalystSocketPerOriginThrottler>();
    }
    return per_origin_throttlers_[origin]->TryCanSend(std::move(callback));
  }


}  // namespace network
