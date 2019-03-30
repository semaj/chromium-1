// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "catalyst_socket_throttler.h"

#include <algorithm>

#include "base/rand_util.h"

namespace network {

//constexpr int CatalystSocketPerProcessThrottler::kMaxPendingCatalystSocketConnections;

//CatalystSocketPerProcessThrottler::PendingConnection::PendingConnection(
    //base::WeakPtr<CatalystSocketPerProcessThrottler> throttler)
    //: throttler_(std::move(throttler)) {
  //DCHECK(throttler_);
  //++throttler_->num_pending_connections_;
//}
//CatalystSocketPerProcessThrottler::PendingConnection::PendingConnection(
    //PendingConnection&& other)
    //: throttler_(std::move(other.throttler_)) {
  //other.throttler_ = nullptr;
//}
//CatalystSocketPerProcessThrottler::PendingConnection::~PendingConnection() {
  //if (!throttler_)
    //return;

  //--throttler_->num_pending_connections_;
  //++throttler_->num_current_failed_connections_;
//}

//void CatalystSocketPerProcessThrottler::PendingConnection::OnCompleteHandshake() {
  //DCHECK(throttler_);

  //--throttler_->num_pending_connections_;
  //++throttler_->num_current_succeeded_connections_;
  //throttler_ = nullptr;
//}

CatalystSocketPerProcessThrottler::CatalystSocketPerProcessThrottler()
    : weak_factory_(this) {}
CatalystSocketPerProcessThrottler::~CatalystSocketPerProcessThrottler() {}

base::TimeDelta CatalystSocketPerProcessThrottler::CalculateDelay() const {
  int64_t f =
      num_previous_failed_connections_ + num_current_failed_connections_;
  int64_t s =
      num_previous_succeeded_connections_ + num_current_succeeded_connections_;
  //int p = num_pending_connections_;
  return base::TimeDelta::FromMilliseconds(
      base::RandInt(1000, 5000) *
      (1 << std::min(f / (s + 1), INT64_C(16))) / 65536);
      //(1 << std::min(p + f / (s + 1), INT64_C(16))) / 65536);
}

//CatalystSocketPerProcessThrottler::PendingConnection
//CatalystSocketPerProcessThrottler::IssuePendingConnectionTracker() {
  //return PendingConnection(weak_factory_.GetWeakPtr());
//}

bool CatalystSocketPerProcessThrottler::IsClean() const {
  //return num_pending_connections_ == 0 &&
  return num_current_succeeded_connections_ == 0 &&
         num_previous_succeeded_connections_ == 0 &&
         num_current_failed_connections_ == 0 &&
         num_previous_succeeded_connections_ == 0;
}

void CatalystSocketPerProcessThrottler::Roll() {
  num_previous_succeeded_connections_ = num_current_succeeded_connections_;
  num_previous_failed_connections_ = num_current_failed_connections_;

  num_current_succeeded_connections_ = 0;
  num_current_failed_connections_ = 0;
}

CatalystSocketThrottler::CatalystSocketThrottler() {}
CatalystSocketThrottler::~CatalystSocketThrottler() {}

//bool CatalystSocketThrottler::HasTooManyPendingConnections(int process_id) const {
  //auto it = per_process_throttlers_.find(process_id);
  //if (it == per_process_throttlers_.end())
    //return false;

  //return it->second->HasTooManyPendingConnections();
//}

base::TimeDelta CatalystSocketThrottler::CalculateDelay(int process_id) const {
  auto it = per_process_throttlers_.find(process_id);
  if (it == per_process_throttlers_.end())
    return base::TimeDelta();

  return it->second->CalculateDelay();
}

//CatalystSocketThrottler::PendingConnection
//CatalystSocketThrottler::IssuePendingConnectionTracker(int process_id) {
  //auto it = per_process_throttlers_.find(process_id);
  //if (it == per_process_throttlers_.end()) {
    //it = per_process_throttlers_
             //.insert(std::make_pair(
                 //process_id, std::make_unique<CatalystSocketPerProcessThrottler>()))
             //.first;
  //}

  //if (!throttling_period_timer_.IsRunning()) {
    //throttling_period_timer_.Start(FROM_HERE, base::TimeDelta::FromMinutes(2),
                                   //this, &CatalystSocketThrottler::OnTimer);
  //}
  //return it->second->IssuePendingConnectionTracker();
//}

void CatalystSocketThrottler::OnTimer() {
  auto it = per_process_throttlers_.begin();
  while (it != per_process_throttlers_.end()) {
    it->second->Roll();
    if (it->second->IsClean()) {
      // We don't need the entry. Erase it.
      it = per_process_throttlers_.erase(it);
    } else {
      ++it;
    }
  }
  if (per_process_throttlers_.empty())
    throttling_period_timer_.Stop();
}

}  // namespace network
