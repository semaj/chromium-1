// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/udp_sockets/rtt_event.h"

namespace blink {

RttEvent::RttEvent(const AtomicString& type,
                       const RttEventInit* initializer)
    : Event(type, initializer) {
  if (initializer->hasTokens())
    tokens_ = initializer->tokens();
}

}  // namespace blink
