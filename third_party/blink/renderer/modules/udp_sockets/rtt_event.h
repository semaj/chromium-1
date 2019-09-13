/*
 * Copyright (C) 2011 Google Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_UDP_SOCKETS_RTT_EVENT_H
#define THIRD_PARTY_BLINK_RENDERER_MODULES_UDP_SOCKETS_RTT_EVENT_H

#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/modules/event_modules.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/modules/udp_sockets/rtt_event_init.h"

namespace blink {

class RttEvent final : public Event {
  DEFINE_WRAPPERTYPEINFO();

 public:
  static RttEvent* Create(uint64_t tokens) {
    return MakeGarbageCollected<RttEvent>(tokens);
  }

  static RttEvent* Create(const AtomicString& type,
      const RttEventInit* initializer) {
    return MakeGarbageCollected<RttEvent>(type, initializer);
  }

  RttEvent(uint64_t tokens)
      : Event(event_type_names::kRtt, Bubbles::kNo, Cancelable::kNo),
        tokens_(tokens) {}
  RttEvent(const AtomicString& type, const RttEventInit* initializer);

  uint64_t tokens() const { return tokens_; }

  // Event function.
  const AtomicString& InterfaceName() const override {
    return event_interface_names::kRttEvent;
  }

  void Trace(blink::Visitor* visitor) override { Event::Trace(visitor); }

 private:
  uint64_t tokens_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_UDP_SOCKETS_RTT_EVENT_H
