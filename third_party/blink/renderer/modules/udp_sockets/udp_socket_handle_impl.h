/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
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

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_UDP_SOCKETS_UDP_SOCKET_HANDLE_IMPL_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_UDP_SOCKETS_UDP_SOCKET_HANDLE_IMPL_H_

#include "mojo/public/cpp/bindings/binding.h"
#include "third_party/blink/renderer/platform/heap/handle.h"
#include "services/network/public/mojom/catalyst_socket.mojom-blink.h"
#include "third_party/blink/renderer/modules/udp_sockets/udp_socket_handle.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class UDPSocketHandleImpl : public UDPSocketHandle,
                            public network::mojom::blink::CatalystSocketClient {
 public:
  UDPSocketHandleImpl(UDPSocketHandleClient *client);
  ~UDPSocketHandleImpl() override;

  void Connect(network::mojom::blink::CatalystSocketPtr,
               const String& user_agent_override,
               base::SingleThreadTaskRunner*) override;
  void Send(const char* data, wtf_size_t) override;
  void Close() override;
  void Trace(blink::Visitor*) override;
  bool CertificateIsValid(const String& cert_chain) override;


 private:
  void Disconnect();

  // network::mojom::blink::CatalystSocketClient methods:
  void OnError(uint32_t custom_reason) override;
  void OnConnect() override;
  void OnDataFrame(const Vector<uint8_t>& data) override;

  Member<UDPSocketHandleClient> client_;

  network::mojom::blink::CatalystSocketPtr udp_socket_;
  mojo::Binding<network::mojom::blink::CatalystSocketClient> client_binding_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_WEBSOCKETS_WEBSOCKET_HANDLE_IMPL_H_
