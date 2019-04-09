// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SERVICES_NETWORK_CATALYST_UDP_STREAM_SOCKET_H
#define SERVICES_NETWORK_CATALYST_UDP_STREAM_SOCKET_H

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include "base/component_export.h"
#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/memory/ref_counted.h"
#include "base/time/time.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "base/containers/span.h"
#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/callback.h"
#include "net/base/completion_once_callback.h"
//#include "net/websockets/websocket_event_interface.h"
#include "services/network/public/mojom/catalyst_socket.mojom.h"
#include "catalyst_socket_throttler.h"
#include "url/origin.h"
#include "services/network/public/mojom/ip_endpoint.mojom.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/base/ip_endpoint.h"
#include "net/base/ip_address.h"
#include "net/dns/host_resolver.h"
#include "net/base/host_port_pair.h"
#include "net/cert/cert_verify_result.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/multi_threaded_cert_verifier.h"
#include "net/cert/x509_util.h"
#include "net/cert/cert_verify_proc.h"
#include "net/socket/stream_socket.h"
#include "net/ssl/ssl_info.h"
#include "net/socket/udp_socket.h"

class GURL;

namespace network {
  class UDPStreamSocket : public net::StreamSocket {
    public:
      UDPStreamSocket(net::DatagramSocket::BindType bind_type,
          net::NetLog* net_log,
          const net::NetLogSource& source,
          net::IPEndPoint& remote_addr);
      ~UDPStreamSocket() override;

      static const uint32_t kMaxReadSize = 64 * 1024;

      // StreamSocket
      //void SetBeforeConnectCallback(
          //const BeforeConnectCallback& before_connect_callback) override;
      int ConnectSync();
      int Connect(net::CompletionOnceCallback callback) override;
      void Disconnect() override;
      bool IsConnected() const override;
      bool IsConnectedAndIdle() const override;
      int GetPeerAddress(net::IPEndPoint* address) const override;
      int GetLocalAddress(net::IPEndPoint* address) const override;
      const net::NetLogWithSource& NetLog() const override;
      bool WasEverUsed() const override;
      bool WasAlpnNegotiated() const override;
      net::NextProto GetNegotiatedProtocol() const override;
      bool GetSSLInfo(net::SSLInfo* ssl_info) override;
      void GetConnectionAttempts(net::ConnectionAttempts* out) const override;
      void ClearConnectionAttempts() override;
      void AddConnectionAttempts(const net::ConnectionAttempts& attempts) override;
      int64_t GetTotalReceivedBytes() const override;
      void ApplySocketTag(const net::SocketTag& tag) override;
      
      // Socket
      int Write(net::IOBuffer* buf,
          int buf_len,
          net::CompletionOnceCallback callback,
          const net::NetworkTrafficAnnotationTag& traffic_annotation) override;
      int Read(net::IOBuffer* buf,
          int buf_len,
          net::CompletionOnceCallback callback) override;
      int SetReceiveBufferSize(int32_t size) override;
      int SetSendBufferSize(int32_t size) override;

    private:
      net::UDPSocket socket_;
      net::IPEndPoint& dest_addr_;
      //BeforeConnectCallback& before_connect_callback_;
      bool is_connected_;
      bool was_ever_used_;
      DISALLOW_COPY_AND_ASSIGN(UDPStreamSocket);
  };
}  // namespace network

#endif  // SERVICES_NETWORK_CATALYST_UDP_STREAM_SOCKET_H
