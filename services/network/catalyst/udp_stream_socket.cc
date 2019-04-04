// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dtls_stream_socket.h"

#include <inttypes.h>
#include <algorithm>
#include <utility>

#include "base/numerics/checked_math.h"
#include "base/numerics/ranges.h"
#include "base/numerics/safe_conversions.h"
#include "base/optional.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/auth.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_util.h"
#include "net/ssl/ssl_info.h"

namespace network {

  UDPStreamSocket::UDPStreamSocket(net::DatagramSocket::BindType bind_type,
      net::NetLog* net_log,
      const net::NetLogSource& source,
      net::IPEndPoint& remote_addr)
    : socket_(bind_type, net_log, source),
    dest_addr_(remote_addr),
    is_connected_(false),
    was_ever_used_(false),{}

  ~CatalystSocketWrapperImpl() {}

  //void UDPStreamSocket::SetBeforeConnectCallback(const BeforeCallback& before_connect_callback) {
    //before_connect_callback_ = before_connect_callback;
  //}

  int UDPStreamSocket::Connect(net::CompletionOnceCallback callback){
    int result = socket_.Open(dest_addr_.GetFamily());
    int kMinBufferSize = 0;
    int kMaxBufferSize = 128 * 1024;
    int clamped = base::ClampToRange(CatalystSocket::kMaxReadSize, kMinBufferSize, kMaxBufferSize);
    socket_.SetReceiveBufferSize(clamped);
    socket_.SetSendBufferSize(clamped);
    if (result == net::OK) {
      std::move(before_connect_callback_).Run(result);
      result = socket_.Connect(dest_addr_);
    }
    if (result == net::OK) {
      net::IPEndPoint& local_addr;
      result = socket_.GetLocalAddress(local_addr);
    }

    if (result != net::OK) {
      socket_.Close();
    } else {
      is_connected_ = true;
    }
    return result;
  }

  void UDPStreamSocket::Disconnect() {
    is_connected = false;
    was_ever_used_ = false;
    socket_.Close();
  }

  bool UDPStreamSocket::IsConnected() const {
    return is_connected_;
  }

  bool IsConnectedAndIdle() const {
    return is_connected_;
  }

  int GetPeerAddress(net::IPEndPoint *address) const {
    return socket_.GetPeerAddress(address);
  }

  int GetLocalAddress(net::IPEndPoint *address) const {
    return socket_.GetLocalAddress(address);
  }

  net::NetLogWithSource& NetLog() const {
    return socket_.NetLog();
  }

  bool WasEverUsed() const {
    return was_ever_used_;
  }

  bool WasAlpnNegotiated() const {
    return false;
  }

  bool GetNegotiatedProtocol() const {
    return net::kProtoUnknown;
  }

  bool GetSSLInfo(net::SSLInfo* ssl_info) {
    return false;
  }

  void GetConnectionAttempts(net::ConnectionAttempts* out) const {
  }

  void ClearConnectionAttempts() {
  }

  void AddConnectionATtempts(const ConnectionAttempts& attempts) {
  }

  int64_t GetTotalReceivedBytes() const {
    return 0;
  }

  void ApplySocketTag(const SocketTag& tag) {
  }

  int Write(
      net::IOBuffer* buf,
      int buf_len,
      net::CompletionOnceCallback callback,
      const net::NetworkTrafficAnnotationTag& traffic_annotation) {
    was_ever_used_ = true;
    return socket_.Write(buf, buf_len, std::move(callback));
  }

  int Read(net::IOBuffer* buf,
               int buf_len,
               net::CompletionOnceCallback callback) {
    was_ever_used_ = true;
    if (!is_connected_) {
      return net::ERR_SOCKET_NOT_CONNECTED;
    }
    return socket_.RecvFrom(buf, buf_len, &dest_addr_, std::move(callback));
  }

  int SetReceiveBufferSize(int32_t size) {
    socket_.SetReceiveBufferSize(size);
  }
  int SetSendBufferSize(int32_t size) {
    socket_.SetSendBufferSize(size);
  }

 private:

  int ClampUDPBufferSize(int requested_buffer_size) {
    constexpr int kMinBufferSize = 0;
    constexpr int kMaxBufferSize = 128 * 1024;
    return base::ClampToRange(requested_buffer_size, kMinBufferSize,
        kMaxBufferSize);
  }
}  // namespace network
