// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "services/network/catalyst/udp_stream_socket.h"

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
    was_ever_used_(false){
      LOG(INFO) << "Create UDPStreamSocket";
    }

  UDPStreamSocket::~UDPStreamSocket() { }

  //Always synchronous!
  int UDPStreamSocket::ConnectSync() {
    LOG(INFO) << "Start connectsync";
    int result = socket_.Open(dest_addr_.GetFamily());
    //if (result == net::OK) {
      //result = socket_.SetReceiveBufferSize(kMaxReadSize);
      //LOG(INFO) << "Done set recv size";
    //}
    //if (result == net::OK) {
      //result = socket_.SetSendBufferSize(kMaxReadSize);
      //LOG(INFO) << "Done set send size";
    //}
    if (result == net::OK) {
      LOG(INFO) << "Start connect";
      result = socket_.Connect(dest_addr_);
      LOG(INFO) << "Done connect";
    } 
    if (result != net::OK) {
      socket_.Close();
      LOG(INFO) << "Failure " << result;
    } else {
      is_connected_ = true;
      LOG(INFO) << "Successfully connected";
    }
    return result;
  }

  int UDPStreamSocket::Connect(net::CompletionOnceCallback callback){
    LOG(INFO) << "Start connect";
    int result = socket_.Open(dest_addr_.GetFamily());
    //socket_.SetReceiveBufferSize(kMaxReadSize);
    //socket_.SetSendBufferSize(kMaxReadSize);
    if (result == net::OK) {
      //std::move(before_connect_callback_).Run(result);
      result = socket_.Connect(dest_addr_);
    }
    if (result == net::OK) {
      net::IPEndPoint *local_addr = nullptr;
      result = socket_.GetLocalAddress(local_addr);
    }

    if (result != net::OK) {
      socket_.Close();
    } else {
      is_connected_ = true;
    }
    LOG(INFO) << "Done connect " << is_connected_;
    return result;
  }

  void UDPStreamSocket::Disconnect() {
    is_connected_ = false;
    was_ever_used_ = false;
    socket_.Close();
  }

  bool UDPStreamSocket::IsConnected() const {
    return is_connected_;
  }

  bool UDPStreamSocket::IsConnectedAndIdle() const {
    return is_connected_;
  }

  int UDPStreamSocket::GetPeerAddress(net::IPEndPoint *address) const {
    return socket_.GetPeerAddress(address);
  }

  int UDPStreamSocket::GetLocalAddress(net::IPEndPoint *address) const {
    return socket_.GetLocalAddress(address);
  }

  const net::NetLogWithSource& UDPStreamSocket::NetLog() const {
    return socket_.NetLog();
  }

  bool UDPStreamSocket::WasEverUsed() const {
    return was_ever_used_;
  }

  bool UDPStreamSocket::WasAlpnNegotiated() const {
    return false;
  }

  net::NextProto UDPStreamSocket::GetNegotiatedProtocol() const {
    return net::kProtoUnknown;
  }

  bool UDPStreamSocket::GetSSLInfo(net::SSLInfo* ssl_info) {
    return false;
  }

  void UDPStreamSocket::GetConnectionAttempts(net::ConnectionAttempts* out) const {
  }

  void UDPStreamSocket::ClearConnectionAttempts() {
  }

  void UDPStreamSocket::AddConnectionAttempts(const net::ConnectionAttempts& attempts) {
  }

  int64_t UDPStreamSocket::GetTotalReceivedBytes() const {
    return 0;
  }

  void UDPStreamSocket::ApplySocketTag(const net::SocketTag& tag) {
  }

  int UDPStreamSocket::Write(
      net::IOBuffer* buf,
      int buf_len,
      net::CompletionOnceCallback callback,
      const net::NetworkTrafficAnnotationTag& traffic_annotation) {
    was_ever_used_ = true;
    return socket_.Write(buf, buf_len, std::move(callback));
  }

  int UDPStreamSocket::Read(net::IOBuffer* buf,
               int buf_len,
               net::CompletionOnceCallback callback) {
    was_ever_used_ = true;
    if (!is_connected_) {
      return net::ERR_SOCKET_NOT_CONNECTED;
    }
    return socket_.Read(buf, 65500, std::move(callback));
  }

  int UDPStreamSocket::SetReceiveBufferSize(int32_t size) {
    return socket_.SetReceiveBufferSize(size);
  }

  int UDPStreamSocket::SetSendBufferSize(int32_t size) {
    return socket_.SetSendBufferSize(size);
  }
}  // namespace network
