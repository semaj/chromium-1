// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/udp_sockets/udp_socket_handle_impl.h"

#include "base/single_thread_task_runner.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/modules/udp_sockets/udp_socket_handle_client.h"
#include "third_party/blink/renderer/platform/network/http_names.h"
#include "third_party/blink/renderer/platform/network/network_log.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

UDPSocketHandleImpl::UDPSocketHandleImpl(UDPSocketHandleClient* client)
    : client_(client), client_binding_(this) {
  NETWORK_DVLOG(1) << this << " created";
}

UDPSocketHandleImpl::~UDPSocketHandleImpl() {
  NETWORK_DVLOG(1) << this << " deleted";

  if (udp_socket_) {
    udp_socket_->Close();
  }
}

void UDPSocketHandleImpl::Connect(network::mojom::blink::CatalystSocketPtr udp_socket,
                                  const String& user_agent_override,
                                  base::SingleThreadTaskRunner* task_runner) {
  NETWORK_DVLOG(1) << "Handle Connect Begin";
  DCHECK(!udp_socket_);
  udp_socket_ = std::move(udp_socket);
  //udp_socket_.set_connection_error_with_reason_handler(WTF::Bind(
      //&UDPSocketHandleImpl::OnError, WTF::Unretained(this)));
  DCHECK(udp_socket_);

  NETWORK_DVLOG(1) << this << " connect()";

  network::mojom::blink::CatalystSocketClientPtr client_proxy;
  client_binding_.Bind(mojo::MakeRequest(&client_proxy, task_runner),
                       task_runner);
  udp_socket_->Connect(std::move(client_proxy));
}

bool UDPSocketHandleImpl::CertificateIsValid(const String& cert_chain) {
  bool is_valid = false;
  udp_socket_->IsCertificateValid(std::move(cert_chain), &is_valid);
  return is_valid;
}

void UDPSocketHandleImpl::Send(const char* data, wtf_size_t size) {
  DCHECK(udp_socket_);

  NETWORK_DVLOG(1) << this << " send(" << "(data size = " << size << "))";
  NETWORK_DVLOG(1) << "First byte: " << data[0];

  // TODO(darin): Avoid this copy.
  Vector<uint8_t> data_to_pass(size);
  std::copy(data, data + size, data_to_pass.begin());

  udp_socket_->SendFrame(data_to_pass);
}

void UDPSocketHandleImpl::Close() {
  DCHECK(udp_socket_);

  NETWORK_DVLOG(1) << this << " close()";

  udp_socket_->Close();
  UDPSocketHandleClient* client = client_;
  Disconnect();
  if (!client)
    return;
  client->DidClose();
}

void UDPSocketHandleImpl::Disconnect() {
  udp_socket_.reset();
  client_ = nullptr;
}

void UDPSocketHandleImpl::OnError(uint32_t custom_reason) {
  // Our connection to the UDPSocket was dropped. This could be due to
  // exceeding the maximum number of concurrent udp_sockets from this process.
  //String failure_message;
  //if (custom_reason ==
      //network::mojom::blink::CatalystSocket::kInsufficientResources) {
    //failure_message =
        //description.empty()
            //? "Insufficient resources"
            //: String::FromUTF8(description.c_str(), description.size());
  //} else {
    //DCHECK(description.empty());
    //failure_message = "Unspecified reason";
  //}
  UDPSocketHandleClient* client = client_;
  Disconnect();
  if (!client)
    return;

  client->DidError();
}

void UDPSocketHandleImpl::OnConnect() {
  NETWORK_DVLOG(1) << this << "OnConnect";
  client_->DidConnect();
}

void UDPSocketHandleImpl::OnRTT(uint64_t tokens) {
  client_->DidReceiveRTTTokens(tokens);
}

void UDPSocketHandleImpl::OnDataFrame(const Vector<uint8_t>& data) {
  LOG(INFO) << "RECEIVE OnDataFrame";
  LOG(INFO) << "START RENDERER RECEIVE";
  NETWORK_DVLOG(1) << this << " OnDataFrame(" << "(data size = " << data.size() << "))";
  if (!client_)
    return;

  const char* data_to_pass =
      reinterpret_cast<const char*>(data.IsEmpty() ? nullptr : &data[0]);
  //Vector<char> vector_data;
  //vector_data.Append(data_to_pass, SafeCast<uint32_t>(size));
  std::unique_ptr<Vector<char>> binary_data =
      std::make_unique<Vector<char>>();
  //binary_data->swap(vector_data);
  binary_data->Append(data_to_pass, SafeCast<uint32_t>(data.size()));
  client_->DidReceiveMessage(std::move(binary_data));
}

void UDPSocketHandleImpl::Trace(blink::Visitor* visitor) {
  visitor->Trace(client_);
  UDPSocketHandle::Trace(visitor);
}


}  // namespace blink
