// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "services/network/catalyst_socket.h"

#include <inttypes.h>
#include <algorithm>
#include <utility>
#include <time.h>
#include <chrono>

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
namespace {


using namespace std::chrono;
class CatalystSocketWrapperImpl : public CatalystSocket::SocketWrapper {

 public:
  CatalystSocketWrapperImpl(net::DatagramSocket::BindType bind_type,
                    net::NetLog* net_log,
                    const net::NetLogSource& source,
                    net::IPEndPoint& remote_addr)
      : socket_(bind_type, net_log, source),
        dest_addr_(remote_addr),
        tokens_(4000),
        refresh_time_(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count())
  {}

  ~CatalystSocketWrapperImpl() override {}

  int Connect(net::IPEndPoint* local_addr_out) override {
    int result = socket_.Open(dest_addr_.GetFamily());
    if (result == net::OK)
      result = socket_.Connect(dest_addr_);
    if (result == net::OK)
      result = socket_.GetLocalAddress(local_addr_out);

    if (result != net::OK) {
      socket_.Close();
      return result;
    }
    LOG(INFO) << "Wrapped socket Successfully connected";
    //socket_.SetReceiveBufferSize(ClampUDPBufferSize(CatalystSocket::kMaxReadSize));
    //socket_.SetSendBufferSize(ClampUDPBufferSize(CatalystSocket::kMaxReadSize));
    return result;
  }
  int Send(
      net::IOBuffer* buf,
      int buf_len,
      net::CompletionOnceCallback callback) override {
    //LOG(INFO) << "Wrapped socket trying SendTo";
    long now = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    long elapsed = (now - refresh_time_);
    refresh_time_ = now;
    tokens_ += elapsed * 500;
    if (tokens_ > 4000) {
      tokens_ = 4000;
    }
    LOG(INFO) << "Elapsed since last send " << elapsed;

    //LOG(INFO) << "SEND SIZE " << buf_len;
    if (buf_len < tokens_) {
      tokens_ -= buf_len;
      return socket_.Write(buf, buf_len, std::move(callback));
    } else {
      LOG(INFO) << "DROPPED";
      return net::OK;
    }
  }
  int Recv(net::IOBuffer* buf,
               int buf_len,
               net::CompletionOnceCallback callback) override {
    return socket_.Read(buf, buf_len, std::move(callback));
  }

 private:

  int ClampUDPBufferSize(int requested_buffer_size) {
    constexpr int kMinBufferSize = 0;
    constexpr int kMaxBufferSize = 128 * 1024;
    return base::ClampToRange(requested_buffer_size, kMinBufferSize,
        kMaxBufferSize);
  }

  int ConfigureOptions(mojom::UDPSocketOptionsPtr options) {
    if (!options)
      return net::OK;
    int result = net::OK;
    if (options->allow_address_reuse)
      result = socket_.AllowAddressReuse();
    if (result == net::OK && options->receive_buffer_size != 0) {
      result = socket_.SetReceiveBufferSize(
          ClampUDPBufferSize(options->receive_buffer_size));
    }
    if (result == net::OK && options->send_buffer_size != 0) {
      result = socket_.SetSendBufferSize(
          ClampUDPBufferSize(options->send_buffer_size));
    }
    return result;
  }

  net::UDPSocket socket_;
  net::IPEndPoint& dest_addr_;
  int tokens_;
  long refresh_time_;

  DISALLOW_COPY_AND_ASSIGN(CatalystSocketWrapperImpl);
};

}  // namespace

CatalystSocket::CatalystSocket(
    std::unique_ptr<Delegate> delegate,
    mojom::CatalystSocketRequest request,
    int child_id,
    int frame_id,
    url::Origin origin
    //base::TimeDelta delay)
    )
    : delegate_(std::move(delegate)),
      binding_(this, std::move(request)),
      //delay_(delay),
      child_id_(child_id),
      frame_id_(frame_id),
      resolver_(net::HostResolver::CreateDefaultResolver(nullptr)),
      is_connected_(false),
      cert_verifier_(std::make_unique<net::MultiThreadedCertVerifier>(net::CertVerifyProc::CreateDefault())),
      origin_(std::move(origin)),
      weak_ptr_factory_(this) {
  binding_.set_connection_error_handler(
      base::BindOnce(&CatalystSocket::OnError, base::Unretained(this)));
}

CatalystSocket::~CatalystSocket() {}

void CatalystSocket::OnDataFrame(
    scoped_refptr<net::IOBuffer> buffer,
    size_t buffer_size) {
  // TODO(darin): Avoid this copy.
  std::vector<uint8_t> data_to_pass(buffer_size);
  if (buffer_size > 0) {
    std::copy(buffer->data(), buffer->data() + buffer_size,
              data_to_pass.begin());
  }

  client_->OnDataFrame(data_to_pass);
}

void CatalystSocket::GoAway() {
  Close();
}

void CatalystSocket::OnSendComplete(int rv) {
  if (rv != net::OK) {
    OnError();
  }
}

void CatalystSocket::SendFrame(const std::vector<uint8_t>& data) {
  if (is_connected_) {
    // This is guaranteed by the maximum size enforced on mojo messages.
    DCHECK_LE(data.size(), static_cast<size_t>(INT_MAX));

    //LOG(INFO) << "First byte: " << data[0];
    // TODO(darin): Avoid this copy.
    net::IOBuffer *data_to_pass = new net::IOBuffer(data.size());
    std::copy(data.begin(), data.end(), data_to_pass->data());
    //LOG(INFO) << "Trying send.";
    int net_result = wrapped_socket_->Send(
        std::move(data_to_pass), data.size(),
        base::BindOnce(&CatalystSocket::OnSendComplete, 
                       weak_ptr_factory_.GetWeakPtr()));
    if (net_result != net::ERR_IO_PENDING) {
      //LOG(INFO) << "Executing send: " << net_result;
      OnSendComplete(net_result);
    } else {
      //LOG(INFO) << "Send was queued.";
    }
  } else {
    //LOG(INFO) << "Trying to send while not connected.";
  }
}

void CatalystSocket::OnValidationComplete(IsCertificateValidCallback callback, int rv) {
  if (rv >= 0) {
    //LOG(INFO) << "Validation successful";
    std::move(callback).Run(true);
  } else {
    //LOG(INFO) << "Validation UNsuccessful";
    std::move(callback).Run(false);
  }
}

void CatalystSocket::IsCertificateValid(const std::string& cert_chain,
                                        IsCertificateValidCallback callback) {
  net::CertificateList certs = net::X509Certificate::CreateCertificateListFromBytes(cert_chain.data(),
      cert_chain.size(),
      net::X509Certificate::FORMAT_PEM_CERT_SEQUENCE);
  if (certs.empty()) {
    std::move(callback).Run(false);
    return;
  }

  std::vector<bssl::UniquePtr<CRYPTO_BUFFER>> intermediates;
  for (size_t i = 1; i < certs.size(); ++i) {
    intermediates.push_back(bssl::UpRef(certs[i]->cert_buffer()));
  }

  scoped_refptr<net::X509Certificate> result(net::X509Certificate::CreateFromBuffer(
        bssl::UpRef(certs[0]->cert_buffer()), std::move(intermediates)));
  net::CertVerifyResult verify_result;
  std::unique_ptr<net::CertVerifier::Request> request;
  int rv = cert_verifier_->Verify(
      net::CertVerifier::RequestParams(result, origin_.host(), 0, std::string()),
      &verify_result,
      base::BindOnce(&CatalystSocket::OnValidationComplete, weak_ptr_factory_.GetWeakPtr(), std::move(callback)),
      &request,
      net::NetLogWithSource());
  if (rv != net::ERR_IO_PENDING) {
    OnValidationComplete(std::move(callback), rv);
  } else {
    //LOG(INFO) << "Validation queued";
  }
}

void CatalystSocket::OnRecvComplete(int rv) {
  if (rv >= 0) {
    //LOG(INFO) << "Recv successful complete";
    std::vector<uint8_t> vec(rv);
    std::copy(recvfrom_buffer_->data(), recvfrom_buffer_->data()+rv, vec.begin());
    client_->OnDataFrame(vec);
    DoRecv();
  } else {
    //LOG(INFO) << "Recv UNsuccessful complete";
    OnError();
  }
}

void CatalystSocket::DoRecv() {
  recvfrom_buffer_ =
      base::MakeRefCounted<net::IOBuffer>(static_cast<size_t>(65507));
  //LOG(INFO) << "Starting DoRecv";
  int net_result = wrapped_socket_->Recv(
      recvfrom_buffer_.get(), 65507,
      base::BindOnce(&CatalystSocket::OnRecvComplete,
        base::Unretained(this)));
  if (net_result != net::ERR_IO_PENDING) {
    //LOG(INFO) << "Recv queued";
    OnRecvComplete(net_result);
  }
}

void CatalystSocket::OnResolveComplete(int rv) {
  //LOG(INFO) << "Starting OnResolveComplete: " << rv;
  DCHECK(resolve_request_);
  auto results = resolve_request_->GetAddressResults();
  //LOG(INFO) << "Got results";
  DCHECK(results);
  if (results.value().empty()) {
    // some error
    //LOG(INFO) << "Resolution returned nothing!";
  } 
  //LOG(INFO) << "Looking at front";
  // Choose the first result, unless there's an IPV4 address
  net::IPEndPoint ip_endpoint = results.value().front();
  for (auto pr = results.value().begin(); pr < results.value().end(); pr++){
    if (pr->GetFamily() == net::ADDRESS_FAMILY_IPV4) {
      ip_endpoint = *pr;
      break;
    }
  }
  //LOG(INFO) << "Resolution: " << ip_endpoint;
  LOG(INFO) << "Resolved to: " << ip_endpoint.ToString();
  DCHECK(!wrapped_socket_);
  wrapped_socket_ = CreateSocketWrapper(ip_endpoint);
  net::IPEndPoint local_addr_out;
  int result = wrapped_socket_->Connect(&local_addr_out);
  if (result != net::OK) {
    wrapped_socket_.reset();
    return;
  }
  is_connected_ = true;
  client_->OnConnect();
  DoRecv();
}

void CatalystSocket::Connect(mojom::CatalystSocketClientPtr client) {

  client_ = std::move(client);
  LOG(INFO) << "Attempting to resolve host: " << origin_.GetURL();
  auto host_port = net::HostPortPair::FromURL(origin_.GetURL());
  resolve_request_ = resolver_->CreateRequest(host_port, net::NetLogWithSource(), base::nullopt);
  LOG(INFO) << "Starting resolution";
  int net_result = resolve_request_->Start(
      base::BindOnce(&CatalystSocket::OnResolveComplete, 
                     base::Unretained(this)));
  if (net_result != net::ERR_IO_PENDING)
    OnResolveComplete(net_result);
}

void CatalystSocket::Close() {
  wrapped_socket_.reset();
  is_connected_ = false;
}


void CatalystSocket::OnError() {

  //delegate_->OnLostConnectionToClient(this);
}

std::unique_ptr<CatalystSocket::SocketWrapper> CatalystSocket::CreateSocketWrapper(net::IPEndPoint& remote_addr)
    const {
  return std::make_unique<CatalystSocketWrapperImpl>(net::DatagramSocket::RANDOM_BIND,
                                             nullptr, net::NetLogSource(),
                                             remote_addr);
}

}  // namespace network
