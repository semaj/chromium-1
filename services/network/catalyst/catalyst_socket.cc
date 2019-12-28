// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "catalyst_socket.h"

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
#include "net/base/host_port_pair.h"

namespace network {

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
      counter_(0),
      resolver_(net::HostResolver::CreateDefaultResolver(nullptr)),
      is_connected_(false),
      cert_verifier_(std::make_unique<net::MultiThreadedCertVerifier>(net::CertVerifyProc::CreateDefault())),
      origin_(std::move(origin)),
      weak_ptr_factory_(this) {
  binding_.set_connection_error_handler(
      base::BindOnce(&CatalystSocket::OnError, base::Unretained(this)));
  for (uint64_t i = 0; i < kNumRTTs; i++) {
    rtts_[i] = kStartRTTns;
  }
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
  if (rv != net::OK && rv < 0) {
    //LOG(INFO) << "Send error " << rv;
    OnError();
  }
}

void CatalystSocket::OnRTTTimer() {

  // Create an iterator pointing to start of set
  auto it = unacked_.begin();

  // Iterate over the set till end
  int losses = 0;
  uint64_t lost_size = 0;
  while(it != unacked_.end())
  {
    auto ack_num = *it;
    auto timeout = Timeout();
    auto now = std::chrono::steady_clock::now();
    auto sent_time = unacked_sent_at_[ack_num];
    uint64_t elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(now - sent_time).count();
    if (elapsed > timeout) {
      //LOG(INFO) << "Loss " << ack_num << " elapsed: " << elapsed;
      lost_size += unacked_sizes_[ack_num];
      it = unacked_.erase(it);
      unacked_sizes_.erase(ack_num);
      losses++;
    } else {
      it++;
    }
  }
  if (losses > 0) {
    Loss(losses);
    DCHECK_LE(lost_size, cwnd_used_);
    cwnd_used_ -= lost_size;
  }
  //LOG(INFO) << "AVAILABLE " << (cwnd_size_ - cwnd_used_);
  client_->OnRTT(cwnd_size_ - cwnd_used_);
  //client_->OnRTT(1000000);
  rtt_timer_.Start(
      FROM_HERE,
      base::TimeDelta::FromNanoseconds(RTT()),
      this,
      &CatalystSocket::OnRTTTimer
      );
}

void CatalystSocket::SendFrame(const std::vector<uint8_t>& data) {
  if (is_connected_) {
    // This is guaranteed by the maximum size enforced on mojo messages.
    DCHECK_LE(data.size(), static_cast<size_t>(INT_MAX));

    // uncomment this later
    //if (data.size() > (cwnd_size_ - cwnd_used_)) {
      //LOG(INFO) << "INVALID SEND! NOT ENOUGH TOKENS.";
      //OnError();
      //return;
    //}
    //DVLOG(1) << "First byte: " << data[0];
    // TODO(darin): Avoid this copy.
    int total_data_size = data.size() + kProbeSizeBytes;
    net::IOBuffer *data_to_pass = new net::IOBuffer(total_data_size);
    //LOG(INFO) << "Sending probe " << last_seq_num_;
    unsigned char * last_seq_num_byte_pointer_ = reinterpret_cast<unsigned char*>(&last_seq_num_);
    std::copy(last_seq_num_byte_pointer_+1, last_seq_num_byte_pointer_+kProbeSizeBytes, data_to_pass->data());
    std::copy(last_seq_num_byte_pointer_, last_seq_num_byte_pointer_+1, data_to_pass->data()+1);
    std::copy(data.begin(), data.end(), data_to_pass->data()+kProbeSizeBytes);

    //LOG(INFO) << "Trying send message of size " << data.size();
    unacked_sent_at_[last_seq_num_] = std::chrono::steady_clock::now();
    unacked_.insert(last_seq_num_);
    unacked_sizes_[last_seq_num_] = data.size();
    last_seq_num_++;
    const net::NetworkTrafficAnnotationTag bad_traffic_annotation =
      net::DefineNetworkTrafficAnnotation("bad", R"(
          trigger: "Chrome sends this when [obscure event that is not related to anything user-perceivable]."
          data: "This sends everything the feature needs to know."
          policy_exception_justification: "None."
          )");
    int net_result = wrapped_socket_->Write(
        std::move(data_to_pass), total_data_size,
        base::BindOnce(&CatalystSocket::OnSendComplete,
                       weak_ptr_factory_.GetWeakPtr()),
        bad_traffic_annotation);
    if (net_result != net::ERR_IO_PENDING) {
      //DVLOG(1) << "Executing send: " << net_result;
      OnSendComplete(net_result);
    } else {
      //DVLOG(1) << "Send was queued.";
    }
  } else {
    LOG(INFO) << "Trying to send while not connected.";
  }
}

void CatalystSocket::OnValidationComplete(IsCertificateValidCallback callback, int rv) {
  if (rv >= 0) {
    //DVLOG(1) << "Validation successful";
    std::move(callback).Run(true);
  } else {
    //DVLOG(1) << "Validation UNsuccessful";
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
    //DVLOG(1) << "Validation queued";
  }
}

// nanoseconds
uint64_t CatalystSocket::RTT() {
  uint64_t sum = 0;
  for (uint64_t i = 0; i < kNumRTTs; i++) {
    sum += rtts_[i];
  }
  auto avg = sum / kNumRTTs;
  return avg;
}

uint64_t CatalystSocket::Timeout() {
  return RTT() * kRTTFactorTimeout;
}

void CatalystSocket::Ack(uint64_t packet_size) {
  int32_t new_cwnd;
  if (phase_ == kPhaseSlowStart) {
    //LOG(INFO) << "SlowStart";
    new_cwnd = cwnd_size_ + round(kAlpha * kSegmentSize);
    if (new_cwnd >= ssthresh_) {
      phase_ = kPhaseCongestionAvoidance;
    }
  } else {
    //LOG(INFO) << "CongestionAvoidance";
    new_cwnd = cwnd_size_ + ((kAlpha * kSegmentSize) * ((double) kSegmentSize / (double) cwnd_size_));
  }
  //LOG(INFO) << "ACK old " << cwnd_size_ << " new " << new_cwnd;
  DCHECK_NE(cwnd_size_, new_cwnd);
  cwnd_size_ = new_cwnd;
  DCHECK_LE(packet_size, cwnd_used_);
  cwnd_used_ -= packet_size;
}

void CatalystSocket::Loss(int num_losses) {
  if (num_losses == 0) {
    return;
  }
  int32_t new_cwnd;
  if (phase_ == kPhaseSlowStart) {
    new_cwnd = cwnd_size_ * (1.0 - kBeta);
  } else {
    if (num_losses == 1) {
      new_cwnd = cwnd_size_ * (1.0 - kBeta);
    } else {
      phase_ = kPhaseSlowStart;
      ssthresh_ = cwnd_size_ * (1.0 - kBeta);
      new_cwnd = kAlpha * kSegmentSize;
    }
  }
  if (new_cwnd < (float) kSegmentSize) {
    new_cwnd = kSegmentSize;
  }
  cwnd_size_ = new_cwnd;
  if (cwnd_size_ < cwnd_used_) {
    cwnd_used_ = cwnd_size_;
  }
  //LOG(INFO) << "Loss cwnd: " << cwnd_size_ << " used: " << cwnd_used_;
}


void CatalystSocket::OnRecvComplete(int rv) {
  if (!wrapped_socket_) {
    LOG(INFO) << "CatalystSocket closed before onrecv completed.";
    return;
  }
  if (rv >= (int) kProbeSizeBytes) {
    uint16_t ack_num;
    unsigned char * ack_num_pointer = reinterpret_cast<unsigned char*>(&ack_num);
    std::copy(recvfrom_buffer_->data(), recvfrom_buffer_->data()+1, ack_num_pointer+1);
    std::copy(recvfrom_buffer_->data()+1, recvfrom_buffer_->data()+kProbeSizeBytes, ack_num_pointer);
    if (ack_num > 0) {
      //LOG(INFO) << "Received an ack " << ack_num;
      auto received_time = std::chrono::steady_clock::now();
      auto sent_time = unacked_sent_at_[ack_num];
      auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(received_time - sent_time);
      if (unacked_.erase(ack_num) > 0) {
        Ack(unacked_sizes_[ack_num]);
        unacked_sizes_.erase(ack_num);
      } else { // expired
        //LOG(INFO) << "False loss " << ack_num << " elapsed: " << elapsed.count();
      }
      //LOG(INFO) << "Elapsed: " << elapsed.count();
      rtts_[rtt_index_] = elapsed.count();
      rtt_index_++;
      rtt_index_ = rtt_index_ % kNumRTTs;
      unacked_sent_at_.erase(ack_num);
      //LOG(INFO) << "RTT: " << RTT();
    } else {
      LOG(INFO) << "Received a payload " << rv - kProbeSizeBytes << " counter " << ++counter_;
      std::vector<uint8_t> vec(rv - kProbeSizeBytes);
      std::copy(recvfrom_buffer_->data()+kProbeSizeBytes, recvfrom_buffer_->data()+rv, vec.begin());
      LOG(INFO) << "SEND OnDataFrame";
      client_->OnDataFrame(vec);
    }
  } else {
    //LOG(INFO) << "Recv UNsuccessful complete";
    OnError();
  }
  DoRecv();
}

void CatalystSocket::DoRecv() {
  recvfrom_buffer_ =
      base::MakeRefCounted<net::IOBuffer>(static_cast<size_t>(kMaxReadSize));
  //DVLOG(1) << "Starting DoRecv";
  int net_result = wrapped_socket_->Read(
      recvfrom_buffer_.get(), kMaxReadSize,
      base::BindOnce(&CatalystSocket::OnRecvComplete,
        base::Unretained(this)));
  if (net_result != net::ERR_IO_PENDING) {
    //DVLOG(1) << "Recv queued";
    OnRecvComplete(net_result);
  }
}

void CatalystSocket::OnResolveComplete(int rv) {
  LOG(INFO) << "Starting OnResolveComplete: " << rv;
  DCHECK(resolve_request_);
  auto results = resolve_request_->GetAddressResults();
  LOG(INFO) << "Got results";
  DCHECK(results);
  if (results.value().empty()) {
    // some error
    LOG(INFO) << "Resolution returned nothing!";
  }
  //LOG(INFO) << "Looking at front";
  // Choose the first result, unless there's an IPV4 address
  net::IPEndPoint ip_endpoint = results.value().front();
  net::IPEndPoint ip_endpoint2 = *(new net::IPEndPoint(ip_endpoint.address(), 443));
  for (auto pr = results.value().begin(); pr < results.value().end(); pr++){
    if (pr->GetFamily() == net::ADDRESS_FAMILY_IPV4) {
      ip_endpoint = *pr;
      break;
    }
  }
  //DVLOG(1) << "Resolution: " << ip_endpoint;
  LOG(INFO) << "Resolved to: " << ip_endpoint2.ToString();
  wrapped_socket_ = CreateSocketWrapper(ip_endpoint2);
  int result = wrapped_socket_->Connect(base::BindOnce(&CatalystSocket::OnConnect, base::Unretained(this)));

  if (result != net::ERR_IO_PENDING) {
    OnConnect(result);
  }
}

void CatalystSocket::OnConnect(int result) {
  if (!wrapped_socket_) {
    LOG(INFO) << "CatalystSocket closed before connect completed.";
    return;
  }
  if (result == net::OK) {
    is_connected_ = true;
    client_->OnConnect();
    //rtt_timer_.Start(
        //FROM_HERE,
        //base::TimeDelta::FromNanoseconds(RTT()),
        //this,
        //&CatalystSocket::OnRTTTimer
        //);
    DoRecv();
  } else {
    wrapped_socket_.reset();
  }
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
  client_->OnError(0);
  //delegate_->OnLostConnectionToClient(this);
}

std::unique_ptr<net::DTLSClientSocketImpl> CatalystSocket::CreateSocketWrapper(net::IPEndPoint& remote_addr)
    const {
  net::SSLConfig ssl_config;
  delegate_->GetURLRequestContext()->ssl_config_service()->GetSSLConfig(&ssl_config);
  const net::SSLClientSocketContext ssl_context = net::SSLClientSocketContext(delegate_->GetURLRequestContext()->cert_verifier(),
       nullptr,
       delegate_->GetURLRequestContext()->transport_security_state(),
       delegate_->GetURLRequestContext()->cert_transparency_verifier(),
       delegate_->GetURLRequestContext()->ct_policy_enforcer(),
       nullptr /* Disables SSL session caching */);
  std::unique_ptr<net::UDPStreamSocket> stream_socket = std::make_unique<net::UDPStreamSocket>(net::DatagramSocket::RANDOM_BIND, nullptr, net::NetLogSource(), remote_addr);
  return std::make_unique<net::DTLSClientSocketImpl>(std::move(stream_socket), net::HostPortPair::FromIPEndPoint(remote_addr), ssl_config, ssl_context);

}

}  // namespace network
