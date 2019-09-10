// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SERVICES_NETWORK_CATALYST_SOCKET_H_
#define SERVICES_NETWORK_CATALYST_SOCKET_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>
#include <chrono>

#include "udp_stream_socket.h"

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
#include "net/socket/dtls_client_socket_impl.h"

class GURL;

namespace net {
  //class CertVerifier;
  //class X509Certificate;
  //class URLRequestContext;
  //class SSLInfo;
}  // namespace net

namespace network {
// Host of net::CatalystSocketChannel.
class COMPONENT_EXPORT(NETWORK_SERVICE) CatalystSocket : public mojom::CatalystSocket {
  public:
    static const uint32_t kMaxPendingSendRequests = 32;
    class Delegate {
      public:
        virtual ~Delegate() {}

        virtual net::URLRequestContext* GetURLRequestContext() = 0;
        // This function may delete |impl|.
        //virtual void OnLostConnectionToClient(CatalystSocket* impl) = 0;
        virtual bool CanReadRawCookies(const GURL& url) = 0;
        virtual void OnCreateURLRequest(int child_id,
            int frame_id,
            net::URLRequest* request) = 0;
    };

    CatalystSocket(std::unique_ptr<Delegate> delegate,
        mojom::CatalystSocketRequest request,
        int child_id,
        int frame_id,
        url::Origin origin
        //base::TimeDelta delay
        );
    ~CatalystSocket() override;

    // The renderer process is going away.
    // This function is virtual for testing.
    virtual void GoAway();

    // blink CatalystSocket implementation
    void SendFrame(const std::vector<uint8_t>& data) override;
    void Close() override;
    void Connect(mojom::CatalystSocketClientPtr client) override;
    void IsCertificateValid(const std::string& cert_chain,
                            IsCertificateValidCallback callback) override;

    static const uint32_t kMaxReadSize = 65535;

    static const uint32_t kSegmentSize = 1460;
    static const uint32_t kStartCwndSize = 10 * kSegmentSize;
    static constexpr float kBeta = 0.6;
    static constexpr float kAlpha = (3.0  * (kBeta / (2.0 - kBeta)));
    static const uint32_t kNumRTTs = 12;
    static const uint32_t kProbeSizeBytes = 2; 
  protected:

    class CatalystSocketEventHandler;

    void OnResolveComplete(int rv);
    void OnDataFrame(scoped_refptr<net::IOBuffer> buffer,
                     size_t buffer_size);
    void OnSendComplete(int rv);
    void DoRecv();
    void OnError();
    void OnConnect(int rv);
    void OnValidationComplete(IsCertificateValidCallback callback, int rv);

    void ProbeWrap(net::IOBuffer *buffer);
    void ProbeUnwrap(net::IOBuffer *buffer);
    void UpdateRTTs(std::chrono::milliseconds rtt);
    int CwndAvailable();
    void Loss(int num_losses);
    void Ack();
    std::chrono::milliseconds RTT();
    std::chrono::milliseconds Timeout();

    scoped_refptr<net::IOBuffer> recvfrom_buffer_;

    std::unique_ptr<Delegate> delegate_;
    mojo::Binding<mojom::CatalystSocket> binding_;

    mojom::CatalystSocketClientPtr client_;

    std::unique_ptr<net::DTLSClientSocketImpl> wrapped_socket_;

    // Delay used for per-renderer CatalystSocket throttling.
    base::TimeDelta delay_;

    int child_id_;
    int frame_id_;

    std::unique_ptr<net::HostResolver> resolver_;
    std::unique_ptr<net::HostResolver::ResolveHostRequest> resolve_request_;
    bool is_connected_;

    std::unique_ptr<net::CertVerifier> cert_verifier_;

    // The web origin to use for the CatalystSocket.
    const url::Origin origin_;


    float ssthresh_ = 65536 * 1.90;
    int cwnd_size_;
    int cwnd_used_;
    uint16_t last_seq_num_ = 0;
    std::map<std::uint16_t, std::chrono::steady_clock> unacked_;
    std::chrono::milliseconds rtts_[kNumRTTs];
    int rtt_index_ = 0;

    base::WeakPtrFactory<CatalystSocket> weak_ptr_factory_;
    DISALLOW_COPY_AND_ASSIGN(CatalystSocket);
  private:
    void OnRecvComplete(int rv);
    // Helper method to create a new SocketWrapper.
    std::unique_ptr<net::DTLSClientSocketImpl> CreateSocketWrapper(net::IPEndPoint& remote_addr) const;
};

}  // namespace network

#endif  // SERVICES_NETWORK_CATALYST_SOCKET_H_
