// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SERVICES_NETWORK_CATALYST_SOCKET_H_
#define SERVICES_NETWORK_CATALYST_SOCKET_H_

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
    // A socket wrapper class that allows tests to substitute the default
    // implementation (implemented using net::UDPSocket) with a test
    // implementation.
    class SocketWrapper {
      public:
        virtual ~SocketWrapper() {}
        // This wrapper class forwards the functions to a concrete udp socket
        // implementation. Please refer to udp_socket_posix.h/udp_socket_win.h for
        // definitions.
        virtual int Connect(net::IPEndPoint* local_addr_out) = 0;
        virtual int Send(
            net::IOBuffer* buf,
            int buf_len,
            net::CompletionOnceCallback callback) = 0;
        virtual int Recv(net::IOBuffer* buf,
            int buf_len,
            net::CompletionOnceCallback callback) = 0;
    };
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

    static const uint32_t kMaxReadSize = 64 * 1024;
    // The limit on data length for a UDP packet is 65,507 for IPv4 and 65,535 for
    // IPv6.
    static const uint32_t kMaxPacketSize = kMaxReadSize - 1;
  protected:

    class CatalystSocketEventHandler;

    void OnResolveComplete(int rv);
    void OnDataFrame(scoped_refptr<net::IOBuffer> buffer,
                     size_t buffer_size);
    void OnSendComplete(int rv);
    void DoRecv();
    void OnError();
    void OnValidationComplete(IsCertificateValidCallback callback, int rv);

    scoped_refptr<net::IOBuffer> recvfrom_buffer_;

    std::unique_ptr<Delegate> delegate_;
    mojo::Binding<mojom::CatalystSocket> binding_;

    mojom::CatalystSocketClientPtr client_;

    std::unique_ptr<SocketWrapper> wrapped_socket_;

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

    base::WeakPtrFactory<CatalystSocket> weak_ptr_factory_;


    DISALLOW_COPY_AND_ASSIGN(CatalystSocket);
  private:
    void OnRecvComplete(int rv);
    // Helper method to create a new SocketWrapper.
    std::unique_ptr<CatalystSocket::SocketWrapper> CreateSocketWrapper(net::IPEndPoint& remote_addr) const;
};

}  // namespace network

#endif  // SERVICES_NETWORK_CATALYST_SOCKET_H_
