// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/catalyst_sockets/catalyst_socket_manager.h"

#include <algorithm>
#include <string>
#include <vector>

#include "base/callback.h"
#include "base/feature_list.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/memory/weak_ptr.h"
#include "base/numerics/safe_conversions.h"
#include "base/task/post_task.h"
#include "content/browser/bad_message.h"
#include "content/browser/child_process_security_policy_impl.h"
#include "content/browser/ssl/ssl_error_handler.h"
#include "content/browser/ssl/ssl_manager.h"
#include "content/public/browser/browser_task_traits.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/render_frame_host.h"
#include "content/public/browser/render_process_host.h"
#include "content/public/browser/render_process_host_observer.h"
#include "content/public/browser/storage_partition.h"
#include "services/network/network_context.h"
#include "services/network/public/cpp/features.h"

namespace content {

namespace {

const char kCatalystSocketManagerKeyName[] = "catalyst_socket_manager";

}  // namespace

class CatalystSocketManager::Delegate final : public network::CatalystSocket::Delegate {
 public:
  explicit Delegate(CatalystSocketManager* manager) : manager_(manager) {}
  ~Delegate() override {}

  net::URLRequestContext* GetURLRequestContext() override {
    return manager_->GetURLRequestContext();
  }

  //void OnLostConnectionToClient(network::CatalystSocket* impl) override {
    //manager_->OnLostConnectionToClient(impl);
  //}

  //void OnSSLCertificateError(
      //std::unique_ptr<net::CatalystSocketEventInterface::SSLErrorCallbacks>
          //callbacks,
      //const GURL& url,
      //int child_id,
      //int frame_id,
      //const net::SSLInfo& ssl_info,
      //bool fatal) override {
    //ssl_error_handler_delegate_ =
        //std::make_unique<SSLErrorHandlerDelegate>(std::move(callbacks));
    //SSLManager::OnSSLCertificateSubresourceError(
        //ssl_error_handler_delegate_->GetWeakPtr(), url, child_id, frame_id,
        //ssl_info, fatal);
  //}

  bool CanReadRawCookies(const GURL& url) override {
    return ChildProcessSecurityPolicyImpl::GetInstance()->CanReadRawCookies(
        manager_->process_id_);
  }

  void OnCreateURLRequest(int child_id,
                          int frame_id,
                          net::URLRequest* url_request) override {
    //CatalystSocketHandshakeRequestInfoImpl::CreateInfoAndAssociateWithRequest(
        //child_id, frame_id, url_request);
  }

 //private:
  //class SSLErrorHandlerDelegate final : public SSLErrorHandler::Delegate {
   //public:
    //explicit SSLErrorHandlerDelegate(
        //std::unique_ptr<net::CatalystSocketEventInterface::SSLErrorCallbacks>
            //callbacks)
        //: callbacks_(std::move(callbacks)), weak_ptr_factory_(this) {}
    //~SSLErrorHandlerDelegate() override {}

    //base::WeakPtr<SSLErrorHandler::Delegate> GetWeakPtr() {
      //return weak_ptr_factory_.GetWeakPtr();
    //}

    //// SSLErrorHandler::Delegate methods
    //void CancelSSLRequest(int error, const net::SSLInfo* ssl_info) override {
      //DVLOG(3) << "SSLErrorHandlerDelegate::CancelSSLRequest"
               //<< " error=" << error << " cert_status="
               //<< (ssl_info ? ssl_info->cert_status
                            //: static_cast<net::CertStatus>(-1));
      //callbacks_->CancelSSLRequest(error, ssl_info);
    //}

    //void ContinueSSLRequest() override {
      //DVLOG(3) << "SSLErrorHandlerDelegate::ContinueSSLRequest";
      //callbacks_->ContinueSSLRequest();
    //}

   private:
    //std::unique_ptr<net::CatalystSocketEventInterface::SSLErrorCallbacks> callbacks_;

    //base::WeakPtrFactory<SSLErrorHandlerDelegate> weak_ptr_factory_;

    //DISALLOW_COPY_AND_ASSIGN(SSLErrorHandlerDelegate);
  //};

  //std::unique_ptr<SSLErrorHandlerDelegate> ssl_error_handler_delegate_;
  //// |manager_| outlives this object.
    CatalystSocketManager* const manager_;

  DISALLOW_COPY_AND_ASSIGN(Delegate);
//};
};

class CatalystSocketManager::Handle : public base::SupportsUserData::Data,
                                 public RenderProcessHostObserver {
 public:
  explicit Handle(CatalystSocketManager* manager) : manager_(manager) {}

  ~Handle() override {
    DCHECK(!manager_) << "Should have received RenderProcessHostDestroyed";
  }

  CatalystSocketManager* manager() const { return manager_; }

  // The network stack could be shutdown after this notification, so be sure to
  // stop using it before then.
  void RenderProcessHostDestroyed(RenderProcessHost* host) override {
    DCHECK(BrowserThread::CurrentlyOn(BrowserThread::UI));
    BrowserThread::DeleteSoon(BrowserThread::IO, FROM_HERE, manager_);
    manager_ = nullptr;
  }

 private:
  CatalystSocketManager* manager_;
};

// static
void CatalystSocketManager::CreateCatalystSocket(
    int process_id,
    int frame_id,
    url::Origin origin,
    network::mojom::CatalystSocketRequest request) {
  DCHECK(BrowserThread::CurrentlyOn(BrowserThread::UI));

  RenderProcessHost* host = RenderProcessHost::FromID(process_id);
  DCHECK(host);

  if (base::FeatureList::IsEnabled(network::features::kNetworkService)) {
    StoragePartition* storage_partition = host->GetStoragePartition();
    network::mojom::NetworkContext* network_context =
        storage_partition->GetNetworkContext();
    network_context->CreateCatalystSocket(std::move(request), process_id, frame_id,
                                     origin);
    return;
  }
  // |auth_handler| is provided only for the network service path.
  //DCHECK(!auth_handler);

  // Maintain a CatalystSocketManager per RenderProcessHost. While the instance of
  // CatalystSocketManager is allocated on the UI thread, it must only be used and
  // deleted from the IO thread.

  Handle* handle =
      static_cast<Handle*>(host->GetUserData(kCatalystSocketManagerKeyName));
  if (!handle) {
    handle = new Handle(
        new CatalystSocketManager(process_id, host->GetStoragePartition()));
    host->SetUserData(kCatalystSocketManagerKeyName, base::WrapUnique(handle));
    host->AddObserver(handle);
  } else {
    DCHECK(handle->manager());
  }

  base::PostTaskWithTraits(
      FROM_HERE, {BrowserThread::IO},
      base::BindOnce(&CatalystSocketManager::DoCreateCatalystSocket,
                     base::Unretained(handle->manager()), frame_id,
                     std::move(origin), std::move(request)));
}

CatalystSocketManager::CatalystSocketManager(int process_id,
                                   StoragePartition* storage_partition)
    : process_id_(process_id),
      context_destroyed_(false) {
  if (storage_partition) {
    url_request_context_getter_ = storage_partition->GetURLRequestContext();
     //This unretained pointer is safe because we destruct a CatalystSocketManager
     //only via CatalystSocketManager::Handle::RenderProcessHostDestroyed which
     //posts a deletion task to the IO thread.
    base::PostTaskWithTraits(
        FROM_HERE, {BrowserThread::IO},
        base::BindOnce(&CatalystSocketManager::ObserveURLRequestContextGetter,
                       base::Unretained(this)));
  }
}

CatalystSocketManager::~CatalystSocketManager() {
  DCHECK(BrowserThread::CurrentlyOn(BrowserThread::IO));

  if (!context_destroyed_ && url_request_context_getter_)
    url_request_context_getter_->RemoveObserver(this);

  for (const auto& impl : impls_) {
    impl->GoAway();
  }
}

void CatalystSocketManager::DoCreateCatalystSocket(
    int frame_id,
    url::Origin origin,
    network::mojom::CatalystSocketRequest request) {
  DCHECK(BrowserThread::CurrentlyOn(BrowserThread::IO));

  if (context_destroyed_) {
    request.ResetWithReason(
        network::mojom::CatalystSocket::kInsufficientResources,
        "Error in connection establishment: net::ERR_UNEXPECTED");
    return;
  }

  // Keep all network::CatalystSockets alive until either the client drops its
  // connection (see OnLostConnectionToClient) or we need to shutdown.

  impls_.insert(DoCreateCatalystSocketInternal(
      std::make_unique<Delegate>(this), std::move(request),
      process_id_, frame_id,
      std::move(origin), throttler_.CalculateDelay()));

  if (!throttling_period_timer_.IsRunning()) {
    throttling_period_timer_.Start(
        FROM_HERE,
        base::TimeDelta::FromMinutes(2),
        this,
        &CatalystSocketManager::ThrottlingPeriodTimerCallback);
  }
}

void CatalystSocketManager::ThrottlingPeriodTimerCallback() {
  throttler_.Roll();
  if (throttler_.IsClean())
    throttling_period_timer_.Stop();
}

std::unique_ptr<network::CatalystSocket> CatalystSocketManager::DoCreateCatalystSocketInternal(
    std::unique_ptr<network::CatalystSocket::Delegate> delegate,
    network::mojom::CatalystSocketRequest request,
    int child_id,
    int frame_id,
    url::Origin origin,
    base::TimeDelta delay) {
  return std::make_unique<network::CatalystSocket>(
      std::move(delegate), std::move(request),
      child_id, frame_id,
      std::move(origin));
      //delay);
}

net::URLRequestContext* CatalystSocketManager::GetURLRequestContext() {
  return url_request_context_getter_->GetURLRequestContext();
}

//void CatalystSocketManager::OnLostConnectionToClient(network::CatalystSocket* impl) {
  //// The client is no longer interested in this CatalystSocket.
  //impl->GoAway();
  //const auto it = impls_.find(impl);
  //DCHECK(it != impls_.end());
  //impls_.erase(it);
//}

void CatalystSocketManager::OnContextShuttingDown() {
  context_destroyed_ = true;
  url_request_context_getter_ = nullptr;
  for (const auto& impl : impls_) {
    impl->GoAway();
  }
  impls_.clear();
}

void CatalystSocketManager::ObserveURLRequestContextGetter() {
  DCHECK(BrowserThread::CurrentlyOn(BrowserThread::IO));
  if (!url_request_context_getter_->GetURLRequestContext()) {
    context_destroyed_ = true;
    url_request_context_getter_ = nullptr;
    return;
  }
  url_request_context_getter_->AddObserver(this);
}

}  // namespace content
