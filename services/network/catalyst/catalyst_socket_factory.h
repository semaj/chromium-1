// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SERVICES_NETWORK_CATALYST_SOCKET_FACTORY_H_
#define SERVICES_NETWORK_CATALYST_SOCKET_FACTORY_H_

#include <vector>

#include "base/containers/unique_ptr_adapters.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "services/network/public/mojom/catalyst_socket.mojom.h"
#include "catalyst_socket.h"
#include "catalyst_socket_throttler.h"

namespace url {
class Origin;
}  // namespace url

namespace network {

class NetworkContext;

class CatalystSocketFactory final {
 public:
  explicit CatalystSocketFactory(NetworkContext* context);
  ~CatalystSocketFactory();

  void CreateCatalystSocket(mojom::CatalystSocketRequest request,
                       int32_t process_id,
                       int32_t render_frame_id,
                       const url::Origin& origin);

 private:
  class Delegate;

  void OnLostConnectionToClient(CatalystSocket* impl);

  // The connections held by this factory.
  std::set<std::unique_ptr<CatalystSocket>, base::UniquePtrComparator> connections_;

  //CatalystSocketThrottler throttler_;

  // |context_| outlives this object.
  NetworkContext* const context_;

  DISALLOW_COPY_AND_ASSIGN(CatalystSocketFactory);
};

}  // namespace network

#endif  // SERVICES_NETWORK_CATALYST_SOCKET_FACTORY_H_
