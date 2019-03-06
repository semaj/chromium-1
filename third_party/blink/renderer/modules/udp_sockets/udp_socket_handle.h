
#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_UDP_SOCKETS_UDP_SOCKET_HANDLE_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_UDP_SOCKETS_UDP_SOCKET_HANDLE_H_

#include <stdint.h>
#include <memory>
#include "base/single_thread_task_runner.h"
#include "services/network/public/mojom/catalyst_socket.mojom-blink.h"
#include "third_party/blink/renderer/platform/wtf/forward.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

namespace blink {

  class UDPSocketHandleClient;

  class UDPSocketHandle : public GarbageCollectedFinalized<UDPSocketHandle>{
    public:
      virtual ~UDPSocketHandle() = default;

      virtual void Connect(network::mojom::blink::CatalystSocketPtr,
          const String& user_agent_override,
          base::SingleThreadTaskRunner*) = 0;
      virtual void Send(const char* data, wtf_size_t) = 0;
      virtual void Close() = 0;
      virtual bool CertificateIsValid(const String& cert_chain) = 0;
      virtual void Trace(blink::Visitor* visitor) {}
  };

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_UDP_SOCKETS_UDP_SOCKET_HANDLE_H_
