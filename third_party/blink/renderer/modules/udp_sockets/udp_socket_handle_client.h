#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_UDP_SOCKETS_UDP_SOCKET_HANDLE_CLIENT_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_UDP_SOCKETS_UDP_SOCKET_HANDLE_CLIENT_H_

#include <stdint.h>
#include <memory>
#include "third_party/blink/renderer/modules/modules_export.h"
#include "third_party/blink/renderer/platform/heap/handle.h"
#include "third_party/blink/renderer/platform/wtf/forward.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

class MODULES_EXPORT UDPSocketHandleClient : public GarbageCollectedMixin {
 public:
  virtual ~UDPSocketHandleClient() = default;
  virtual void DidConnect() {}
  virtual void DidReceiveRTTTokens(uint64_t tokens) {}
  virtual void DidReceiveMessage(std::unique_ptr<Vector<char>>) {}
  virtual void DidError() {}
  virtual void DidClose() {}
  void Trace(blink::Visitor* visitor) override {}

 protected:
  UDPSocketHandleClient() = default;
};

}  // namespace blink

#endif // THIRD_PARTY_BLINK_RENDERER_MODULES_UDP_SOCKETS_UDPSOCKET_HANDLE_CLIENT_H_
