#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_UDP_SOCKETS_DOM_UDP_SOCKET_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_UDP_SOCKETS_DOM_UDP_SOCKET_H_

#include <stddef.h>
#include <stdint.h>
#include <memory>
#include "third_party/blink/renderer/bindings/core/v8/active_script_wrappable.h"
#include "third_party/blink/renderer/core/dom/events/event_listener.h"
#include "third_party/blink/renderer/core/dom/events/event_target.h"
#include "third_party/blink/renderer/core/typed_arrays/array_buffer_view_helpers.h"
#include "third_party/blink/renderer/modules/event_target_modules.h"
#include "third_party/blink/renderer/modules/modules_export.h"
#include "third_party/blink/renderer/modules/udp_sockets/udp_socket_handle.h"
#include "third_party/blink/renderer/modules/udp_sockets/udp_socket_handle_client.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/handle.h"
#include "third_party/blink/renderer/platform/timer.h"
#include "third_party/blink/renderer/platform/wtf/deque.h"
#include "third_party/blink/renderer/platform/wtf/forward.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/core/execution_context/context_lifecycle_state_observer.h"

namespace blink {

  class DOMArrayBuffer;
  class ExceptionState;
  class ExecutionContext;
  class StringOrStringSequence;

  class MODULES_EXPORT DOMUDPSocket : public EventTargetWithInlineData,
                                      public ActiveScriptWrappable<DOMUDPSocket>,
                                      public ContextLifecycleStateObserver,
                                      public UDPSocketHandleClient {
    DEFINE_WRAPPERTYPEINFO();
    USING_GARBAGE_COLLECTED_MIXIN(DOMUDPSocket);

    public:
    // DOMWebSocket instances must be used with a wrapper since this class's
    // lifetime management is designed assuming the V8 holds a ref on it while
    // hasPendingActivity() returns true.
    static DOMUDPSocket* Create(ExecutionContext*, 
                                ExceptionState&);

    ~DOMUDPSocket() override;

    enum State { kConnecting = 0, kOpen = 1, kClosed = 2 };

    void Connect(ExceptionState&);

    void send(NotShared<DOMArrayBufferView>, ExceptionState&);
    //void send(NotShared<DOMArrayBufferView>, ExceptionState&);

    void close(ExceptionState&);

    bool certIsValid(const String& cert_chain, ExceptionState&);

    State readyState() const;

    DEFINE_ATTRIBUTE_EVENT_LISTENER(open, kOpen);
    DEFINE_ATTRIBUTE_EVENT_LISTENER(message, kMessage);
    DEFINE_ATTRIBUTE_EVENT_LISTENER(error, kError);
    DEFINE_ATTRIBUTE_EVENT_LISTENER(close, kClose);

    //// EventTarget functions.
    const AtomicString& InterfaceName() const override;
    ExecutionContext* GetExecutionContext() const override;


    //// PausableObject functions.
    void ContextDestroyed(ExecutionContext*) override;
    void ContextLifecycleStateChanged(mojom::FrameLifecycleState) override;

    // ScriptWrappable functions.
    // Prevent this instance from being collected while it's not in CLOSED
    // state.
    bool HasPendingActivity() const final;


    //// UDPSocketHandleClient functions.
    void DidConnect() override;
    void DidReceiveMessage(std::unique_ptr<Vector<char>>) override;
    void DidError() override;
    void DidClose() override;

    void Trace(blink::Visitor*) override;

    explicit DOMUDPSocket(ExecutionContext*);

    private:
    class EventQueue final : public GarbageCollectedFinalized<EventQueue> {
     public:
      static EventQueue* Create(EventTarget* target) {
        return MakeGarbageCollected<EventQueue>(target);
      }

      explicit EventQueue(EventTarget*);
      ~EventQueue();

      // Dispatches the event if this queue is active.
      // Queues the event if this queue is suspended.
      // Does nothing otherwise.
      void Dispatch(Event* /* event */);

      bool IsEmpty() const;

      void Pause();
      void Unpause();
      void ContextDestroyed();

      bool IsPaused();

      void Trace(blink::Visitor*);

     private:
      enum State {
        kActive,
        kPaused,
        kUnpausePosted,
        kStopped,
      };

      // Dispatches queued events if this queue is active.
      // Does nothing otherwise.
      void DispatchQueuedEvents();
      void UnpauseTask();

      State state_;
      Member<EventTarget> target_;
      HeapDeque<Member<Event>> events_;
    };

    void ReleaseHandle();
    // Adds a console message with JSMessageSource and ErrorMessageLevel.
    void LogError(const String& message);


    Member<EventQueue> event_queue_;
    Member<UDPSocketHandle> handle_;

    State state_;

  };
}
#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_UDP_SOCKETS_DOM_UDP_SOCKET_H_
