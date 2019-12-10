
#include "services/service_manager/public/cpp/interface_provider.h"
#include "third_party/blink/renderer/modules/udp_sockets/dom_udp_socket.h"

#include "base/location.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/platform/web_insecure_request_policy.h"
#include "third_party/blink/renderer/bindings/core/v8/script_controller.h"
#include "third_party/blink/renderer/bindings/core/v8/source_location.h"
#include "third_party/blink/renderer/bindings/core/v8/string_or_string_sequence.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/events/message_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/fileapi/blob.h"
#include "third_party/blink/renderer/core/frame/csp/content_security_policy.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/use_counter.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer_view.h"
#include "third_party/blink/renderer/modules/udp_sockets/rtt_event.h"
#include "third_party/blink/renderer/modules/udp_sockets/udp_socket_handle_impl.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
#include "third_party/blink/renderer/platform/heap/persistent.h"
#include "third_party/blink/renderer/platform/histogram.h"
#include "third_party/blink/renderer/platform/network/network_log.h"
#include "third_party/blink/renderer/platform/weborigin/known_ports.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/assertions.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/cstring.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

//static const size_t kMaxByteSizeForHistogram = 100 * 1000 * 1000;
//static const int32_t kBucketCountForMessageSizeHistogram = 50;

namespace blink {

DOMUDPSocket::EventQueue::EventQueue(EventTarget* target)
    : state_(kActive), target_(target) {}

DOMUDPSocket::EventQueue::~EventQueue() {
  ContextDestroyed();
}

void DOMUDPSocket::EventQueue::Dispatch(Event* event) {
  switch (state_) {
    case kActive:
      DCHECK(events_.IsEmpty());
      DCHECK(target_->GetExecutionContext());
      target_->DispatchEvent(*event);
      break;
    case kPaused:
    case kUnpausePosted:
      events_.push_back(event);
      break;
    case kStopped:
      DCHECK(events_.IsEmpty());
      // Do nothing.
      break;
  }
}

bool DOMUDPSocket::EventQueue::IsEmpty() const {
  return events_.IsEmpty();
}

void DOMUDPSocket::EventQueue::Pause() {
  if (state_ == kStopped || state_ == kPaused)
    return;

  state_ = kPaused;
}

void DOMUDPSocket::EventQueue::Unpause() {
  if (state_ != kPaused || state_ == kUnpausePosted)
    return;

  state_ = kUnpausePosted;
  target_->GetExecutionContext()
      ->GetTaskRunner(TaskType::kUDPSocket)
      ->PostTask(FROM_HERE,
                 WTF::Bind(&EventQueue::UnpauseTask, WrapWeakPersistent(this)));
}

void DOMUDPSocket::EventQueue::ContextDestroyed() {
  if (state_ == kStopped)
    return;

  state_ = kStopped;
  events_.clear();
}

bool DOMUDPSocket::EventQueue::IsPaused() {
  return state_ == kPaused || state_ == kUnpausePosted;
}

void DOMUDPSocket::EventQueue::DispatchQueuedEvents() {
  if (state_ != kActive)
    return;

  HeapDeque<Member<Event>> events;
  events.Swap(events_);
  while (!events.IsEmpty()) {
    if (state_ == kStopped || state_ == kPaused || state_ == kUnpausePosted)
      break;
    DCHECK_EQ(state_, kActive);
    DCHECK(target_->GetExecutionContext());
    target_->DispatchEvent(*events.TakeFirst());
    // |this| can be stopped here.
  }
  if (state_ == kPaused || state_ == kUnpausePosted) {
    while (!events_.IsEmpty())
      events.push_back(events_.TakeFirst());
    events.Swap(events_);
  }
}

void DOMUDPSocket::EventQueue::UnpauseTask() {
  if (state_ != kUnpausePosted)
    return;
  state_ = kActive;
  DispatchQueuedEvents();
}

void DOMUDPSocket::EventQueue::Trace(blink::Visitor* visitor) {
  visitor->Trace(target_);
  visitor->Trace(events_);
}

//const size_t kMaxReasonSizeInBytes = 123;

static void SetInvalidStateErrorForSendMethod(ExceptionState& exception_state) {
  exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                    "Still in CONNECTING state.");
}

DOMUDPSocket::DOMUDPSocket(ExecutionContext* context)
    : ContextLifecycleStateObserver(context),
      event_queue_(EventQueue::Create(this)),
      state_(kConnecting),
      counter_(0) {}

DOMUDPSocket::~DOMUDPSocket() {
  DCHECK(!handle_);
}

void DOMUDPSocket::LogError(const String& message) {
  if (GetExecutionContext()) {
    GetExecutionContext()->AddConsoleMessage(
        ConsoleMessage::Create(kJSMessageSource, kErrorMessageLevel, message));
  }
}

DOMUDPSocket* DOMUDPSocket::Create(ExecutionContext* context,
                                   ExceptionState& exception_state) {
  DOMUDPSocket* udpsocket = MakeGarbageCollected<DOMUDPSocket>(context);

  udpsocket->Connect(exception_state);

  if (exception_state.HadException())
    return nullptr;

  return udpsocket;
}

void DOMUDPSocket::Connect(ExceptionState& exception_state) {
  UseCounter::Count(GetExecutionContext(), WebFeature::kUDPSocket);


  handle_ = MakeGarbageCollected<UDPSocketHandleImpl>(this);

  NETWORK_DVLOG(1) << "UDPSocket " << this << " connect()";
  network::mojom::blink::CatalystSocketPtr socket_ptr;
  auto socket_request = mojo::MakeRequest(&socket_ptr);
  service_manager::InterfaceProvider* interface_provider =
      GetExecutionContext()->GetInterfaceProvider();
  if (interface_provider)
    interface_provider->GetInterface(std::move(socket_request));
  NETWORK_DVLOG(1) << "REQUEST MADE";
  handle_->Connect(std::move(socket_ptr),
      GetExecutionContext()->UserAgent(),
      GetExecutionContext()->GetTaskRunner(TaskType::kNetworking).get());
  NETWORK_DVLOG(1) << "CONNECT DONE";
  return;
}

void DOMUDPSocket::send(NotShared<DOMArrayBufferView> array_buffer_view,
                        ExceptionState& exception_state) {
  DCHECK(array_buffer_view);
  DCHECK(array_buffer_view.View()->buffer());
  if (state_ == kConnecting) {
    SetInvalidStateErrorForSendMethod(exception_state);
    return;
  }
  if (state_ == kClosed) {
    return;
  }
  DOMArrayBuffer *array_buff = array_buffer_view.View()->buffer()->Slice(array_buffer_view.View()->byteOffset(), array_buffer_view.View()->byteOffset() + array_buffer_view.View()->byteLength());
  handle_->Send(
      static_cast<const char*>(array_buff->Data()),
      array_buff->ByteLength());
}

void DOMUDPSocket::close(ExceptionState& exception_state) {
  if (state_ == kClosed)
    return;
  DCHECK(handle_);
  handle_->Close();
}

bool DOMUDPSocket::certIsValid(const String& cert_chain, ExceptionState& exception_state) {
  DCHECK(handle_);
  return handle_->CertificateIsValid(cert_chain);
}

DOMUDPSocket::State DOMUDPSocket::readyState() const {
  return state_;
}

const AtomicString& DOMUDPSocket::InterfaceName() const {
  return event_target_names::kUDPSocket;
}

ExecutionContext* DOMUDPSocket::GetExecutionContext() const {
  return ContextLifecycleStateObserver::GetExecutionContext();
}

void DOMUDPSocket::ContextLifecycleStateChanged(
    mojom::FrameLifecycleState state) {
  if (state == mojom::FrameLifecycleState::kRunning) {
    event_queue_->Unpause();
  } else {
    event_queue_->Pause();
  }
}

void DOMUDPSocket::ContextDestroyed(ExecutionContext*) {
  NETWORK_DVLOG(1) << "UDPSocket " << this << " contextDestroyed()";
  event_queue_->ContextDestroyed();
  if (handle_) {
    handle_->Close();
    ReleaseHandle();
  }
  if (state_ != kClosed) {
    state_ = kClosed;
  }
}

void DOMUDPSocket::DidConnect() {
  NETWORK_DVLOG(1) << "UDPSocket " << this << " DidConnect()";
  if (state_ != kConnecting) {
    return;
  }
  state_ = kOpen;
  event_queue_->Dispatch(Event::Create(event_type_names::kOpen));
}

void DOMUDPSocket::DidReceiveRTTTokens(uint64_t tokens) {
  DCHECK_NE(state_, kConnecting);
  if (state_ != kOpen) {
    LOG(INFO) << "Not open!";
    return;
  }
  event_queue_->Dispatch(RttEvent::Create(tokens));
}

void DOMUDPSocket::DidReceiveMessage(std::unique_ptr<Vector<char>> binary_data) {
  NETWORK_DVLOG(1) << "UDPSocket " << this << " DidReceiveMessage() "
                   << binary_data->size() << " byte binary message";
  LOG(INFO) << "Renderer payload counter " << ++counter_;

  DCHECK_NE(state_, kConnecting);
  if (state_ != kOpen) {
    return;
  }

  LOG(INFO) << "COPY3 START";
  DOMArrayBuffer* array_buffer =
      DOMArrayBuffer::Create(binary_data->data(), binary_data->size());
  LOG(INFO) << "COPY3 STOP";
  event_queue_->Dispatch(MessageEvent::Create(array_buffer));
}

void DOMUDPSocket::DidError() {
  NETWORK_DVLOG(1) << "UDPSocket " << this << " DidError()";
  state_ = kClosed;
  event_queue_->Dispatch(Event::Create(event_type_names::kError));
}

void DOMUDPSocket::DidClose() {
  NETWORK_DVLOG(1) << "UDPSocket " << this << " DidClose()";
  DCHECK(handle_);
  state_ = kClosed;
  ReleaseHandle();
  event_queue_->Dispatch(Event::Create(event_type_names::kClose));
}

bool DOMUDPSocket::HasPendingActivity() const {
  return handle_ || !event_queue_->IsEmpty();
}

void DOMUDPSocket::ReleaseHandle() {
  //DCHECK(handle_);
  handle_ = nullptr;
}

void DOMUDPSocket::Trace(blink::Visitor* visitor) {
  visitor->Trace(handle_);
  visitor->Trace(event_queue_);
  UDPSocketHandleClient::Trace(visitor);
  EventTargetWithInlineData::Trace(visitor);
  ContextLifecycleStateObserver::Trace(visitor);
}


}  // namespace blink
