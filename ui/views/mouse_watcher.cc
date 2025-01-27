// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ui/views/mouse_watcher.h"

#include "base/bind.h"
#include "base/compiler_specific.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/memory/weak_ptr.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "ui/events/event.h"
#include "ui/events/event_constants.h"
#include "ui/events/event_observer.h"
#include "ui/events/event_utils.h"
#include "ui/events/platform_event.h"
#include "ui/views/event_monitor.h"

namespace views {

// Amount of time between when the mouse moves outside the Host's zone and when
// the listener is notified.
constexpr int kNotifyListenerTimeMs = 300;

class MouseWatcher::Observer : public ui::EventObserver {
 public:
  Observer(MouseWatcher* mouse_watcher, gfx::NativeWindow window)
      : mouse_watcher_(mouse_watcher), notify_listener_factory_(this) {
    event_monitor_ = EventMonitor::CreateApplicationMonitor(
        this, window,
        {ui::ET_MOUSE_PRESSED, ui::ET_MOUSE_MOVED, ui::ET_MOUSE_EXITED,
         ui::ET_MOUSE_DRAGGED});
  }

  // ui::EventObserver:
  void OnEvent(const ui::Event& event) override {
    switch (event.type()) {
      case ui::ET_MOUSE_MOVED:
      case ui::ET_MOUSE_DRAGGED:
        HandleMouseEvent(MouseWatcherHost::MOUSE_MOVE);
        break;
      case ui::ET_MOUSE_EXITED:
        HandleMouseEvent(MouseWatcherHost::MOUSE_EXIT);
        break;
      case ui::ET_MOUSE_PRESSED:
        HandleMouseEvent(MouseWatcherHost::MOUSE_PRESS);
        break;
      default:
        NOTREACHED();
        break;
    }
  }

 private:
  MouseWatcherHost* host() const { return mouse_watcher_->host_.get(); }

  // Called when a mouse event we're interested is seen.
  void HandleMouseEvent(MouseWatcherHost::MouseEventType event_type) {
    // It's safe to use last_mouse_location() here as this function is invoked
    // during event dispatching.
    if (!host()->Contains(event_monitor_->GetLastMouseLocation(), event_type)) {
      if (event_type == MouseWatcherHost::MOUSE_PRESS) {
        NotifyListener();
      } else if (!notify_listener_factory_.HasWeakPtrs()) {
        // Mouse moved outside the host's zone, start a timer to notify the
        // listener.
        base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
            FROM_HERE,
            base::BindOnce(&Observer::NotifyListener,
                           notify_listener_factory_.GetWeakPtr()),
            event_type == MouseWatcherHost::MOUSE_MOVE
                ? base::TimeDelta::FromMilliseconds(kNotifyListenerTimeMs)
                : mouse_watcher_->notify_on_exit_time_);
      }
    } else {
      // Mouse moved quickly out of the host and then into it again, so cancel
      // the timer.
      notify_listener_factory_.InvalidateWeakPtrs();
    }
  }

  void NotifyListener() {
    mouse_watcher_->NotifyListener();
    // WARNING: we've been deleted.
  }

 private:
  MouseWatcher* mouse_watcher_;
  std::unique_ptr<views::EventMonitor> event_monitor_;

  // A factory that is used to construct a delayed callback to the listener.
  base::WeakPtrFactory<Observer> notify_listener_factory_;

  DISALLOW_COPY_AND_ASSIGN(Observer);
};

MouseWatcherListener::~MouseWatcherListener() = default;

MouseWatcherHost::~MouseWatcherHost() = default;

MouseWatcher::MouseWatcher(std::unique_ptr<MouseWatcherHost> host,
                           MouseWatcherListener* listener)
    : host_(std::move(host)),
      listener_(listener),
      notify_on_exit_time_(
          base::TimeDelta::FromMilliseconds(kNotifyListenerTimeMs)) {}

MouseWatcher::~MouseWatcher() = default;

void MouseWatcher::Start(gfx::NativeWindow window) {
  if (!is_observing())
    observer_ = std::make_unique<Observer>(this, window);
}

void MouseWatcher::Stop() {
  observer_.reset();
}

void MouseWatcher::NotifyListener() {
  observer_.reset();
  listener_->MouseMovedOutOfHost();
}

}  // namespace views
