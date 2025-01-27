// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_TRACING_BACKGROUND_TRACING_MANAGER_IMPL_H_
#define CONTENT_BROWSER_TRACING_BACKGROUND_TRACING_MANAGER_IMPL_H_

#include <map>
#include <memory>
#include <set>
#include <string>

#include "base/macros.h"
#include "content/browser/tracing/background_tracing_config_impl.h"
#include "content/public/browser/background_tracing_manager.h"

namespace base {
template <typename T>
class NoDestructor;
}  // namespace base

namespace content {

class BackgroundTracingRule;
class BackgroundTracingActiveScenario;
class TraceMessageFilter;
class TracingDelegate;

class BackgroundTracingManagerImpl : public BackgroundTracingManager {
 public:
  // Enabled state observers get a callback when the state of background tracing
  // changes.
  class CONTENT_EXPORT EnabledStateObserver {
   public:
    // Called when the activation of a background tracing scenario is
    // successful.
    virtual void OnScenarioActivated(
        const BackgroundTracingConfigImpl* config) = 0;

    // In case the scenario was aborted before or after tracing was enabled.
    virtual void OnScenarioAborted() = 0;

    // Called after tracing is enabled on all processes because the rule was
    // triggered.
    virtual void OnTracingEnabled(
        BackgroundTracingConfigImpl::CategoryPreset preset) = 0;

    virtual ~EnabledStateObserver() = default;
  };

  class TraceMessageFilterObserver {
   public:
    virtual void OnTraceMessageFilterAdded(TraceMessageFilter* filter) = 0;
    virtual void OnTraceMessageFilterRemoved(TraceMessageFilter* filter) = 0;
  };

  // These values are used for a histogram. Do not reorder.
  enum class Metrics {
    SCENARIO_ACTIVATION_REQUESTED = 0,
    SCENARIO_ACTIVATED_SUCCESSFULLY = 1,
    RECORDING_ENABLED = 2,
    PREEMPTIVE_TRIGGERED = 3,
    REACTIVE_TRIGGERED = 4,
    FINALIZATION_ALLOWED = 5,
    FINALIZATION_DISALLOWED = 6,
    FINALIZATION_STARTED = 7,
    OBSOLETE_FINALIZATION_COMPLETE = 8,
    SCENARIO_ACTION_FAILED_LOWRES_CLOCK = 9,
    UPLOAD_FAILED = 10,
    UPLOAD_SUCCEEDED = 11,
    STARTUP_SCENARIO_TRIGGERED = 12,
    NUMBER_OF_BACKGROUND_TRACING_METRICS,
  };
  static void RecordMetric(Metrics metric);

  CONTENT_EXPORT static BackgroundTracingManagerImpl* GetInstance();

  bool SetActiveScenario(std::unique_ptr<BackgroundTracingConfig>,
                         ReceiveCallback,
                         DataFiltering data_filtering) override;
  CONTENT_EXPORT void AbortScenario() override;
  bool HasActiveScenario() override;

  // Named triggers
  void TriggerNamedEvent(TriggerHandle, StartedFinalizingCallback) override;
  TriggerHandle RegisterTriggerType(const char* trigger_name) override;
  std::string GetTriggerNameFromHandle(TriggerHandle handle) const;

  void OnHistogramTrigger(const std::string& histogram_name);

  void OnRuleTriggered(const BackgroundTracingRule* triggered_rule,
                       StartedFinalizingCallback callback);

  // Add/remove EnabledStateObserver.
  CONTENT_EXPORT void AddEnabledStateObserver(EnabledStateObserver* observer);
  CONTENT_EXPORT void RemoveEnabledStateObserver(
      EnabledStateObserver* observer);

  // Add/remove TraceMessageFilter{Observer}.
  void AddTraceMessageFilter(TraceMessageFilter* trace_message_filter);
  void RemoveTraceMessageFilter(TraceMessageFilter* trace_message_filter);
  void AddTraceMessageFilterObserver(TraceMessageFilterObserver* observer);
  void RemoveTraceMessageFilterObserver(TraceMessageFilterObserver* observer);

  void AddMetadataGeneratorFunction();

  bool IsAllowedFinalization() const;

  // Called by BackgroundTracingActiveScenario
  void OnStartTracingDone(BackgroundTracingConfigImpl::CategoryPreset preset);

  // For tests
  CONTENT_EXPORT BackgroundTracingActiveScenario* GetActiveScenarioForTesting();
  CONTENT_EXPORT void InvalidateTriggerHandlesForTesting();
  CONTENT_EXPORT bool IsTracingForTesting();
  void WhenIdle(IdleCallback idle_callback) override;

 private:
  friend class base::NoDestructor<BackgroundTracingManagerImpl>;

  BackgroundTracingManagerImpl();
  ~BackgroundTracingManagerImpl() override;

  void ValidateStartupScenario();
  bool IsSupportedConfig(BackgroundTracingConfigImpl* config);
  std::unique_ptr<base::DictionaryValue> GenerateMetadataDict();
  bool IsTriggerHandleValid(TriggerHandle handle) const;
  void OnScenarioAborted();

  std::unique_ptr<BackgroundTracingActiveScenario> active_scenario_;

  std::unique_ptr<TracingDelegate> delegate_;
  std::map<TriggerHandle, std::string> trigger_handles_;
  int trigger_handle_ids_;

  // There is no need to use base::ObserverList to store observers because we
  // only access |background_tracing_observers_| and
  // |trace_message_filter_observers_| from the UI thread.
  std::set<EnabledStateObserver*> background_tracing_observers_;
  std::set<scoped_refptr<TraceMessageFilter>> trace_message_filters_;
  std::set<TraceMessageFilterObserver*> trace_message_filter_observers_;

  IdleCallback idle_callback_;
  base::RepeatingClosure tracing_enabled_callback_for_testing_;

  DISALLOW_COPY_AND_ASSIGN(BackgroundTracingManagerImpl);
};

}  // namespace content

#endif  // CONTENT_BROWSER_TRACING_BACKGROUND_TRACING_MANAGER_IMPL_H_
