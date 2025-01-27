// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "content/browser/background_fetch/background_fetch_registration_notifier.h"

#include "base/bind.h"
#include "base/command_line.h"
#include "base/metrics/histogram_macros.h"
#include "content/common/background_fetch/background_fetch_types.h"
#include "content/public/common/content_switches.h"

namespace content {

BackgroundFetchRegistrationNotifier::BackgroundFetchRegistrationNotifier()
    : weak_factory_(this) {}

BackgroundFetchRegistrationNotifier::~BackgroundFetchRegistrationNotifier() {}

void BackgroundFetchRegistrationNotifier::AddObserver(
    const std::string& unique_id,
    blink::mojom::BackgroundFetchRegistrationObserverPtr observer) {
  // Observe connection errors, which occur when the JavaScript object or the
  // renderer hosting them goes away. (For example through navigation.) The
  // observer gets freed together with |this|, thus the Unretained is safe.
  observer.set_connection_error_handler(
      base::BindOnce(&BackgroundFetchRegistrationNotifier::OnConnectionError,
                     base::Unretained(this), unique_id, observer.get()));

  observers_.emplace(unique_id, std::move(observer));
}

void BackgroundFetchRegistrationNotifier::Notify(
    const blink::mojom::BackgroundFetchRegistration& registration) {
  auto range = observers_.equal_range(registration.unique_id);
  for (auto it = range.first; it != range.second; ++it) {
    it->second->OnProgress(registration.upload_total, registration.uploaded,
                           registration.download_total, registration.downloaded,
                           registration.result, registration.failure_reason);
  }
}

void BackgroundFetchRegistrationNotifier::NotifyRecordsUnavailable(
    const std::string& unique_id) {
  auto iter = num_requests_and_updates_.find(unique_id);
  if (iter == num_requests_and_updates_.end())
    return;

  // Record the percentage of requests we've sent updates for.
  int num_updates_sent = iter->second.first;
  int num_total_requests = iter->second.second;
  UMA_HISTOGRAM_PERCENTAGE(
      "BackgroundFetch.PercentOfRequestsForWhichUpdatesAreSent",
      static_cast<int>(num_updates_sent * 100.0 / num_total_requests));
  num_requests_and_updates_.erase(iter);

  for (auto it = observers_.begin(); it != observers_.end();) {
    if (it->first != unique_id) {
      it++;
      continue;
    }

    it->second->OnRecordsUnavailable();

    // No more notifications will be sent to the observers from this point.
    it = observers_.erase(it);
  }
}

void BackgroundFetchRegistrationNotifier::AddObservedUrl(
    const std::string& unique_id,
    const GURL& url) {
  // Ensure we have an observer for this unique_id.
  if (observers_.find(unique_id) == observers_.end())
    return;

  observed_urls_[unique_id].insert(url);
}

void BackgroundFetchRegistrationNotifier::NotifyRequestCompleted(
    const std::string& unique_id,
    blink::mojom::FetchAPIRequestPtr request,
    blink::mojom::FetchAPIResponsePtr response) {
  // Avoid sending {request, response} over the mojo pipe if no |observers_|
  // care about it.
  auto observed_urls_iter = observed_urls_.find(unique_id);
  if (observed_urls_iter == observed_urls_.end())
    return;
  if (observed_urls_iter->second.find(request->url) ==
      observed_urls_iter->second.end()) {
    return;
  }

  auto range = observers_.equal_range(unique_id);
  for (auto it = range.first; it != range.second; ++it) {
    it->second->OnRequestCompleted(
        BackgroundFetchSettledFetch::CloneRequest(request),
        BackgroundFetchSettledFetch::CloneResponse(response));
  }

  auto iter = num_requests_and_updates_.find(unique_id);
  if (iter == num_requests_and_updates_.end())
    return;
  iter->second.first++;
}

void BackgroundFetchRegistrationNotifier::OnConnectionError(
    const std::string& unique_id,
    blink::mojom::BackgroundFetchRegistrationObserver* observer) {
  DCHECK_GE(observers_.count(unique_id), 1u);
  base::EraseIf(observers_,
                [observer](const auto& unique_id_observer_ptr_pair) {
                  return unique_id_observer_ptr_pair.second.get() == observer;
                });
}

void BackgroundFetchRegistrationNotifier::NoteTotalRequests(
    const std::string& unique_id,
    int num_total_requests) {
  DCHECK(!num_requests_and_updates_.count(unique_id));
  num_requests_and_updates_[unique_id] = {/* total_updates_sent= */ 0,
                                          num_total_requests};
}

}  // namespace content
