// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/installable/fake_installable_manager.h"

#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/callback.h"
#include "base/threading/thread_task_runner_handle.h"
#include "chrome/browser/installable/installable_data.h"

FakeInstallableManager::FakeInstallableManager(
    content::WebContents* web_contents)
    : InstallableManager(web_contents) {}

FakeInstallableManager::~FakeInstallableManager() {}

void FakeInstallableManager::GetData(const InstallableParams& params,
                                     InstallableCallback callback) {
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::BindOnce(&FakeInstallableManager::RunCallback,
                                base::Unretained(this), std::move(callback)));
}

void FakeInstallableManager::RunCallback(InstallableCallback callback) {
  std::move(callback).Run(*data_);
}

// static
FakeInstallableManager* FakeInstallableManager::CreateForWebContents(
    content::WebContents* web_contents) {
  auto manager = std::make_unique<FakeInstallableManager>(web_contents);
  FakeInstallableManager* result = manager.get();
  web_contents->SetUserData(UserDataKey(), std::move(manager));
  return result;
}

// static
FakeInstallableManager*
FakeInstallableManager::CreateForWebContentsWithManifest(
    content::WebContents* web_contents,
    InstallableStatusCode installable_code,
    const GURL& manifest_url,
    std::unique_ptr<blink::Manifest> manifest) {
  FakeInstallableManager* installable_manager =
      FakeInstallableManager::CreateForWebContents(web_contents);

  installable_manager->manifest_ = std::move(manifest);

  const bool valid_manifest = true;
  const bool has_worker = true;
  std::vector<InstallableStatusCode> errors;

  // Not used:
  const GURL icon_url;
  const std::unique_ptr<SkBitmap> icon;

  if (installable_code != NO_ERROR_DETECTED)
    errors.push_back(installable_code);

  auto installable_data = std::make_unique<InstallableData>(
      std::move(errors), manifest_url, installable_manager->manifest_.get(),
      icon_url, icon.get(), false, icon_url, icon.get(), valid_manifest,
      has_worker);

  installable_manager->data_ = std::move(installable_data);

  return installable_manager;
}
