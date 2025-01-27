// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/web_applications/extensions/pending_bookmark_app_manager.h"

#include <map>
#include <memory>
#include <string>
#include <utility>

#include "base/bind.h"
#include "base/callback.h"
#include "base/macros.h"
#include "base/optional.h"
#include "base/scoped_observer.h"
#include "base/test/bind_test_util.h"
#include "base/timer/mock_timer.h"
#include "chrome/browser/web_applications/components/app_registrar.h"
#include "chrome/browser/web_applications/components/pending_app_manager.h"
#include "chrome/browser/web_applications/components/web_app_constants.h"
#include "chrome/browser/web_applications/extensions/bookmark_app_installation_task.h"
#include "chrome/browser/web_applications/extensions/bookmark_app_registrar.h"
#include "chrome/browser/web_applications/test/test_app_registrar.h"
#include "chrome/test/base/chrome_render_view_host_test_harness.h"
#include "chrome/test/base/testing_profile.h"
#include "content/public/test/web_contents_tester.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace extensions {

namespace {

const char kFooWebAppUrl[] = "https://foo.example";
const char kBarWebAppUrl[] = "https://bar.example";
const char kQuxWebAppUrl[] = "https://qux.example";

const char kWrongUrl[] = "https://foobar.example";

web_app::PendingAppManager::AppInfo GetFooAppInfo(
    base::Optional<bool> override_previous_user_uninstall =
        base::Optional<bool>()) {
  web_app::PendingAppManager::AppInfo info(
      GURL(kFooWebAppUrl), web_app::LaunchContainer::kTab,
      web_app::InstallSource::kExternalPolicy);

  if (override_previous_user_uninstall.has_value())
    info.override_previous_user_uninstall = *override_previous_user_uninstall;

  return info;
}

web_app::PendingAppManager::AppInfo GetBarAppInfo() {
  web_app::PendingAppManager::AppInfo info(
      GURL(kBarWebAppUrl), web_app::LaunchContainer::kWindow,
      web_app::InstallSource::kExternalPolicy);
  return info;
}

web_app::PendingAppManager::AppInfo GetQuxAppInfo() {
  web_app::PendingAppManager::AppInfo info(
      GURL(kQuxWebAppUrl), web_app::LaunchContainer::kWindow,
      web_app::InstallSource::kExternalPolicy);
  return info;
}

std::string GenerateFakeAppId(const GURL& url) {
  return std::string("fake_app_id_for:") + url.spec();
}

class TestBookmarkAppInstallationTask : public BookmarkAppInstallationTask {
 public:
  TestBookmarkAppInstallationTask(Profile* profile,
                                  web_app::TestAppRegistrar* registrar,
                                  web_app::PendingAppManager::AppInfo app_info,
                                  bool succeeds)
      : BookmarkAppInstallationTask(profile, std::move(app_info)),
        profile_(profile),
        registrar_(registrar),
        succeeds_(succeeds),
        extension_ids_map_(profile_->GetPrefs()) {}
  ~TestBookmarkAppInstallationTask() override = default;

  void Install(content::WebContents* web_contents,
               BookmarkAppInstallationTask::ResultCallback callback) override {
    auto result_code = web_app::InstallResultCode::kFailedUnknownReason;
    std::string app_id;
    if (succeeds_) {
      result_code = web_app::InstallResultCode::kSuccess;
      app_id = GenerateFakeAppId(app_info().url);
      extension_ids_map_.Insert(app_info().url, app_id,
                                app_info().install_source);
      registrar_->AddAsInstalled(app_id);
    }

    std::move(on_install_called_).Run();
    std::move(callback).Run(
        BookmarkAppInstallationTask::Result(result_code, app_id));
  }

  void SetOnInstallCalled(base::OnceClosure on_install_called) {
    on_install_called_ = std::move(on_install_called);
  }

 private:
  Profile* profile_;
  web_app::TestAppRegistrar* registrar_;
  bool succeeds_;
  web_app::ExtensionIdsMap extension_ids_map_;

  base::OnceClosure on_install_called_;

  DISALLOW_COPY_AND_ASSIGN(TestBookmarkAppInstallationTask);
};

class TestBookmarkAppUninstaller : public BookmarkAppUninstaller {
 public:
  TestBookmarkAppUninstaller(Profile* profile, web_app::AppRegistrar* registrar)
      : BookmarkAppUninstaller(profile, registrar) {}

  ~TestBookmarkAppUninstaller() override = default;

  size_t uninstall_call_count() { return uninstall_call_count_; }

  void ResetResults() {
    uninstall_call_count_ = 0;
    uninstalled_app_urls_.clear();
  }

  const std::vector<GURL>& uninstalled_app_urls() {
    return uninstalled_app_urls_;
  }

  const GURL& last_uninstalled_app_url() { return uninstalled_app_urls_[0]; }

  void SetNextResultForTesting(const GURL& app_url, bool result) {
    DCHECK(!base::ContainsKey(next_result_map_, app_url));
    next_result_map_[app_url] = result;
  }

  // BookmarkAppUninstaller
  bool UninstallApp(const GURL& app_url) override {
    DCHECK(base::ContainsKey(next_result_map_, app_url));

    ++uninstall_call_count_;
    uninstalled_app_urls_.push_back(app_url);

    bool result = next_result_map_[app_url];
    next_result_map_.erase(app_url);
    return result;
  }

 private:
  std::map<GURL, bool> next_result_map_;

  size_t uninstall_call_count_ = 0;
  std::vector<GURL> uninstalled_app_urls_;

  DISALLOW_COPY_AND_ASSIGN(TestBookmarkAppUninstaller);
};

}  // namespace

class PendingBookmarkAppManagerTest : public ChromeRenderViewHostTestHarness {
 public:
  PendingBookmarkAppManagerTest()
      : test_web_contents_creator_(base::BindRepeating(
            &PendingBookmarkAppManagerTest::CreateTestWebContents,
            base::Unretained(this))),
        successful_installation_task_creator_(base::BindRepeating(
            &PendingBookmarkAppManagerTest::CreateSuccessfulInstallationTask,
            base::Unretained(this))),
        failing_installation_task_creator_(base::BindRepeating(
            &PendingBookmarkAppManagerTest::CreateFailingInstallationTask,
            base::Unretained(this))) {}

  ~PendingBookmarkAppManagerTest() override = default;

  void SetUp() override {
    ChromeRenderViewHostTestHarness::SetUp();
    registrar_ = std::make_unique<web_app::TestAppRegistrar>();
  }

  void TearDown() override {
    uninstaller_ = nullptr;
    ChromeRenderViewHostTestHarness::TearDown();
  }

  std::unique_ptr<content::WebContents> CreateTestWebContents(
      Profile* profile) {
    auto web_contents =
        content::WebContentsTester::CreateTestWebContents(profile, nullptr);
    web_contents_tester_ = content::WebContentsTester::For(web_contents.get());
    return web_contents;
  }

  std::unique_ptr<BookmarkAppInstallationTask> CreateInstallationTask(
      Profile* profile,
      web_app::PendingAppManager::AppInfo app_info,
      bool succeeds) {
    auto task = std::make_unique<TestBookmarkAppInstallationTask>(
        profile, registrar_.get(), std::move(app_info), succeeds);
    auto* task_ptr = task.get();
    task->SetOnInstallCalled(base::BindLambdaForTesting([task_ptr, this]() {
      ++installation_task_run_count_;
      last_app_info_ = task_ptr->app_info();
    }));
    return task;
  }

  std::unique_ptr<BookmarkAppInstallationTask> CreateSuccessfulInstallationTask(
      Profile* profile,
      web_app::PendingAppManager::AppInfo app_info) {
    return CreateInstallationTask(profile, std::move(app_info),
                                  true /* succeeds */);
  }

  std::unique_ptr<BookmarkAppInstallationTask> CreateFailingInstallationTask(
      Profile* profile,
      web_app::PendingAppManager::AppInfo app_info) {
    return CreateInstallationTask(profile, std::move(app_info),
                                  false /* succeeds */);
  }

  void InstallCallback(const GURL& url, web_app::InstallResultCode code) {
    install_callback_url_ = url;
    install_callback_code_ = code;
  }

  void UninstallCallback(const GURL& url, bool successfully_uninstalled) {
    uninstall_callback_url_ = url;
    last_uninstall_successful_ = successfully_uninstalled;
  }

 protected:
  void ResetResults() {
    install_callback_url_.reset();
    install_callback_code_.reset();
    installation_task_run_count_ = 0;
    uninstall_callback_url_.reset();
    last_uninstall_successful_.reset();
    uninstaller_->ResetResults();
  }

  const PendingBookmarkAppManager::WebContentsFactory&
  test_web_contents_creator() {
    return test_web_contents_creator_;
  }

  const PendingBookmarkAppManager::TaskFactory&
  successful_installation_task_creator() {
    return successful_installation_task_creator_;
  }

  const PendingBookmarkAppManager::TaskFactory&
  failing_installation_task_creator() {
    return failing_installation_task_creator_;
  }

  std::unique_ptr<PendingBookmarkAppManager>
  GetPendingBookmarkAppManagerWithTestFactories() {
    auto manager = std::make_unique<PendingBookmarkAppManager>(
        profile(), registrar_.get());
    manager->SetFactoriesForTesting(test_web_contents_creator(),
                                    successful_installation_task_creator());

    // The test suite doesn't support multiple uninstallers.
    DCHECK_EQ(nullptr, uninstaller_);

    auto uninstaller = std::make_unique<TestBookmarkAppUninstaller>(
        profile(), registrar_.get());
    uninstaller_ = uninstaller.get();
    manager->SetUninstallerForTesting(std::move(uninstaller));

    return manager;
  }

  void SuccessfullyLoad(const GURL& url) {
    web_contents_tester_->NavigateAndCommit(url);
    web_contents_tester_->TestDidFinishLoad(url);
    base::RunLoop().RunUntilIdle();
  }

  content::WebContentsTester* web_contents_tester() {
    return web_contents_tester_;
  }

  bool app_installed() {
    switch (install_callback_code_.value()) {
      case web_app::InstallResultCode::kSuccess:
      case web_app::InstallResultCode::kAlreadyInstalled:
        return true;
      default:
        break;
    }
    return false;
  }

  const GURL& install_callback_url() { return install_callback_url_.value(); }

  const web_app::PendingAppManager::AppInfo& last_app_info() {
    CHECK(last_app_info_.has_value());
    return *last_app_info_;
  }

  // Number of times BookmarkAppInstallationTask::InstallWebAppOrShorcut was
  // called. Reflects how many times we've tried to create an Extension.
  size_t installation_task_run_count() { return installation_task_run_count_; }

  const GURL& uninstall_callback_url() {
    return uninstall_callback_url_.value();
  }

  bool last_uninstall_successful() {
    return last_uninstall_successful_.value();
  }

  size_t uninstall_call_count() { return uninstaller_->uninstall_call_count(); }

  const std::vector<GURL>& uninstalled_app_urls() {
    return uninstaller_->uninstalled_app_urls();
  }

  const GURL& last_uninstalled_app_url() {
    return uninstaller_->last_uninstalled_app_url();
  }

  web_app::TestAppRegistrar* registrar() { return registrar_.get(); }

  TestBookmarkAppUninstaller* uninstaller() { return uninstaller_; }

 private:
  content::WebContentsTester* web_contents_tester_ = nullptr;
  base::Optional<GURL> install_callback_url_;
  base::Optional<web_app::InstallResultCode> install_callback_code_;
  base::Optional<web_app::PendingAppManager::AppInfo> last_app_info_;
  size_t installation_task_run_count_ = 0;

  base::Optional<GURL> uninstall_callback_url_;
  base::Optional<bool> last_uninstall_successful_;

  PendingBookmarkAppManager::WebContentsFactory test_web_contents_creator_;
  PendingBookmarkAppManager::TaskFactory successful_installation_task_creator_;
  PendingBookmarkAppManager::TaskFactory failing_installation_task_creator_;

  std::unique_ptr<web_app::TestAppRegistrar> registrar_;
  TestBookmarkAppUninstaller* uninstaller_ = nullptr;

  DISALLOW_COPY_AND_ASSIGN(PendingBookmarkAppManagerTest);
};

TEST_F(PendingBookmarkAppManagerTest, Install_Succeeds) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();
  pending_app_manager->Install(
      GetFooAppInfo(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));

  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kFooWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetFooAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kFooWebAppUrl), install_callback_url());
}

TEST_F(PendingBookmarkAppManagerTest, Install_SerialCallsDifferentApps) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();
  pending_app_manager->Install(
      GetFooAppInfo(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));

  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kFooWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetFooAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kFooWebAppUrl), install_callback_url());
  ResetResults();

  pending_app_manager->Install(
      GetBarAppInfo(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));

  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kBarWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetBarAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kBarWebAppUrl), install_callback_url());
}

TEST_F(PendingBookmarkAppManagerTest, Install_ConcurrentCallsDifferentApps) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();
  pending_app_manager->Install(
      GetFooAppInfo(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));
  pending_app_manager->Install(
      GetBarAppInfo(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));

  // The last call to Install gets higher priority.
  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kBarWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetBarAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kBarWebAppUrl), install_callback_url());
  ResetResults();

  // Then the first call to Install gets processed.
  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kFooWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetFooAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kFooWebAppUrl), install_callback_url());
}

TEST_F(PendingBookmarkAppManagerTest, Install_PendingSuccessfulTask) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();
  pending_app_manager->Install(
      GetFooAppInfo(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));
  // Make sure the installation has started.
  base::RunLoop().RunUntilIdle();

  pending_app_manager->Install(
      GetBarAppInfo(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));

  // Finish the first install.
  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kFooWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetFooAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kFooWebAppUrl), install_callback_url());
  ResetResults();

  // Finish the second install.
  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kBarWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetBarAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kBarWebAppUrl), install_callback_url());
}

TEST_F(PendingBookmarkAppManagerTest, Install_PendingFailingTask) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();
  pending_app_manager->Install(
      GetFooAppInfo(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));
  // Make sure the installation has started.
  base::RunLoop().RunUntilIdle();

  pending_app_manager->Install(
      GetBarAppInfo(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));

  // Fail the first install.
  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kWrongUrl));

  // The installation didn't run because we loaded the wrong url.
  EXPECT_EQ(0u, installation_task_run_count());
  EXPECT_FALSE(app_installed());
  EXPECT_EQ(GURL(kFooWebAppUrl), install_callback_url());
  ResetResults();

  // Finish the second install.
  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kBarWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetBarAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kBarWebAppUrl), install_callback_url());
}

TEST_F(PendingBookmarkAppManagerTest, Install_ReentrantCallback) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();
  // Call install with a callback that tries to install another app.
  pending_app_manager->Install(
      GetFooAppInfo(),
      base::BindLambdaForTesting(
          [&](const GURL& provided_url,
              web_app::InstallResultCode install_result_code) {
            InstallCallback(provided_url, install_result_code);
            pending_app_manager->Install(
                GetBarAppInfo(),
                base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                               base::Unretained(this)));
          }));

  // Finish the first install.
  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kFooWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetFooAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kFooWebAppUrl), install_callback_url());
  ResetResults();

  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kBarWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetBarAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kBarWebAppUrl), install_callback_url());
}

TEST_F(PendingBookmarkAppManagerTest, Install_SerialCallsSameApp) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();
  pending_app_manager->Install(
      GetFooAppInfo(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));

  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kFooWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GURL(kFooWebAppUrl), install_callback_url());
  ResetResults();

  pending_app_manager->Install(
      GetFooAppInfo(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));

  base::RunLoop().RunUntilIdle();

  // The app is already installed so we shouldn't try to install it again.
  EXPECT_EQ(0u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GURL(kFooWebAppUrl), install_callback_url());
}

TEST_F(PendingBookmarkAppManagerTest, Install_ConcurrentCallsSameApp) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();
  pending_app_manager->Install(
      GetFooAppInfo(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));
  pending_app_manager->Install(
      GetFooAppInfo(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));

  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kFooWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetFooAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kFooWebAppUrl), install_callback_url());
}

TEST_F(PendingBookmarkAppManagerTest, Install_AlwaysUpdate) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();

  auto get_always_update_info = []() {
    web_app::PendingAppManager::AppInfo info(
        GURL(kFooWebAppUrl), web_app::LaunchContainer::kWindow,
        web_app::InstallSource::kExternalPolicy);
    info.always_update = true;
    return info;
  };
  pending_app_manager->Install(
      get_always_update_info(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));

  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kFooWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GURL(kFooWebAppUrl), install_callback_url());
  ResetResults();

  pending_app_manager->Install(
      get_always_update_info(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));

  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kFooWebAppUrl));

  // The app is reinstalled even though it is already installed.
  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GURL(kFooWebAppUrl), install_callback_url());
}

TEST_F(PendingBookmarkAppManagerTest, Install_FailsLoadIncorrectURL) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();
  pending_app_manager->Install(
      GetFooAppInfo(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));

  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kWrongUrl));

  EXPECT_EQ(0u, installation_task_run_count());
  EXPECT_FALSE(app_installed());
  EXPECT_EQ(GURL(kFooWebAppUrl), install_callback_url());
}

TEST_F(PendingBookmarkAppManagerTest, InstallApps_Succeeds) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();
  std::vector<web_app::PendingAppManager::AppInfo> apps_to_install;
  apps_to_install.push_back(GetFooAppInfo());

  pending_app_manager->InstallApps(
      std::move(apps_to_install),
      base::BindRepeating(&PendingBookmarkAppManagerTest::InstallCallback,
                          base::Unretained(this)));

  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kFooWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetFooAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kFooWebAppUrl), install_callback_url());
}

TEST_F(PendingBookmarkAppManagerTest, InstallApps_Fails) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();
  std::vector<web_app::PendingAppManager::AppInfo> apps_to_install;
  apps_to_install.push_back(GetFooAppInfo());

  pending_app_manager->InstallApps(
      std::move(apps_to_install),
      base::BindRepeating(&PendingBookmarkAppManagerTest::InstallCallback,
                          base::Unretained(this)));

  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kWrongUrl));

  EXPECT_EQ(0u, installation_task_run_count());
  EXPECT_FALSE(app_installed());
  EXPECT_EQ(GURL(kFooWebAppUrl), install_callback_url());
}

TEST_F(PendingBookmarkAppManagerTest, InstallApps_Multiple) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();

  std::vector<web_app::PendingAppManager::AppInfo> apps_to_install;
  apps_to_install.push_back(GetFooAppInfo());
  apps_to_install.push_back(GetBarAppInfo());

  pending_app_manager->InstallApps(
      std::move(apps_to_install),
      base::BindRepeating(&PendingBookmarkAppManagerTest::InstallCallback,
                          base::Unretained(this)));

  // Finish the first install.
  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kFooWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetFooAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kFooWebAppUrl), install_callback_url());
  ResetResults();

  // Finish the second install.
  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kBarWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetBarAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kBarWebAppUrl), install_callback_url());
}

TEST_F(PendingBookmarkAppManagerTest, InstallApps_PendingInstallApps) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();

  {
    std::vector<web_app::PendingAppManager::AppInfo> apps_to_install;
    apps_to_install.push_back(GetFooAppInfo());

    pending_app_manager->InstallApps(
        std::move(apps_to_install),
        base::BindRepeating(&PendingBookmarkAppManagerTest::InstallCallback,
                            base::Unretained(this)));
  }

  {
    std::vector<web_app::PendingAppManager::AppInfo> apps_to_install;
    apps_to_install.push_back(GetBarAppInfo());

    pending_app_manager->InstallApps(
        std::move(apps_to_install),
        base::BindRepeating(&PendingBookmarkAppManagerTest::InstallCallback,
                            base::Unretained(this)));
  }

  // Finish the first install.
  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kFooWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetFooAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kFooWebAppUrl), install_callback_url());
  ResetResults();

  // Finish the second install.
  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kBarWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetBarAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kBarWebAppUrl), install_callback_url());
}

TEST_F(PendingBookmarkAppManagerTest, Install_PendingMulitpleInstallApps) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();

  std::vector<web_app::PendingAppManager::AppInfo> apps_to_install;
  apps_to_install.push_back(GetFooAppInfo());
  apps_to_install.push_back(GetBarAppInfo());

  // Queue through InstallApps.
  pending_app_manager->InstallApps(
      std::move(apps_to_install),
      base::BindRepeating(&PendingBookmarkAppManagerTest::InstallCallback,
                          base::Unretained(this)));

  // Queue through Install.
  pending_app_manager->Install(
      GetQuxAppInfo(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));

  // The install request from Install should be processed first.
  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kQuxWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetQuxAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kQuxWebAppUrl), install_callback_url());
  ResetResults();

  // The install requests from InstallApps should be processed next.
  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kFooWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetFooAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kFooWebAppUrl), install_callback_url());
  ResetResults();

  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kBarWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetBarAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kBarWebAppUrl), install_callback_url());
}

TEST_F(PendingBookmarkAppManagerTest, InstallApps_PendingInstall) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();
  // Queue through Install.
  pending_app_manager->Install(
      GetQuxAppInfo(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));

  // Queue through InstallApps.
  std::vector<web_app::PendingAppManager::AppInfo> apps_to_install;
  apps_to_install.push_back(GetFooAppInfo());
  apps_to_install.push_back(GetBarAppInfo());

  pending_app_manager->InstallApps(
      std::move(apps_to_install),
      base::BindRepeating(&PendingBookmarkAppManagerTest::InstallCallback,
                          base::Unretained(this)));

  // The install request from Install should be processed first.
  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kQuxWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetQuxAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kQuxWebAppUrl), install_callback_url());
  ResetResults();

  // The install requests from InstallApps should be processed next.
  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kFooWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GURL(kFooWebAppUrl), install_callback_url());
  EXPECT_EQ(GetFooAppInfo(), last_app_info());
  ResetResults();

  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kBarWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  EXPECT_EQ(GetBarAppInfo(), last_app_info());
  EXPECT_EQ(GURL(kBarWebAppUrl), install_callback_url());
}

TEST_F(PendingBookmarkAppManagerTest, ExtensionUninstalled) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();
  pending_app_manager->Install(
      GetFooAppInfo(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));

  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kFooWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  ResetResults();

  // Simulate the extension for the app getting uninstalled.
  const std::string app_id = GenerateFakeAppId(GURL(kFooWebAppUrl));
  registrar()->RemoveAsInstalled(app_id);

  // Try to install the app again.
  pending_app_manager->Install(
      GetFooAppInfo(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));

  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kFooWebAppUrl));

  // The extension was uninstalled so a new installation task should run.
  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
}

TEST_F(PendingBookmarkAppManagerTest, ExternalExtensionUninstalled) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();
  pending_app_manager->Install(
      GetFooAppInfo(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));

  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kFooWebAppUrl));

  EXPECT_EQ(1u, installation_task_run_count());
  EXPECT_TRUE(app_installed());
  ResetResults();

  // Simulate external extension for the app getting uninstalled by the user.
  const std::string app_id = GenerateFakeAppId(GURL(kFooWebAppUrl));
  registrar()->AddAsExternalAppUninstalledByUser(app_id);
  registrar()->RemoveAsInstalled(app_id);

  // The extension was uninstalled by the user. Installing again should succeed
  // or fail depending on whether we set override_previous_user_uninstall. We
  // try with override_previous_user_uninstall false first, true second.
  for (unsigned int i = 0; i < 2; i++) {
    bool override_previous_user_uninstall = i > 0;

    pending_app_manager->Install(
        GetFooAppInfo(override_previous_user_uninstall),
        base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                       base::Unretained(this)));
    base::RunLoop().RunUntilIdle();
    if (override_previous_user_uninstall) {
      SuccessfullyLoad(GURL(kFooWebAppUrl));
    }

    EXPECT_EQ(i, installation_task_run_count());
    EXPECT_EQ(override_previous_user_uninstall, app_installed());
    ResetResults();
  }
}

TEST_F(PendingBookmarkAppManagerTest, UninstallApps_Succeeds) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();

  uninstaller()->SetNextResultForTesting(GURL(kFooWebAppUrl), true);
  pending_app_manager->UninstallApps(
      std::vector<GURL>{GURL(kFooWebAppUrl)},
      base::BindRepeating(&PendingBookmarkAppManagerTest::UninstallCallback,
                          base::Unretained(this)));

  EXPECT_EQ(GURL(kFooWebAppUrl), uninstall_callback_url());
  EXPECT_TRUE(last_uninstall_successful());
  EXPECT_EQ(1u, uninstall_call_count());
  EXPECT_EQ(GURL(kFooWebAppUrl), last_uninstalled_app_url());
}

TEST_F(PendingBookmarkAppManagerTest, UninstallApps_Fails) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();

  uninstaller()->SetNextResultForTesting(GURL(kFooWebAppUrl), false);
  pending_app_manager->UninstallApps(
      std::vector<GURL>{GURL(kFooWebAppUrl)},
      base::BindRepeating(&PendingBookmarkAppManagerTest::UninstallCallback,
                          base::Unretained(this)));

  EXPECT_EQ(GURL(kFooWebAppUrl), uninstall_callback_url());
  EXPECT_FALSE(last_uninstall_successful());
  EXPECT_EQ(1u, uninstall_call_count());
  EXPECT_EQ(GURL(kFooWebAppUrl), last_uninstalled_app_url());
}

TEST_F(PendingBookmarkAppManagerTest, UninstallApps_Multiple) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();

  uninstaller()->SetNextResultForTesting(GURL(kFooWebAppUrl), true);
  uninstaller()->SetNextResultForTesting(GURL(kBarWebAppUrl), true);
  pending_app_manager->UninstallApps(
      std::vector<GURL>{GURL(kFooWebAppUrl), GURL(kBarWebAppUrl)},
      base::BindRepeating(&PendingBookmarkAppManagerTest::UninstallCallback,
                          base::Unretained(this)));

  EXPECT_TRUE(last_uninstall_successful());
  EXPECT_EQ(2u, uninstall_call_count());
  EXPECT_EQ(std::vector<GURL>({GURL(kFooWebAppUrl), GURL(kBarWebAppUrl)}),
            uninstalled_app_urls());
}

TEST_F(PendingBookmarkAppManagerTest, UninstallApps_PendingInstall) {
  auto pending_app_manager = GetPendingBookmarkAppManagerWithTestFactories();
  pending_app_manager->Install(
      GetFooAppInfo(),
      base::BindOnce(&PendingBookmarkAppManagerTest::InstallCallback,
                     base::Unretained(this)));

  uninstaller()->SetNextResultForTesting(GURL(kFooWebAppUrl), false);
  pending_app_manager->UninstallApps(
      std::vector<GURL>{GURL(kFooWebAppUrl)},
      base::BindRepeating(&PendingBookmarkAppManagerTest::UninstallCallback,
                          base::Unretained(this)));

  EXPECT_EQ(GURL(kFooWebAppUrl), uninstall_callback_url());
  EXPECT_FALSE(last_uninstall_successful());
  EXPECT_EQ(1u, uninstall_call_count());

  base::RunLoop().RunUntilIdle();
  SuccessfullyLoad(GURL(kFooWebAppUrl));

  EXPECT_TRUE(app_installed());
}

}  // namespace extensions
