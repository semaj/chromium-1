// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Implements the Chrome Extensions Cookies API.

#include "chrome/browser/extensions/api/cookies/cookies_api.h"

#include <memory>
#include <utility>
#include <vector>

#include "base/bind.h"
#include "base/json/json_writer.h"
#include "base/lazy_instance.h"
#include "base/time/time.h"
#include "base/values.h"
#include "chrome/browser/chrome_notification_types.h"
#include "chrome/browser/extensions/api/cookies/cookies_api_constants.h"
#include "chrome/browser/extensions/api/cookies/cookies_helpers.h"
#include "chrome/browser/extensions/chrome_extension_function_details.h"
#include "chrome/browser/profiles/profile.h"
#include "chrome/browser/ui/browser.h"
#include "chrome/browser/ui/browser_list.h"
#include "chrome/common/extensions/api/cookies.h"
#include "content/public/browser/browser_context.h"
#include "content/public/browser/browser_thread.h"
#include "content/public/browser/notification_service.h"
#include "content/public/browser/storage_partition.h"
#include "extensions/browser/event_router.h"
#include "extensions/common/error_utils.h"
#include "extensions/common/extension.h"
#include "extensions/common/permissions/permissions_data.h"
#include "net/cookies/canonical_cookie.h"
#include "net/cookies/cookie_constants.h"
#include "services/network/public/mojom/network_service.mojom.h"

using content::BrowserThread;

namespace extensions {

namespace {

bool ParseUrl(const Extension* extension,
              const std::string& url_string,
              GURL* url,
              bool check_host_permissions,
              std::string* error) {
  *url = GURL(url_string);
  if (!url->is_valid()) {
    *error = ErrorUtils::FormatErrorMessage(
        cookies_api_constants::kInvalidUrlError, url_string);
    return false;
  }
  // Check against host permissions if needed.
  if (check_host_permissions &&
      !extension->permissions_data()->HasHostPermission(*url)) {
    *error = ErrorUtils::FormatErrorMessage(
        cookies_api_constants::kNoHostPermissionsError, url->spec());
    return false;
  }
  return true;
}

network::mojom::CookieManager* ParseStoreCookieManager(
    content::BrowserContext* function_context,
    bool include_incognito,
    std::string* store_id,
    std::string* error) {
  Profile* function_profile = Profile::FromBrowserContext(function_context);
  Profile* store_profile = nullptr;
  if (!store_id->empty()) {
    store_profile = cookies_helpers::ChooseProfileFromStoreId(
        *store_id, function_profile, include_incognito);
    if (!store_profile) {
      *error = ErrorUtils::FormatErrorMessage(
          cookies_api_constants::kInvalidStoreIdError, *store_id);
      return nullptr;
    }
  } else {
    store_profile = function_profile;
    *store_id = cookies_helpers::GetStoreIdFromProfile(store_profile);
  }

  return content::BrowserContext::GetDefaultStoragePartition(store_profile)
      ->GetCookieManagerForBrowserProcess();
}

}  // namespace

CookiesEventRouter::CookiesEventRouter(content::BrowserContext* context)
    : profile_(Profile::FromBrowserContext(context)) {
  CHECK(registrar_.IsEmpty());
  registrar_.Add(this,
                 chrome::NOTIFICATION_COOKIE_CHANGED_FOR_EXTENSIONS,
                 content::NotificationService::AllBrowserContextsAndSources());
}

CookiesEventRouter::~CookiesEventRouter() {
}

void CookiesEventRouter::Observe(
    int type,
    const content::NotificationSource& source,
    const content::NotificationDetails& details) {
  DCHECK_EQ(chrome::NOTIFICATION_COOKIE_CHANGED_FOR_EXTENSIONS, type);

  Profile* profile = content::Source<Profile>(source).ptr();
  if (!profile_->IsSameProfile(profile))
    return;

  CookieChanged(profile, content::Details<ChromeCookieDetails>(details).ptr());
}

void CookiesEventRouter::CookieChanged(
    Profile* profile,
    ChromeCookieDetails* details) {
  std::unique_ptr<base::ListValue> args(new base::ListValue());
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetBoolean(cookies_api_constants::kRemovedKey, details->removed);

  api::cookies::Cookie cookie = cookies_helpers::CreateCookie(
      *details->cookie, cookies_helpers::GetStoreIdFromProfile(profile));
  dict->Set(cookies_api_constants::kCookieKey, cookie.ToValue());

  // Map the internal cause to an external string.
  std::string cause;
  switch (details->cause) {
    // Report an inserted cookie as an "explicit" change cause. All other causes
    // only make sense for deletions.
    case network::mojom::CookieChangeCause::INSERTED:
    case network::mojom::CookieChangeCause::EXPLICIT:
      cause = cookies_api_constants::kExplicitChangeCause;
      break;

    case network::mojom::CookieChangeCause::OVERWRITE:
      cause = cookies_api_constants::kOverwriteChangeCause;
      break;

    case network::mojom::CookieChangeCause::EXPIRED:
      cause = cookies_api_constants::kExpiredChangeCause;
      break;

    case network::mojom::CookieChangeCause::EVICTED:
      cause = cookies_api_constants::kEvictedChangeCause;
      break;

    case network::mojom::CookieChangeCause::EXPIRED_OVERWRITE:
      cause = cookies_api_constants::kExpiredOverwriteChangeCause;
      break;

    case network::mojom::CookieChangeCause::UNKNOWN_DELETION:
      NOTREACHED();
  }
  dict->SetString(cookies_api_constants::kCauseKey, cause);

  args->Append(std::move(dict));

  GURL cookie_domain =
      cookies_helpers::GetURLFromCanonicalCookie(*details->cookie);
  DispatchEvent(profile, events::COOKIES_ON_CHANGED,
                api::cookies::OnChanged::kEventName, std::move(args),
                cookie_domain);
}

void CookiesEventRouter::DispatchEvent(
    content::BrowserContext* context,
    events::HistogramValue histogram_value,
    const std::string& event_name,
    std::unique_ptr<base::ListValue> event_args,
    GURL& cookie_domain) {
  EventRouter* router = context ? EventRouter::Get(context) : NULL;
  if (!router)
    return;
  auto event = std::make_unique<Event>(histogram_value, event_name,
                                       std::move(event_args), context);
  event->event_url = cookie_domain;
  router->BroadcastEvent(std::move(event));
}

CookiesGetFunction::CookiesGetFunction() {
}

CookiesGetFunction::~CookiesGetFunction() {
}

ExtensionFunction::ResponseAction CookiesGetFunction::Run() {
  parsed_args_ = api::cookies::Get::Params::Create(*args_);
  EXTENSION_FUNCTION_VALIDATE(parsed_args_.get());

  // Read/validate input parameters.
  std::string error;
  if (!ParseUrl(extension(), parsed_args_->details.url, &url_, true, &error))
    return RespondNow(Error(error));

  std::string store_id =
      parsed_args_->details.store_id.get() ? *parsed_args_->details.store_id
                                           : std::string();
  network::mojom::CookieManager* cookie_manager = ParseStoreCookieManager(
      browser_context(), include_incognito_information(), &store_id, &error);
  if (!cookie_manager)
    return RespondNow(Error(error));

  if (!parsed_args_->details.store_id.get())
    parsed_args_->details.store_id.reset(new std::string(store_id));

  cookies_helpers::GetCookieListFromManager(
      cookie_manager, url_,
      base::BindOnce(&CookiesGetFunction::GetCookieCallback, this));

  // Will finish asynchronously.
  return RespondLater();
}

void CookiesGetFunction::GetCookieCallback(const net::CookieList& cookie_list) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);
  for (const net::CanonicalCookie& cookie : cookie_list) {
    // Return the first matching cookie. Relies on the fact that the
    // CookieManager interface returns them in canonical order (longest path,
    // then earliest creation time).
    if (cookie.Name() == parsed_args_->details.name) {
      api::cookies::Cookie api_cookie = cookies_helpers::CreateCookie(
          cookie, *parsed_args_->details.store_id);
      Respond(ArgumentList(api::cookies::Get::Results::Create(api_cookie)));
      return;
    }
  }

  // The cookie doesn't exist; return null.
  Respond(OneArgument(std::make_unique<base::Value>()));
}

CookiesGetAllFunction::CookiesGetAllFunction() {
}

CookiesGetAllFunction::~CookiesGetAllFunction() {
}

ExtensionFunction::ResponseAction CookiesGetAllFunction::Run() {
  parsed_args_ = api::cookies::GetAll::Params::Create(*args_);
  EXTENSION_FUNCTION_VALIDATE(parsed_args_.get());

  std::string error;
  if (parsed_args_->details.url.get() &&
      !ParseUrl(extension(), *parsed_args_->details.url, &url_, false,
                &error)) {
    return RespondNow(Error(error));
  }

  std::string store_id =
      parsed_args_->details.store_id.get() ? *parsed_args_->details.store_id
                                           : std::string();
  network::mojom::CookieManager* cookie_manager = ParseStoreCookieManager(
      browser_context(), include_incognito_information(), &store_id, &error);
  if (!cookie_manager)
    return RespondNow(Error(error));

  if (!parsed_args_->details.store_id.get())
    parsed_args_->details.store_id.reset(new std::string(store_id));

  DCHECK(url_.is_empty() || url_.is_valid());
  cookies_helpers::GetCookieListFromManager(
      cookie_manager, url_,
      base::BindOnce(&CookiesGetAllFunction::GetAllCookiesCallback, this));

  return RespondLater();
}

void CookiesGetAllFunction::GetAllCookiesCallback(
    const net::CookieList& cookie_list) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);
  ResponseValue response;
  if (extension()) {
    std::vector<api::cookies::Cookie> match_vector;
    cookies_helpers::AppendMatchingCookiesToVector(
        cookie_list, url_, &parsed_args_->details, extension(), &match_vector);

    response =
        ArgumentList(api::cookies::GetAll::Results::Create(match_vector));
  } else {
    // TODO(devlin): When can |extension()| be null for this function?
    response = NoArguments();
  }
  Respond(std::move(response));
}

CookiesSetFunction::CookiesSetFunction()
    : state_(NO_RESPONSE), success_(false) {}

CookiesSetFunction::~CookiesSetFunction() {
}

ExtensionFunction::ResponseAction CookiesSetFunction::Run() {
  parsed_args_ = api::cookies::Set::Params::Create(*args_);
  EXTENSION_FUNCTION_VALIDATE(parsed_args_.get());

  // Read/validate input parameters.
  std::string error;
  if (!ParseUrl(extension(), parsed_args_->details.url, &url_, true, &error))
    return RespondNow(Error(error));

  std::string store_id =
      parsed_args_->details.store_id.get() ? *parsed_args_->details.store_id
                                           : std::string();
  network::mojom::CookieManager* cookie_manager = ParseStoreCookieManager(
      browser_context(), include_incognito_information(), &store_id, &error);
  if (!cookie_manager)
    return RespondNow(Error(error));

  if (!parsed_args_->details.store_id.get())
    parsed_args_->details.store_id.reset(new std::string(store_id));


  base::Time expiration_time;
  if (parsed_args_->details.expiration_date.get()) {
    // Time::FromDoubleT converts double time 0 to empty Time object. So we need
    // to do special handling here.
    expiration_time = (*parsed_args_->details.expiration_date == 0) ?
        base::Time::UnixEpoch() :
        base::Time::FromDoubleT(*parsed_args_->details.expiration_date);
  }

  net::CookieSameSite same_site = net::CookieSameSite::DEFAULT_MODE;
  switch (parsed_args_->details.same_site) {
    case api::cookies::SAME_SITE_STATUS_NONE:
    case api::cookies::SAME_SITE_STATUS_NO_RESTRICTION:
      same_site = net::CookieSameSite::DEFAULT_MODE;
      break;
    case api::cookies::SAME_SITE_STATUS_LAX:
      same_site = net::CookieSameSite::LAX_MODE;
      break;
    case api::cookies::SAME_SITE_STATUS_STRICT:
      same_site = net::CookieSameSite::STRICT_MODE;
      break;
  }

  // clang-format off
  std::unique_ptr<net::CanonicalCookie> cc(
      net::CanonicalCookie::CreateSanitizedCookie(
          url_, parsed_args_->details.name.get() ? *parsed_args_->details.name
                                                 : std::string(),
          parsed_args_->details.value.get() ? *parsed_args_->details.value
                                                 : std::string(),
          parsed_args_->details.domain.get() ? *parsed_args_->details.domain
                                             : std::string(),
          parsed_args_->details.path.get() ? *parsed_args_->details.path
                                           : std::string(),
          base::Time(),
          expiration_time,
          base::Time(),
          parsed_args_->details.secure.get() ? *parsed_args_->details.secure
                                             : false,
          parsed_args_->details.http_only.get() ?
              *parsed_args_->details.http_only :
              false,
          same_site,
          net::COOKIE_PRIORITY_DEFAULT));
  // clang-format on
  if (!cc) {
    // Return error through callbacks so that the proper error message
    // is generated.
    success_ = false;
    state_ = SET_COMPLETED;
    GetCookieListCallback(net::CookieList());
    return AlreadyResponded();
  }

  // Dispatch the setter, immediately followed by the getter.  This
  // plus FIFO ordering on the cookie_manager_ pipe means that no
  // other extension function will affect the get result.
  net::CookieOptions options;
  options.set_include_httponly();
  options.set_same_site_cookie_context(
      net::CookieOptions::SameSiteCookieContext::SAME_SITE_STRICT);
  cookie_manager->SetCanonicalCookie(
      *cc, url_.scheme(), options,
      base::BindOnce(&CookiesSetFunction::SetCanonicalCookieCallback, this));
  cookies_helpers::GetCookieListFromManager(
      cookie_manager, url_,
      base::BindOnce(&CookiesSetFunction::GetCookieListCallback, this));

  // Will finish asynchronously.
  return RespondLater();
}

void CookiesSetFunction::SetCanonicalCookieCallback(bool set_cookie_result) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);
  DCHECK_EQ(NO_RESPONSE, state_);
  state_ = SET_COMPLETED;
  success_ = set_cookie_result;
}

void CookiesSetFunction::GetCookieListCallback(
    const net::CookieList& cookie_list) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);
  DCHECK_EQ(SET_COMPLETED, state_);
  state_ = GET_COMPLETED;

  if (!success_) {
    std::string name = parsed_args_->details.name.get()
                           ? *parsed_args_->details.name
                           : std::string();
    Respond(Error(ErrorUtils::FormatErrorMessage(
        cookies_api_constants::kCookieSetFailedError, name)));
    return;
  }

  ResponseValue value;
  for (const net::CanonicalCookie& cookie : cookie_list) {
    // Return the first matching cookie. Relies on the fact that the
    // CookieMonster returns them in canonical order (longest path, then
    // earliest creation time).
    std::string name =
        parsed_args_->details.name.get() ? *parsed_args_->details.name
                                         : std::string();
    if (cookie.Name() == name) {
      api::cookies::Cookie api_cookie = cookies_helpers::CreateCookie(
          cookie, *parsed_args_->details.store_id);
      value = ArgumentList(api::cookies::Set::Results::Create(api_cookie));
      break;
    }
  }

  Respond(value ? std::move(value) : NoArguments());
}

CookiesRemoveFunction::CookiesRemoveFunction() {
}

CookiesRemoveFunction::~CookiesRemoveFunction() {
}

ExtensionFunction::ResponseAction CookiesRemoveFunction::Run() {
  parsed_args_ = api::cookies::Remove::Params::Create(*args_);
  EXTENSION_FUNCTION_VALIDATE(parsed_args_.get());

  // Read/validate input parameters.
  std::string error;
  if (!ParseUrl(extension(), parsed_args_->details.url, &url_, true, &error))
    return RespondNow(Error(error));

  std::string store_id =
      parsed_args_->details.store_id.get() ? *parsed_args_->details.store_id
                                           : std::string();
  network::mojom::CookieManager* cookie_manager = ParseStoreCookieManager(
      browser_context(), include_incognito_information(), &store_id, &error);
  if (!cookie_manager)
    return RespondNow(Error(error));

  if (!parsed_args_->details.store_id.get())
    parsed_args_->details.store_id.reset(new std::string(store_id));

  network::mojom::CookieDeletionFilterPtr filter(
      network::mojom::CookieDeletionFilter::New());
  filter->url = url_;
  filter->cookie_name = parsed_args_->details.name;
  cookie_manager->DeleteCookies(
      std::move(filter),
      base::BindOnce(&CookiesRemoveFunction::RemoveCookieCallback, this));

  // Will return asynchronously.
  return RespondLater();
}

void CookiesRemoveFunction::RemoveCookieCallback(uint32_t /* num_deleted */) {
  DCHECK_CURRENTLY_ON(BrowserThread::UI);

  // Build the callback result
  api::cookies::Remove::Results::Details details;
  details.name = parsed_args_->details.name;
  details.url = url_.spec();
  details.store_id = *parsed_args_->details.store_id;

  Respond(ArgumentList(api::cookies::Remove::Results::Create(details)));
}

ExtensionFunction::ResponseAction CookiesGetAllCookieStoresFunction::Run() {
  Profile* original_profile = Profile::FromBrowserContext(browser_context());
  DCHECK(original_profile);
  std::unique_ptr<base::ListValue> original_tab_ids(new base::ListValue());
  Profile* incognito_profile = NULL;
  std::unique_ptr<base::ListValue> incognito_tab_ids;
  if (include_incognito_information() &&
      original_profile->HasOffTheRecordProfile()) {
    incognito_profile = original_profile->GetOffTheRecordProfile();
    if (incognito_profile)
      incognito_tab_ids.reset(new base::ListValue());
  }
  DCHECK(original_profile != incognito_profile);

  // Iterate through all browser instances, and for each browser,
  // add its tab IDs to either the regular or incognito tab ID list depending
  // whether the browser is regular or incognito.
  for (auto* browser : *BrowserList::GetInstance()) {
    if (browser->profile() == original_profile) {
      cookies_helpers::AppendToTabIdList(browser, original_tab_ids.get());
    } else if (incognito_tab_ids.get() &&
               browser->profile() == incognito_profile) {
      cookies_helpers::AppendToTabIdList(browser, incognito_tab_ids.get());
    }
  }
  // Return a list of all cookie stores with at least one open tab.
  std::vector<api::cookies::CookieStore> cookie_stores;
  if (original_tab_ids->GetSize() > 0) {
    cookie_stores.push_back(cookies_helpers::CreateCookieStore(
        original_profile, std::move(original_tab_ids)));
  }
  if (incognito_tab_ids.get() && incognito_tab_ids->GetSize() > 0 &&
      incognito_profile) {
    cookie_stores.push_back(cookies_helpers::CreateCookieStore(
        incognito_profile, std::move(incognito_tab_ids)));
  }
  return RespondNow(ArgumentList(
      api::cookies::GetAllCookieStores::Results::Create(cookie_stores)));
}

CookiesAPI::CookiesAPI(content::BrowserContext* context)
    : browser_context_(context) {
  EventRouter::Get(browser_context_)
      ->RegisterObserver(this, api::cookies::OnChanged::kEventName);
}

CookiesAPI::~CookiesAPI() {
}

void CookiesAPI::Shutdown() {
  EventRouter::Get(browser_context_)->UnregisterObserver(this);
}

static base::LazyInstance<BrowserContextKeyedAPIFactory<CookiesAPI>>::
    DestructorAtExit g_cookies_api_factory = LAZY_INSTANCE_INITIALIZER;

// static
BrowserContextKeyedAPIFactory<CookiesAPI>* CookiesAPI::GetFactoryInstance() {
  return g_cookies_api_factory.Pointer();
}

void CookiesAPI::OnListenerAdded(const EventListenerInfo& details) {
  cookies_event_router_.reset(new CookiesEventRouter(browser_context_));
  EventRouter::Get(browser_context_)->UnregisterObserver(this);
}

}  // namespace extensions
