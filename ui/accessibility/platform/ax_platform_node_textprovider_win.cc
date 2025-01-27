// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ui/accessibility/platform/ax_platform_node_textprovider_win.h"

#include <utility>

#include "ui/accessibility/ax_node_position.h"
#include "ui/accessibility/platform/ax_platform_node_delegate.h"
#include "ui/accessibility/platform/ax_platform_node_textrangeprovider_win.h"

#define UIA_VALIDATE_TEXTPROVIDER_CALL() \
  if (!owner()->GetDelegate())           \
    return UIA_E_ELEMENTNOTAVAILABLE;
#define UIA_VALIDATE_TEXTPROVIDER_CALL_1_ARG(arg) \
  if (!owner()->GetDelegate())                    \
    return UIA_E_ELEMENTNOTAVAILABLE;             \
  if (!arg)                                       \
    return E_INVALIDARG;

namespace ui {

AXPlatformNodeTextProviderWin::AXPlatformNodeTextProviderWin() {
  DVLOG(1) << __func__;
}

AXPlatformNodeTextProviderWin::~AXPlatformNodeTextProviderWin() {}

// static
HRESULT AXPlatformNodeTextProviderWin::Create(ui::AXPlatformNodeWin* owner,
                                              IUnknown** provider) {
  CComObject<AXPlatformNodeTextProviderWin>* text_provider = nullptr;
  HRESULT hr =
      CComObject<AXPlatformNodeTextProviderWin>::CreateInstance(&text_provider);
  if (SUCCEEDED(hr)) {
    DCHECK(text_provider);
    text_provider->owner_ = owner;
    hr = text_provider->QueryInterface(IID_PPV_ARGS(provider));
  }

  return hr;
}

//
// ITextProvider methods.
//

STDMETHODIMP AXPlatformNodeTextProviderWin::GetSelection(
    SAFEARRAY** selection) {
  WIN_ACCESSIBILITY_API_HISTOGRAM(UMA_API_TEXT_GETSELECTION);
  return E_NOTIMPL;
}

STDMETHODIMP AXPlatformNodeTextProviderWin::GetVisibleRanges(
    SAFEARRAY** visible_ranges) {
  WIN_ACCESSIBILITY_API_HISTOGRAM(UMA_API_TEXT_GETVISIBLERANGES);
  return E_NOTIMPL;
}

STDMETHODIMP AXPlatformNodeTextProviderWin::RangeFromChild(
    IRawElementProviderSimple* child,
    ITextRangeProvider** range) {
  UIA_VALIDATE_TEXTPROVIDER_CALL_1_ARG(child);

  DVLOG(1) << __func__;

  *range = nullptr;

  Microsoft::WRL::ComPtr<ui::AXPlatformNodeWin> child_platform_node;
  if (child->QueryInterface(IID_PPV_ARGS(&child_platform_node)) != S_OK)
    return UIA_E_INVALIDOPERATION;

  if (!owner()->IsDescendant(child_platform_node.Get()))
    return E_INVALIDARG;

  // Start and end should be leaf text positions.
  AXNodePosition::AXPositionInstance start = child_platform_node->GetDelegate()
                                                 ->CreateTextPositionAt(0)
                                                 ->AsLeafTextPosition();

  AXNodePosition::AXPositionInstance end =
      child_platform_node->GetDelegate()
          ->CreateTextPositionAt(start->MaxTextOffset())
          ->AsLeafTextPosition()
          ->CreatePositionAtEndOfAnchor();

  return AXPlatformNodeTextRangeProviderWin::CreateTextRangeProvider(
      owner_, std::move(start), std::move(end), range);
}

STDMETHODIMP AXPlatformNodeTextProviderWin::RangeFromPoint(
    UiaPoint uia_point,
    ITextRangeProvider** range) {
  WIN_ACCESSIBILITY_API_HISTOGRAM(UMA_API_TEXT_RANGEFROMPOINT);
  return E_NOTIMPL;
}

STDMETHODIMP AXPlatformNodeTextProviderWin::get_DocumentRange(
    ITextRangeProvider** range) {
  WIN_ACCESSIBILITY_API_HISTOGRAM(UMA_API_TEXT_GET_DOCUMENTRANGE);
  UIA_VALIDATE_TEXTPROVIDER_CALL();

  *range = nullptr;

  // Start and end should be leaf text positions that span the beginning
  // and end of text content within a node for get_DocumentRange. The start
  // position should be the directly first child and the end position should
  // be the deepest last child node.
  AXNodePosition::AXPositionInstance start =
      owner()->GetDelegate()->CreateTextPositionAt(0)->AsLeafTextPosition();

  AXNodePosition::AXPositionInstance end;
  if (owner()->GetChildCount() == 0) {
    end = start->CreatePositionAtEndOfAnchor()->AsLeafTextPosition();
  } else {
    AXPlatformNode* deepest_last_child =
        AXPlatformNode::FromNativeViewAccessible(
            owner()->ChildAtIndex(owner()->GetChildCount() - 1));

    while (deepest_last_child &&
           deepest_last_child->GetDelegate()->GetChildCount() > 0) {
      deepest_last_child = AXPlatformNode::FromNativeViewAccessible(
          deepest_last_child->GetDelegate()->ChildAtIndex(
              deepest_last_child->GetDelegate()->GetChildCount() - 1));
    }
    end = deepest_last_child->GetDelegate()
              ->CreateTextPositionAt(0)
              ->CreatePositionAtEndOfAnchor()
              ->AsLeafTextPosition();
  }

  return AXPlatformNodeTextRangeProviderWin::CreateTextRangeProvider(
      owner_, std::move(start), std::move(end), range);
}

STDMETHODIMP AXPlatformNodeTextProviderWin::get_SupportedTextSelection(
    enum SupportedTextSelection* text_selection) {
  WIN_ACCESSIBILITY_API_HISTOGRAM(UMA_API_TEXT_GET_SUPPORTEDTEXTSELECTION);
  UIA_VALIDATE_TEXTPROVIDER_CALL();

  *text_selection = SupportedTextSelection_Single;
  return S_OK;
}

//
// ITextEditProvider methods.
//

STDMETHODIMP AXPlatformNodeTextProviderWin::GetActiveComposition(
    ITextRangeProvider** range) {
  WIN_ACCESSIBILITY_API_HISTOGRAM(UMA_API_TEXTEDIT_GETACTIVECOMPOSITION);
  return E_NOTIMPL;
}

STDMETHODIMP AXPlatformNodeTextProviderWin::GetConversionTarget(
    ITextRangeProvider** range) {
  WIN_ACCESSIBILITY_API_HISTOGRAM(UMA_API_TEXTEDIT_GETCONVERSIONTARGET);
  return E_NOTIMPL;
}

ui::AXPlatformNodeWin* AXPlatformNodeTextProviderWin::owner() const {
  return owner_;
}

}  // namespace ui
