// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_UI_VIEWS_AUTOFILL_LOCAL_CARD_MIGRATION_ICON_VIEW_H_
#define CHROME_BROWSER_UI_VIEWS_AUTOFILL_LOCAL_CARD_MIGRATION_ICON_VIEW_H_

#include "base/macros.h"
#include "chrome/browser/ui/views/page_action/page_action_icon_view.h"

class Browser;
class CommandUpdater;

namespace autofill {

class ManageMigrationUiController;

// The icon shown in location bar for the intermediate local card migration
// bubble.
class LocalCardMigrationIconView : public PageActionIconView {
 public:
  LocalCardMigrationIconView(CommandUpdater* command_updater,
                             Browser* browser,
                             PageActionIconView::Delegate* delegate,
                             const gfx::FontList& font_list);
  ~LocalCardMigrationIconView() override;

  // PageActionIconView:
  views::BubbleDialogDelegateView* GetBubble() const override;
  bool Update() override;
  base::string16 GetTextForTooltipAndAccessibleName() const override;

 protected:
  // PageActionIconView:
  void OnExecuting(PageActionIconView::ExecuteSource execute_source) override;
  const gfx::VectorIcon& GetVectorIcon() const override;
  const gfx::VectorIcon& GetVectorIconBadge() const override;

 private:
  ManageMigrationUiController* GetController() const;

  // IconLabelBubbleView:
  void AnimationProgressed(const gfx::Animation* animation) override;
  void AnimationEnded(const gfx::Animation* animation) override;

  // Used to do nullptr check when getting the controller.
  Browser* const browser_;

  DISALLOW_COPY_AND_ASSIGN(LocalCardMigrationIconView);
};

}  // namespace autofill

#endif  // CHROME_BROWSER_UI_VIEWS_AUTOFILL_LOCAL_CARD_MIGRATION_ICON_VIEW_H_
