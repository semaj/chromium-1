// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "components/viz/service/surfaces/surface_allocation_group.h"

#include "components/viz/service/surfaces/surface.h"
#include "components/viz/service/surfaces/surface_manager.h"

namespace viz {

SurfaceAllocationGroup::SurfaceAllocationGroup(
    SurfaceManager* surface_manager,
    const FrameSinkId& submitter,
    const base::UnguessableToken& embed_token)
    : submitter_(submitter),
      embed_token_(embed_token),
      surface_manager_(surface_manager) {}

SurfaceAllocationGroup::~SurfaceAllocationGroup() = default;

bool SurfaceAllocationGroup::IsReadyToDestroy() const {
  return surfaces_.empty() && active_embedders_.empty();
}

void SurfaceAllocationGroup::RegisterSurface(Surface* surface) {
  DCHECK_EQ(submitter_, surface->surface_id().frame_sink_id());
  DCHECK_EQ(embed_token_,
            surface->surface_id().local_surface_id().embed_token());
  DCHECK(!last_created_surface() || surface->surface_id().IsNewerThan(
                                        last_created_surface()->surface_id()));
  surfaces_.push_back(surface);
}

void SurfaceAllocationGroup::UnregisterSurface(Surface* surface) {
  auto it = std::find(surfaces_.begin(), surfaces_.end(), surface);
  DCHECK(it != surfaces_.end());
  surfaces_.erase(it);
  MaybeMarkForDestruction();
}

void SurfaceAllocationGroup::RegisterActiveEmbedder(Surface* surface) {
  DCHECK(!active_embedders_.count(surface));
  active_embedders_.insert(surface);
}

void SurfaceAllocationGroup::UnregisterActiveEmbedder(Surface* surface) {
  DCHECK(active_embedders_.count(surface));
  active_embedders_.erase(surface);
  MaybeMarkForDestruction();
}

void SurfaceAllocationGroup::UpdateLastReferencedSurfaceAndMaybeActivate(
    const SurfaceId& surface_id) {
  DCHECK_EQ(submitter_, surface_id.frame_sink_id());
  DCHECK_EQ(embed_token_, surface_id.local_surface_id().embed_token());
  if (last_referenced_surface_id_.is_valid() &&
      last_referenced_surface_id_.IsSameOrNewerThan(surface_id)) {
    return;
  }
  last_referenced_surface_id_ = surface_id;
  auto it = FindLatestSurfaceUpTo(surface_id);
  if (it != surfaces_.end() && !(*it)->HasActiveFrame())
    (*it)->ActivatePendingFrameForInheritedDeadline();
}

const SurfaceId& SurfaceAllocationGroup::GetLastReferencedSurfaceId() {
  return last_referenced_surface_id_;
}

Surface* SurfaceAllocationGroup::FindLatestActiveSurfaceInRange(
    const SurfaceRange& range) const {
  // If the embed token of the end of the SurfaceRange matches that of this
  // group, find the latest active surface that is older than or equal to the
  // end, then check that it's not older than start.
  if (range.end().local_surface_id().embed_token() == embed_token_) {
    DCHECK_EQ(submitter_, range.end().frame_sink_id());
    auto it = FindLatestActiveSurfaceUpTo(range.end());
    if (it != surfaces_.end() &&
        (!range.start() || !range.start()->IsNewerThan((*it)->surface_id()))) {
      return *it;
    } else {
      return nullptr;
    }
  }

  // If we are here, the embed token of the end of the range doesn't match this
  // group's embed token. In this case, the range must have a start and its
  // embed token must match this group. Simply find the last active surface, and
  // check whether it's newer than the range's start.
  DCHECK(range.start());
  DCHECK_EQ(embed_token_, range.start()->local_surface_id().embed_token());
  DCHECK_NE(embed_token_, range.end().local_surface_id().embed_token());
  DCHECK_EQ(submitter_, range.start()->frame_sink_id());

  Surface* result = nullptr;
  // Normally there is at most one pending surface, so this for loop shouldn't
  // take more than two iterations.
  for (int i = surfaces_.size() - 1; i >= 0; i--) {
    if (surfaces_[i]->HasActiveFrame()) {
      result = surfaces_[i];
      break;
    }
  }
  if (result && range.start()->IsNewerThan(result->surface_id()))
    return nullptr;
  return result;
}

void SurfaceAllocationGroup::TakeAggregatedLatencyInfoUpTo(
    Surface* surface,
    std::vector<ui::LatencyInfo>* out) {
  DCHECK_EQ(this, surface->allocation_group());
  surface->TakeActiveLatencyInfo(out);
  auto it = FindLatestSurfaceUpTo(surface->surface_id());
  DCHECK_EQ(*it, surface);
  for (--it; it >= surfaces_.begin() && !(*it)->is_latency_info_taken(); --it)
    (*it)->TakeActiveAndPendingLatencyInfo(out);
}

void SurfaceAllocationGroup::OnFirstSurfaceActivation(Surface* surface) {
  for (Surface* embedder : active_embedders_)
    embedder->OnChildActivatedForActiveFrame(surface->surface_id());
}

std::vector<Surface*>::const_iterator
SurfaceAllocationGroup::FindLatestSurfaceUpTo(
    const SurfaceId& surface_id) const {
  DCHECK_EQ(submitter_, surface_id.frame_sink_id());
  DCHECK_EQ(embed_token_, surface_id.local_surface_id().embed_token());

  // Return early if there are no surfaces in this group.
  if (surfaces_.empty())
    return surfaces_.end();

  // If even the first surface is newer than |surface_id|, we can't find a
  // surface that is older than or equal to |surface_id|.
  if (surfaces_[0]->surface_id().IsNewerThan(surface_id))
    return surfaces_.end();

  // Perform a binary search the find the latest surface that is older than or
  // equal to |surface_id|.
  int begin = 0;
  int end = surfaces_.size();
  while (end - begin > 1) {
    int avg = (begin + end) / 2;
    if (surfaces_[avg]->surface_id().IsNewerThan(surface_id))
      end = avg;
    else
      begin = avg;
  }

  return surfaces_.begin() + begin;
}

std::vector<Surface*>::const_iterator
SurfaceAllocationGroup::FindLatestActiveSurfaceUpTo(
    const SurfaceId& surface_id) const {
  // Start from the last older or equal surface and keep iterating back until we
  // find an active surface. Normally, there is only one pending surface at a
  // time this shouldn't take more than two iterations.
  auto it = FindLatestSurfaceUpTo(surface_id);

  if (it == surfaces_.end())
    return surfaces_.end();

  for (; it >= surfaces_.begin(); --it) {
    if ((*it)->HasActiveFrame())
      return it;
  }

  // No active surface was found.
  return surfaces_.end();
}

void SurfaceAllocationGroup::MaybeMarkForDestruction() {
  if (IsReadyToDestroy())
    surface_manager_->SetAllocationGroupsNeedGarbageCollection();
}

}  // namespace viz
