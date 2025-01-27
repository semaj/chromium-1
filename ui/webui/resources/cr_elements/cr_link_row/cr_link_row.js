// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview
 * A link row is a UI element similar to a button, though usually wider than a
 * button (taking up the whole 'row'). The name link comes from the intended use
 * of this element to take the user to another page in the app or to an external
 * page (somewhat like an HTML link).
 * Note: the ripple handling was taken from Polymer v1 paper-icon-button-light.
 */
Polymer({
  is: 'cr-link-row',

  properties: {
    startIcon: {
      type: String,
      value: '',
    },

    label: {
      type: String,
      value: '',
    },

    subLabel: {
      type: String,
      /* Value used for noSubLabel attribute. */
      value: '',
      observer: 'onSubLabelChange_',
    },

    disabled: {
      type: Boolean,
      reflectToAttribute: true,
    },

    external: {
      type: Boolean,
      value: false,
    },

    /** @private {string|undefined} */
    ariaDescribedBy_: String,
  },

  /** @type {boolean} */
  get noink() {
    return this.$.icon.noink;
  },

  /** @type {boolean} */
  set noink(value) {
    this.$.icon.noink = value;
  },

  focus: function() {
    this.$.icon.focus();
  },

  /** @private */
  getIconClass_: function() {
    return this.external ? 'icon-external' : 'subpage-arrow';
  },

  /** @private */
  onSubLabelChange_: function() {
    this.ariaDescribedBy_ = this.subLabel ? 'subLabel' : undefined;
  },
});
