// /js/dashboard-common.js
(function (window, $) {
  'use strict';

  // Percent change badge utility used across modules
  function setChange(selector, percent) {
    const el = $(selector);
    el.removeClass('up down neutral');
    if (percent > 0) {
      el.addClass('up').html(`<span>+${percent}%</span><span class="arrow">&#8599;</span>`);
    } else if (percent < 0) {
      el.addClass('down').html(`<span>${percent}%</span><span class="arrow">&#8600;</span>`);
    } else {
      el.addClass('neutral').html(`<span>0%</span><span class="arrow">&#8594;</span>`);
    }
  }

  // Expose only what we need
  window.Dash = { setChange };
})(window, jQuery);
