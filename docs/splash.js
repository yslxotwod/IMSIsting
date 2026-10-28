/* Decorative videos only play while visible and when motion is allowed. */
(function () {
  var videos = Array.from(document.querySelectorAll('.hero-video, .section-splash, .module-hero-video'));
  var reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
  var visible = new Set();

  function sync(video) {
    if (visible.has(video) && !reduced.matches && !document.hidden) {
      var playing = video.play();
      if (playing) playing.catch(function () {});
    } else {
      video.pause();
    }
  }

  if ('IntersectionObserver' in window) {
    var observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (entry) {
        if (entry.isIntersecting) visible.add(entry.target);
        else visible.delete(entry.target);
        sync(entry.target);
      });
    }, { threshold: 0.01 });
    videos.forEach(function (video) { observer.observe(video); });
  } else {
    videos.forEach(function (video) { visible.add(video); sync(video); });
  }
  function syncAll() { videos.forEach(sync); }
  if (reduced.addEventListener) reduced.addEventListener('change', syncAll);
  else if (reduced.addListener) reduced.addListener(syncAll);
  document.addEventListener('visibilitychange', syncAll);
})();
