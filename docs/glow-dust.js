/* Decorative particles live outside clipped window surfaces and never intercept input. */
(function () {
  var targets = document.querySelectorAll('.button, .spec-plate, .cap-card, .screenshot, .terminal, .state-grid, .command-block');
  var motion = window.matchMedia('(prefers-reduced-motion: reduce)');
  var active = null;
  var canvas = null;
  var context = null;
  var particles = [];
  var frame = 0;
  var previous = 0;
  var accumulator = 0;

  function stop() {
    active = null;
    particles = [];
    accumulator = 0;
    previous = 0;
    if (frame) cancelAnimationFrame(frame);
    frame = 0;
    if (canvas) context.clearRect(0, 0, canvas.width, canvas.height);
  }

  function start(target) {
    if (motion.matches || document.hidden || active === target) return;
    stop();
    if (!canvas) {
      canvas = document.createElement('canvas');
      canvas.className = 'glow-dust';
      canvas.setAttribute('aria-hidden', 'true');
      document.body.appendChild(canvas);
      context = canvas.getContext('2d');
      if (!context) { canvas.remove(); canvas = null; return; }
    }
    active = target;
    resize();
    for (var i = 0; i < 12; i++) spawn();
    frame = requestAnimationFrame(draw);
  }

  function resize() {
    if (!canvas) return;
    var ratio = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.round(window.innerWidth * ratio);
    canvas.height = Math.round(window.innerHeight * ratio);
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
  }

  function spawn() {
    var rect = active.getBoundingClientRect();
    var side = Math.floor(Math.random() * 4);
    var x = side < 2 ? rect.left + Math.random() * rect.width : (side === 2 ? rect.left : rect.right);
    var y = side >= 2 ? rect.top + Math.random() * rect.height : (side === 0 ? rect.top : rect.bottom);
    var angle = side === 0 ? -Math.PI / 2 : side === 1 ? Math.PI / 2 : side === 2 ? Math.PI : 0;
    angle += (Math.random() - .5) * 1.2;
    var speed = 4 + Math.random() * 12;
    particles.push({x:x, y:y, vx:Math.cos(angle)*speed, vy:Math.sin(angle)*speed - 2, life:.8 + Math.random()*1.2, age:0, radius:.6 + Math.random()*1.25});
  }

  function draw(time) {
    if (!active) return;
    var elapsed = previous ? Math.min((time - previous) / 1000, .05) : 0;
    previous = time;
    context.clearRect(0, 0, window.innerWidth, window.innerHeight);
    accumulator += elapsed * 18;
    while (accumulator >= 1 && particles.length < 35) { spawn(); accumulator--; }
    accumulator = Math.min(accumulator, 1);
    particles = particles.filter(function (particle) {
      particle.age += elapsed;
      if (particle.age >= particle.life) return false;
      particle.x += particle.vx * elapsed;
      particle.y += particle.vy * elapsed;
      var fade = Math.sin(Math.PI * particle.age / particle.life);
      context.beginPath();
      context.arc(particle.x, particle.y, particle.radius, 0, Math.PI * 2);
      context.fillStyle = 'rgba(153, 232, 255,' + (fade * .85) + ')';
      context.shadowColor = '#6bd7f5';
      context.shadowBlur = 7;
      context.fill();
      return true;
    });
    frame = requestAnimationFrame(draw);
  }

  targets.forEach(function (target) {
    target.addEventListener('pointerenter', function (event) { if (event.pointerType !== 'touch') start(target); });
    target.addEventListener('pointerleave', function () { if (active === target) stop(); });
    target.addEventListener('focusin', function (event) { if (event.target.matches(':focus-visible')) start(target); });
    target.addEventListener('focusout', function () { if (active === target) stop(); });
  });
  window.addEventListener('resize', resize);
  window.addEventListener('scroll', function () { if (active) stop(); }, {passive:true});
  document.addEventListener('visibilitychange', function () { if (document.hidden) stop(); });
  if (motion.addEventListener) motion.addEventListener('change', function () { if (motion.matches) stop(); });
  else if (motion.addListener) motion.addListener(function () { if (motion.matches) stop(); });
})();
