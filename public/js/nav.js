// SentinelForge Navigation
(function () {
  const toggle = document.querySelector('.nav-toggle');
  const nav = document.querySelector('#nav-links');
  const links = document.querySelectorAll('.nav-links a');
  const currentPath = window.location.pathname;

  // Mobile menu toggle
  if (toggle && nav) {
    toggle.addEventListener('click', function () {
      const isOpen = nav.classList.toggle('open');
      toggle.setAttribute('aria-expanded', isOpen);
    });
  }

  // Close menu on Escape key
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && nav && nav.classList.contains('open')) {
      nav.classList.remove('open');
      if (toggle) toggle.setAttribute('aria-expanded', 'false');
    }
  });

  // Highlight current page in navigation
  links.forEach(function (link) {
    const href = link.getAttribute('href');
    if (href && currentPath.endsWith(href)) {
      link.classList.add('active');
      link.setAttribute('aria-current', 'page');
    }
  });
})();
