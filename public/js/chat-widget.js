// SentinelForge AI Support Assistant — Chat Widget UI
// Preview only. No AI backend is connected. Messages are not sent to any AI service.
// Code is structured for future genuine backend integration.
// No API keys or secrets are exposed in the browser.

(function () {
  'use strict';

  // Configuration
  const CONFIG = {
    welcomeMessage:
      "Hello! I'm the SentinelForge AI Support Assistant (preview). The AI backend is not yet hosted, so I can't respond to messages right now. For help, see the documentation links in the footer or open a GitHub issue.",
    suggestedQuestions: [
      'What is SentinelForge AI?',
      'How do I install SentinelForge?',
      'How does the detection engine work?',
      'What are the five detection rules?',
      'How do I run the local SOC dashboard?',
      'How does MITRE ATT&CK mapping work?',
      'What is the difference between the public demo and local dashboard?',
      'How can I contribute to the project?'
    ],
    previewNotice:
      'Preview only — AI backend not yet hosted. Messages are not sent to any AI service. Use the documentation links or GitHub issues for support.',
    maxHistory: 50
  };

  // DOM elements
  let panel, floatBtn, messagesContainer, inputField, sendBtn, statusBar;
  let suggestionsContainer, previewNoticeEl;
  let isOpen = false;
  let isMinimized = false;
  let lastFocusedElement = null;
  let messageCount = 0;

  // Initialize when DOM is ready
  function init() {
    const widgetContainer = document.getElementById('sentinelforge-support');
    if (!widgetContainer) {
      setTimeout(init, 100);
      return;
    }

    panel = document.getElementById('support-panel');
    floatBtn = document.getElementById('support-float-btn');
    messagesContainer = document.getElementById('support-messages');
    inputField = document.getElementById('support-input');
    sendBtn = document.getElementById('support-send');
    statusBar = document.getElementById('support-status');
    suggestionsContainer = document.getElementById('support-suggestions');
    previewNoticeEl = document.getElementById('support-preview-notice');

    if (!panel || !floatBtn || !messagesContainer) return;

    bindEvents();
    renderWelcome();
    renderSuggestions();
    updateStatus('Preview — AI backend not yet hosted');
  }

  function bindEvents() {
    // Toggle panel
    floatBtn.addEventListener('click', togglePanel);

    // Minimize / close
    const minimizeBtn = document.getElementById('support-minimize');
    const closeBtn = document.getElementById('support-close');
    if (minimizeBtn) minimizeBtn.addEventListener('click', minimizePanel);
    if (closeBtn) closeBtn.addEventListener('click', closePanel);

    // Send message
    sendBtn.addEventListener('click', sendUserMessage);
    inputField.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendUserMessage();
      }
    });

    // Auto-resize textarea
    inputField.addEventListener('input', function () {
      this.style.height = 'auto';
      this.style.height = Math.min(this.scrollHeight, 120) + 'px';
    });

    // Suggested questions
    document.addEventListener('click', function (e) {
      const btn = e.target.closest('.suggestion-btn');
      if (btn) {
        const question = btn.textContent.trim();
        inputField.value = question;
        inputField.style.height = 'auto';
        inputField.style.height = Math.min(inputField.scrollHeight, 120) + 'px';
        sendUserMessage();
      }
    });

    // Clear conversation
    const clearBtn = document.getElementById('support-clear');
    if (clearBtn) clearBtn.addEventListener('click', clearConversation);

    // Escape key closes panel when open
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && isOpen) {
        e.preventDefault();
        closePanel();
      }
    });
  }

  // Panel state management
  function togglePanel() {
    if (isMinimized) {
      // Restore from minimized state
      isMinimized = false;
      isOpen = true;
      panel.classList.add('open');
      panel.setAttribute('aria-hidden', 'false');
      floatBtn.style.display = 'none';
      const badge = floatBtn.querySelector('.badge');
      if (badge) badge.style.display = 'none';
      lastFocusedElement = floatBtn;
      inputField.focus();
    } else if (isOpen) {
      closePanel();
    } else {
      isOpen = true;
      panel.classList.add('open');
      panel.setAttribute('aria-hidden', 'false');
      floatBtn.style.display = 'none';
      lastFocusedElement = floatBtn;
      inputField.focus();
    }
  }

  function minimizePanel() {
    isMinimized = true;
    isOpen = false;
    panel.classList.remove('open');
    panel.setAttribute('aria-hidden', 'true');
    floatBtn.style.display = 'flex';
    const badge = floatBtn.querySelector('.badge');
    if (badge) badge.style.display = 'flex';
  }

  function closePanel() {
    isOpen = false;
    isMinimized = false;
    panel.classList.remove('open');
    panel.setAttribute('aria-hidden', 'true');
    floatBtn.style.display = 'flex';
    const badge = floatBtn.querySelector('.badge');
    if (badge) badge.style.display = 'none';
    // Restore focus to the floating button
    if (lastFocusedElement) {
      lastFocusedElement.focus();
      lastFocusedElement = null;
    }
    clearConversation();
  }

  // Rendering (safe DOM, no innerHTML for dynamic content)
  function renderWelcome() {
    addMessage(CONFIG.welcomeMessage, 'agent', true);
  }

  function renderSuggestions() {
    if (!suggestionsContainer) return;
    suggestionsContainer.innerHTML = '';
    const h4 = document.createElement('h4');
    h4.id = 'support-suggestions-label';
    h4.textContent = 'Suggested questions';
    suggestionsContainer.appendChild(h4);
    const grid = document.createElement('div');
    grid.className = 'suggestion-grid';
    CONFIG.suggestedQuestions.forEach(function (q) {
      const btn = document.createElement('button');
      btn.className = 'suggestion-btn';
      btn.type = 'button';
      btn.textContent = q;
      btn.setAttribute('aria-describedby', 'support-suggestions-label');
      grid.appendChild(btn);
    });
    suggestionsContainer.appendChild(grid);
  }

  function updateStatus(text) {
    if (statusBar) statusBar.textContent = text;
  }

  function addMessage(text, sender, isWelcome = false) {
    const wrapper = document.createElement('div');
    wrapper.className = 'message ' + sender;

    const avatar = document.createElement('div');
    avatar.className = 'message-avatar';
    avatar.textContent = sender === 'user' ? 'You' : 'S';
    avatar.setAttribute('aria-hidden', 'true');

    const content = document.createElement('div');
    content.className = 'message-content';
    content.textContent = text;

    const time = document.createElement('div');
    time.className = 'message-time';
    time.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    wrapper.appendChild(avatar);
    wrapper.appendChild(content);
    wrapper.appendChild(time);

    if (isWelcome) {
      wrapper.classList.add('fade-in');
    }

    messagesContainer.appendChild(wrapper);
    scrollToBottom();
    messageCount++;

    const messages = messagesContainer.querySelectorAll('.message');
    if (messages.length > CONFIG.maxHistory) {
      messages[0].remove();
    }

    return wrapper;
  }

  function addPreviewNotice() {
    const notice = document.createElement('div');
    notice.className = 'message agent state-info';
    notice.setAttribute('role', 'status');
    notice.setAttribute('aria-live', 'polite');

    const avatar = document.createElement('div');
    avatar.className = 'message-avatar';
    avatar.textContent = 'S';
    avatar.setAttribute('aria-hidden', 'true');

    const content = document.createElement('div');
    content.className = 'message-content';
    content.textContent = CONFIG.previewNotice;

    const time = document.createElement('div');
    time.className = 'message-time';
    time.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    notice.appendChild(avatar);
    notice.appendChild(content);
    notice.appendChild(time);

    messagesContainer.appendChild(notice);
    scrollToBottom();
    messageCount++;
    return notice;
  }

  function addError(message) {
    const error = document.createElement('div');
    error.className = 'message agent state-error';
    error.setAttribute('role', 'alert');
    error.setAttribute('aria-live', 'polite');

    const avatar = document.createElement('div');
    avatar.className = 'message-avatar';
    avatar.textContent = 'S';
    avatar.setAttribute('aria-hidden', 'true');

    const content = document.createElement('div');
    content.className = 'message-content';
    content.textContent = message;

    const time = document.createElement('div');
    time.className = 'message-time';
    time.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    const retryBtn = document.createElement('button');
    retryBtn.id = 'support-retry';
    retryBtn.type = 'button';
    retryBtn.textContent = 'Retry';
    retryBtn.style.cssText =
      'margin-top:var(--space-xs);background:none;border:none;color:var(--forge-cyan);cursor:pointer;font-size:0.8125rem;';
    retryBtn.addEventListener('click', function () {
      error.remove();
      const lastUser = document.querySelector('.message.user:last-child .message-content');
      if (lastUser) {
        inputField.value = lastUser.textContent;
        sendUserMessage();
      }
    });

    error.appendChild(avatar);
    error.appendChild(content);
    error.appendChild(time);
    error.appendChild(retryBtn);

    messagesContainer.appendChild(error);
    scrollToBottom();
  }

  function setInputLoading(loading) {
    inputField.disabled = loading;
    sendBtn.disabled = loading;
    if (!loading) inputField.focus();
  }

  function scrollToBottom() {
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }

  function clearConversation() {
    messagesContainer.innerHTML = '';
    messageCount = 0;
    renderWelcome();
    renderSuggestions();
    addPreviewNotice();
  }

  function sendUserMessage() {
    const text = inputField.value.trim();
    if (!text) return;

    // Clear any error state
    const errors = messagesContainer.querySelectorAll('.state-error');
    errors.forEach(function (e) { e.remove(); });

    // Add user message
    addMessage(text, 'user');
    inputField.value = '';
    inputField.style.height = 'auto';

    // Preview notice — backend not available, do not simulate AI typing or response
    addPreviewNotice();
    updateStatus('Preview — AI backend not yet hosted');
    inputField.focus();
  }

  // Start
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
