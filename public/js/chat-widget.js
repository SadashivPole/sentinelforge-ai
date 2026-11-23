// SentinelForge AI Support Assistant — Chat Widget UI
// Connects to a secure server-side support backend.
// No API keys or secrets are exposed in the browser.

(function () {
  'use strict';

  // Configuration
  const CONFIG = {
    backendEndpoint: '/api/support/chat', // Relative path — deployed backend only
    welcomeMessage:
      "Hello! I'm the SentinelForge AI Support Assistant. I can help you understand the project, explore detection capabilities, troubleshoot installation and navigate the documentation. What would you like to know?",
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
    backendUnavailableMessage:
      'The AI support backend is not yet hosted. This widget is ready to connect once a secure backend is deployed. For now, please refer to the documentation pages linked in the footer, or open a GitHub issue for help.',
    maxHistory: 50,
    typingDelay: 800
  };

  // DOM elements
  let panel, floatBtn, messagesContainer, inputField, sendBtn, statusBar;
  let suggestionsContainer;
  let isOpen = false;
  let isMinimized = false;
  let isTyping = false;
  let messageCount = 0;

  // Initialize when DOM is ready
  function init() {
    // Wait for the widget HTML to be injected
    const widgetContainer = document.getElementById('sentinelforge-support');
    if (!widgetContainer) {
      // Retry after short delay
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

    if (!panel || !floatBtn || !messagesContainer) return;

    bindEvents();
    renderWelcome();
    renderSuggestions();
    updateStatus('Backend not yet hosted — documentation only');
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
      if (e.target.closest('.suggestion-btn')) {
        const question = e.target.closest('.suggestion-btn').textContent.trim();
        inputField.value = question;
        inputField.style.height = 'auto';
        inputField.style.height = Math.min(inputField.scrollHeight, 120) + 'px';
        sendUserMessage();
      }
    });

    // Clear conversation
    const clearBtn = document.getElementById('support-clear');
    if (clearBtn) clearBtn.addEventListener('click', clearConversation);
  }

  function togglePanel() {
    isOpen = !isOpen;
    if (isOpen) {
      panel.classList.add('open');
      floatBtn.style.display = 'none';
      inputField.focus();
    } else {
      panel.classList.remove('open');
      floatBtn.style.display = 'flex';
    }
  }

  function minimizePanel() {
    isMinimized = true;
    panel.classList.remove('open');
    floatBtn.style.display = 'flex';
    floatBtn.querySelector('.badge').style.display = 'flex';
  }

  function closePanel() {
    isOpen = false;
    isMinimized = false;
    panel.classList.remove('open');
    floatBtn.style.display = 'flex';
    floatBtn.querySelector('.badge').style.display = 'none';
    clearConversation();
  }

  function renderWelcome() {
    addMessage(CONFIG.welcomeMessage, 'agent', true);
  }

  function renderSuggestions() {
    if (!suggestionsContainer) return;
    suggestionsContainer.innerHTML = '';
    const h4 = document.createElement('h4');
    h4.textContent = 'Suggested questions';
    suggestionsContainer.appendChild(h4);
    const grid = document.createElement('div');
    grid.className = 'suggestion-grid';
    CONFIG.suggestedQuestions.forEach(function (q) {
      const btn = document.createElement('button');
      btn.className = 'suggestion-btn';
      btn.type = 'button';
      btn.textContent = q;
      grid.appendChild(btn);
    });
    suggestionsContainer.appendChild(grid);
  }

  function updateStatus(text) {
    if (statusBar) statusBar.textContent = text;
  }

  // --- Messaging ---

  function addMessage(text, sender, isWelcome = false) {
    const wrapper = document.createElement('div');
    wrapper.className = 'message ' + sender;

    const avatar = document.createElement('div');
    avatar.className = 'message-avatar';
    avatar.textContent = sender === 'user' ? 'You' : 'S';

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

    // Trim history
    const messages = messagesContainer.querySelectorAll('.message');
    if (messages.length > CONFIG.maxHistory) {
      messages[0].remove();
    }

    return wrapper;
  }

  function addTypingIndicator() {
    if (isTyping) return;
    isTyping = true;
    const typing = document.createElement('div');
    typing.className = 'typing';
    typing.id = 'support-typing';
    typing.textContent = 'Assistant is typing…';
    messagesContainer.appendChild(typing);
    scrollToBottom();
  }

  function removeTypingIndicator() {
    isTyping = false;
    const typing = document.getElementById('support-typing');
    if (typing) typing.remove();
  }

  function addError(message) {
    const error = document.createElement('div');
    error.className = 'message agent state-error';
    error.innerHTML =
      '<div class="message-avatar">S</div>' +
      '<div class="message-content">' + escapeHtml(message) + '</div>' +
      '<div class="message-time">' + new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + '</div>' +
      '<button id="support-retry" style="margin-top:var(--space-xs);background:none;border:none;color:var(--forge-cyan);cursor:pointer;font-size:0.8125rem;">Retry</button>';
    messagesContainer.appendChild(error);
    scrollToBottom();
    document.getElementById('support-retry').addEventListener('click', function () {
      error.remove();
      const lastUser = document.querySelector('.message.user:last-child .message-content');
      if (lastUser) {
        inputField.value = lastUser.textContent;
        sendUserMessage();
      }
    });
  }

  function setInputLoading(loading) {
    inputField.disabled = loading;
    sendBtn.disabled = loading;
    if (!loading) inputField.focus();
  }

  function scrollToBottom() {
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  function clearConversation() {
    messagesContainer.innerHTML = '';
    messageCount = 0;
    renderWelcome();
    renderSuggestions();
  }

  async function sendUserMessage() {
    const text = inputField.value.trim();
    if (!text || isTyping) return;

    // Clear any error state
    const errors = messagesContainer.querySelectorAll('.state-error');
    errors.forEach(function (e) { e.remove(); });

    // Add user message
    addMessage(text, 'user');
    inputField.value = '';
    inputField.style.height = 'auto';
    setInputLoading(true);

    // Simulate backend unavailability — show status
    // In production, this would fetch(CONFIG.backendEndpoint, ...)
    await new Promise(resolve => setTimeout(resolve, CONFIG.typingDelay));

    addTypingIndicator();

    await new Promise(resolve => setTimeout(resolve, 1500));
    removeTypingIndicator();

    addMessage(CONFIG.backendUnavailableMessage, 'agent');
    updateStatus('Backend not yet hosted — documentation only');
    setInputLoading(false);
  }

  // Start
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
