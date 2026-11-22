// SentinelForge — Public Demo Application
const app = {
  scenarios: null,
  selectedId: null,
  init() {
    this.grid = document.getElementById('scenario-grid');
    this.panel = document.getElementById('detail-panel');
    this.title = document.getElementById('detail-title');
    this.mitre = document.getElementById('detail-mitre');
    this.content = document.getElementById('detail-content');
    this.resetBtn = document.getElementById('reset-btn');
    fetch('data/scenarios.json')
      .then(r => r.json())
      .then(data => {
        this.scenarios = data.scenarios;
        this.renderGrid();
      })
      .catch(err => {
        console.error('Failed to load demo scenarios:', err);
        this.grid.innerHTML = '<p style="color:#EF6472">Failed to load demo data.</p>';
      });
  },
  renderGrid() {
    this.grid.innerHTML = '';
    this.scenarios.forEach(s => {
      const card = document.createElement('article');
      card.className = 'scenario-card';
      card.setAttribute('role', 'button');
      card.setAttribute('tabindex', '0');
      card.setAttribute('aria-label', 'Select ' + s.name + ' scenario');
      card.innerHTML = `
        <div class="scenario-header">
          <h3>${this.escape(s.name)}</h3>
          <span class="severity-badge severity-${s.severity.toLowerCase()}">${this.escape(s.severity)}</span>
        </div>
        <p>${this.escape(s.description)}</p>
        <div class="scenario-meta">
          <span class="meta-item">MITRE: ${this.escape(s.mitre)}</span>
          <span class="meta-item">Rule: ${this.escape(s.rule)}</span>
          <span class="meta-item">Events: ${s.events.length}</span>
        </div>
      `;
      card.addEventListener('click', () => this.select(s.id));
      card.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          this.select(s.id);
        }
      });
      this.grid.appendChild(card);
    });
  },
  select(id) {
    this.selectedId = id;
    const scenario = this.scenarios.find(s => s.id === id);
    if (!scenario) return;
    this.renderGrid();
    const idx = this.scenarios.findIndex(s => s.id === id);
    const selectedCard = this.grid.children[idx];
    if (selectedCard) selectedCard.classList.add('selected');
    this.title.textContent = scenario.name;
    this.mitre.textContent = scenario.mitre + ' · Rule: ' + scenario.rule + ' · Severity: ' + scenario.severity;
    this.panel.classList.add('visible');
    const eventsHtml = scenario.events.map(e => `
      <div class="event-row">
        <span class="time">${this.escape(e.timestamp)}</span>
        <span class="type">${this.escape(e.event_type)}</span>
        <span class="raw">${this.escape(e.raw)}</span>
      </div>
    `).join('');
    this.content.innerHTML = `
      <div class="detection-card">
        <h3>Detection result</h3>
        <p><strong>Rule:</strong> ${this.escape(scenario.detection.rule_id)}</p>
        <p><strong>Matched events:</strong> ${scenario.detection.matched_events.join(', ')}</p>
        <p><strong>Evidence:</strong> ${this.escape(scenario.detection.evidence_citation)}</p>
        <span class="risk-score">Risk score: ${scenario.detection.risk_score}/100</span>
        <div class="confidence">Detection confidence: ${Math.round(scenario.detection.confidence * 100)}%</div>
        ${scenario.detection.note ? '<div class="note-box">' + this.escape(scenario.detection.note) + '</div>' : ''}
      </div>
      <h3 style="margin-top:1.5rem;font-size:1rem;color:#35D6C3;">Raw events (${scenario.events.length})</h3>
      <div class="events-list">${eventsHtml}</div>
      <p style="font-size:0.8125rem;color:#6B80A0;margin-top:1rem;">Raw log lines are preserved verbatim.</p>
    `;
    this.panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
  },
  reset() {
    this.selectedId = null;
    this.renderGrid();
    this.panel.classList.remove('visible');
    this.title.textContent = 'Select a scenario';
    this.mitre.textContent = '';
    this.content.innerHTML = '';
  },
  escape(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
};
document.addEventListener('DOMContentLoaded', () => app.init());
