const screens = {
  welcome: document.getElementById('screen-welcome'),
  running: document.getElementById('screen-running'),
  donePush: document.getElementById('screen-done-push'),
  doneFile: document.getElementById('screen-done-file'),
  error: document.getElementById('screen-error'),
};

function show(name) {
  for (const [k, el] of Object.entries(screens)) {
    el.classList.toggle('hidden', k !== name);
  }
}

let currentConfig = null;

async function init() {
  currentConfig = await window.collector.getConfig();
  document.getElementById('welcome-msp').textContent = currentConfig.msp_name;
  document.getElementById('welcome-prospect').textContent = currentConfig.prospect_name;
  document.getElementById('welcome-fingerprint').textContent = currentConfig.fingerprint || '—';
  document.getElementById('done-msp').textContent = currentConfig.msp_name;

  document.getElementById('start-btn').addEventListener('click', startScan);
  document.getElementById('abort-btn').addEventListener('click', () => window.collector.abort());
  document.getElementById('close-btn').addEventListener('click', () => window.collector.close());
  document.getElementById('close-btn-2').addEventListener('click', () => window.collector.close());
  document.getElementById('error-close-btn').addEventListener('click', () => window.collector.close());
  document.getElementById('welcome-whatwedo').addEventListener('click', (e) => {
    e.preventDefault();
    alert(
      'PCC Scout inventories the devices on your network so your IT team can:\n\n' +
      '• See what computers, phones, printers and servers exist\n' +
      '• Detect outdated systems that need patches\n' +
      '• Spot risky settings like open remote-desktop or old file-sharing\n\n' +
      "It does NOT read documents, passwords, browser history, or personal files."
    );
  });

  window.collector.onProgress((p) => {
    document.getElementById('running-phase').textContent = p.phase || '';
    const pct = Math.max(0, Math.min(100, Math.round(p.percent || 0)));
    document.getElementById('progress-bar').style.width = pct + '%';
    document.getElementById('progress-percent').textContent = pct + '%';
  });

  window.collector.onComplete((result) => {
    if (result.delivery === 'push') {
      show('donePush');
    } else {
      document.getElementById('file-path').textContent = result.filePath;
      document.getElementById('mailto-btn').onclick = () => window.collector.openExternal(result.mailto);
      document.getElementById('open-file-btn').onclick = () => window.collector.openPath(result.filePath);
      show('doneFile');
    }
  });

  window.collector.onError((msg) => {
    document.getElementById('error-message').textContent = msg;
    show('error');
  });

  show('welcome');
}

function startScan() {
  show('running');
  window.collector.start().catch(() => { /* error handler fires via onError */ });
}

init();
