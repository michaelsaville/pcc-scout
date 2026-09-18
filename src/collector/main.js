const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const { loadConfig } = require('./config');
const { collectAll } = require('./scanner/native');
const { deliver } = require('./transport');

// Parse --mode=push|file (default push) from argv.
function parseMode() {
  const arg = process.argv.find(a => a.startsWith('--mode='));
  if (arg) {
    const v = arg.split('=')[1];
    if (v === 'file' || v === 'push') return v;
  }
  return 'push';
}

let mainWindow;
let aborted = false;
const mode = parseMode();
const config = loadConfig();

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 720,
    height: 560,
    resizable: false,
    title: `Network Scan — ${config.msp_name}`,
    backgroundColor: '#0b0d12',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  mainWindow.setMenuBarVisibility(false);
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

app.whenReady().then(createWindow);
app.on('window-all-closed', () => app.quit());

ipcMain.handle('collector:config', () => ({
  prospect_name: config.prospect_name,
  msp_name: config.msp_name,
  tech_email: config.tech_email,
  fingerprint: config.fingerprint,
  mode,
}));

ipcMain.handle('collector:start', async () => {
  aborted = false;
  try {
    mainWindow.webContents.send('collector:progress', { phase: 'Starting...', percent: 2 });

    const result = await collectAll((progress) => {
      if (aborted) throw new Error('Aborted by user');
      mainWindow.webContents.send('collector:progress', progress);
    });

    if (aborted) throw new Error('Aborted by user');
    mainWindow.webContents.send('collector:progress', { phase: 'Delivering results...', percent: 95 });

    const deliveryResult = await deliver(result, config, mode);

    mainWindow.webContents.send('collector:progress', { phase: 'Done', percent: 100 });
    mainWindow.webContents.send('collector:complete', deliveryResult);
    return deliveryResult;
  } catch (err) {
    const msg = err.message || String(err);
    mainWindow.webContents.send('collector:error', msg);
    throw err;
  }
});

ipcMain.handle('collector:abort', () => {
  aborted = true;
  return true;
});

ipcMain.handle('collector:close', () => {
  app.quit();
});
