const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const { runScan } = require('./scanner');
const { generateReport } = require('./report/generator');

const CONFIG_PATH = path.join(__dirname, '..', 'config', 'pcc-scout.json');
const ASSETS_DIR = path.join(__dirname, '..', 'assets');
const OUTPUT_DIR = path.join(__dirname, '..', 'output');

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 850,
    minWidth: 900,
    minHeight: 700,
    title: 'PCC Scout',
    backgroundColor: '#080b0f',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}

app.whenReady().then(() => {
  // Ensure output directory exists
  if (!fs.existsSync(OUTPUT_DIR)) {
    fs.mkdirSync(OUTPUT_DIR, { recursive: true });
  }
  createWindow();
});

app.on('window-all-closed', () => {
  app.quit();
});

// --- Config IPC ---

ipcMain.handle('config:load', () => {
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
    }
  } catch (err) {
    console.error('Failed to load config:', err);
  }
  return null;
});

ipcMain.handle('config:save', (_event, config) => {
  try {
    const configDir = path.dirname(CONFIG_PATH);
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
    return { success: true };
  } catch (err) {
    return { success: false, error: err.message };
  }
});

// --- Dialog IPC ---

ipcMain.handle('dialog:openFile', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    title: 'Select Company Logo',
    filters: [{ name: 'Images', extensions: ['png', 'jpg', 'jpeg', 'svg'] }],
    properties: ['openFile'],
  });

  if (result.canceled || result.filePaths.length === 0) {
    return null;
  }

  const srcPath = result.filePaths[0];
  const ext = path.extname(srcPath);
  const destPath = path.join(ASSETS_DIR, `user-logo${ext}`);

  // Remove any existing user-logo files
  const existing = fs.readdirSync(ASSETS_DIR).filter(f => f.startsWith('user-logo'));
  for (const f of existing) {
    fs.unlinkSync(path.join(ASSETS_DIR, f));
  }

  fs.copyFileSync(srcPath, destPath);
  return destPath;
});

ipcMain.handle('shell:openPath', (_event, dirPath) => {
  shell.openPath(dirPath || OUTPUT_DIR);
});

// --- Scanner IPC ---

ipcMain.handle('scanner:start', async (event, { subnet, scan_label, scan_type }) => {
  try {
    const result = await runScan(
      { subnet, scan_label, scan_type },
      (progress) => {
        mainWindow.webContents.send('scanner:progress', progress);
      }
    );
    mainWindow.webContents.send('scanner:complete', result);
    return result;
  } catch (err) {
    const msg = err.message || String(err);
    mainWindow.webContents.send('scanner:error', msg);
    throw err;
  }
});

// --- Report IPC ---

ipcMain.handle('report:generate', async (_event, { scan_result, branding }) => {
  try {
    const filepath = await generateReport(scan_result, branding);
    mainWindow.webContents.send('report:complete', { filepath });
    return { filepath };
  } catch (err) {
    throw new Error(`Report generation failed: ${err.message}`);
  }
});
